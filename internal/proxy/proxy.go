package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/DiegoMuneraT/MCP-Proxy/internal/arbiter"
	"github.com/DiegoMuneraT/MCP-Proxy/internal/audit"
	"github.com/DiegoMuneraT/MCP-Proxy/internal/config"
	"github.com/DiegoMuneraT/MCP-Proxy/internal/rules"
)

var requestCounter uint64

// Proxy is the HTTP reverse proxy that intercepts all MCP traffic.
type Proxy struct {
	cfg     *config.Config
	arbiter *arbiter.Arbiter
	logger  *audit.Logger
}

// New creates a Proxy.
func New(cfg *config.Config, arb *arbiter.Arbiter, log *audit.Logger) *Proxy {
	return &Proxy{cfg: cfg, arbiter: arb, logger: log}
}

// Handler returns an http.Handler for the proxy.
// The client connects here; the proxy forwards to the real MCP server.
func (p *Proxy) Handler() http.Handler {
	mux := http.NewServeMux()
	// Route: /{server_id}/{rest...}
	// e.g. GET /filesystem-server/sse
	//      POST /filesystem-server/message
	mux.HandleFunc("/", p.route)
	return mux
}

// route dispatches requests to the correct upstream server.
func (p *Proxy) route(w http.ResponseWriter, r *http.Request) {
	// Extract server ID from path: first segment after /
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "missing server id in path", http.StatusBadRequest)
		return
	}
	serverID := parts[0]

	srv, ok := p.cfg.Servers[serverID]
	if !ok && p.cfg.Firewall.BlockUnknownServers {
		http.Error(w, fmt.Sprintf("unknown server: %s", serverID), http.StatusForbidden)
		return
	}

	target, err := url.Parse(srv.URL)
	if err != nil {
		http.Error(w, "invalid server URL in config", http.StatusInternalServerError)
		return
	}

	// Rewrite path — strip the server ID prefix before forwarding.
	restPath := "/"
	if len(parts) > 1 {
		restPath = "/" + parts[1]
	}
	r.URL.Path = restPath

	// Intercept POST /message (JSON-RPC calls — outbound from client).
	if r.Method == http.MethodPost {
		p.handleJSONRPC(w, r, serverID, &srv, target)
		return
	}

	// For SSE and other GET requests — proxy transparently but intercept
	// SSE events containing tool results on the way back.
	if r.Header.Get("Accept") == "text/event-stream" {
		p.handleSSE(w, r, serverID, &srv, target)
		return
	}

	// Default: transparent reverse proxy.
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ServeHTTP(w, r)
}

// handleJSONRPC intercepts outbound JSON-RPC messages (client → server).
func (p *Proxy) handleJSONRPC(w http.ResponseWriter, r *http.Request, serverID string, srv *config.ServerConfig, target *url.URL) {
	ctx := r.Context()
	requestID := newRequestID()

	body, err := io.ReadAll(io.LimitReader(r.Body, 2*1024*1024)) // 2 MB limit
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	msg, err := parseMessage(body, rules.Outbound, serverID, srv.URL)
	if err != nil {
		http.Error(w, "invalid JSON-RPC message", http.StatusBadRequest)
		return
	}

	// Run the firewall.
	decision := p.arbiter.Evaluate(ctx, msg)
	p.logger.Log(requestID, msg, &decision)

	switch decision.Verdict {
	case rules.Block:
		writeJSONRPCError(w, msg.ID, -32600, fmt.Sprintf("Blocked by MCP Firewall: %s", decision.Reason))
		return
	case rules.Confirm:
		// For autonomous operation: apply LLM-based self-confirmation.
		// In this release we return an error asking the caller to confirm.
		// A future release will add a confirmation callback mechanism.
		writeJSONRPCError(w, msg.ID, -32601,
			fmt.Sprintf("Action requires confirmation: %s — resubmit with X-MCPFW-Confirm: true header to proceed.", decision.Reason))
		return
	}

	// Passed outbound checks — forward to server and scan the response.
	forwardAndScanResponse(ctx, w, r, body, target, p.cfg.Firewall.RequestTimeout, msg, serverID, srv, p)
}

// handleSSE intercepts inbound Server-Sent Events (tool results flow back this way).
func (p *Proxy) handleSSE(w http.ResponseWriter, r *http.Request, serverID string, srv *config.ServerConfig, target *url.URL) {
	ctx := r.Context()

	// Open upstream SSE connection.
	upstreamURL := *target
	upReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, upstreamURL.String(), nil)
	upReq.Header = r.Header.Clone()

	client := &http.Client{}
	upResp, err := client.Do(upReq)
	if err != nil {
		http.Error(w, "upstream SSE connection failed", http.StatusBadGateway)
		return
	}
	defer upResp.Body.Close()

	// Set SSE headers on our response.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, canFlush := w.(http.Flusher)

	buf := make([]byte, 4096)
	var eventBuf strings.Builder

	for {
		n, err := upResp.Body.Read(buf)
		if n > 0 {
			chunk := string(buf[:n])
			eventBuf.WriteString(chunk)

			// SSE events are separated by double newlines.
			for {
				raw := eventBuf.String()
				idx := strings.Index(raw, "\n\n")
				if idx == -1 {
					break
				}
				event := raw[:idx+2]
				eventBuf.Reset()
				eventBuf.WriteString(raw[idx+2:])

				// Inspect the event data for inbound tool results.
				data := extractSSEData(event)
				if data != "" {
					msg := parseInboundEvent(data, serverID, srv.URL)
					if msg != nil {
						requestID := newRequestID()
						decision := p.arbiter.Evaluate(ctx, msg)
						p.logger.Log(requestID, msg, &decision)

						if decision.Verdict == rules.Block {
							// Replace the event data with a sanitised error.
							safeEvent := buildSafeSSEEvent(msg.ID, decision.Reason)
							fmt.Fprint(w, safeEvent)
							if canFlush {
								flusher.Flush()
							}
							continue
						}
					}
				}

				// Safe — forward as-is.
				fmt.Fprint(w, event)
				if canFlush {
					flusher.Flush()
				}
			}
		}
		if err != nil {
			break
		}
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func parseMessage(raw []byte, dir rules.Direction, serverID, serverURL string) (*rules.Message, error) {
	var msg rules.Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, err
	}
	msg.Raw = raw
	msg.Direction = dir
	msg.ServerID = serverID
	msg.ServerURL = serverURL

	// Extract tool name and args for tools/call messages.
	if msg.Method == "tools/call" && msg.Params != nil {
		var params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(msg.Params, &params); err == nil {
			msg.ToolName = params.Name
			msg.ToolArgs = params.Arguments
		}
	}

	return &msg, nil
}

func parseInboundEvent(data, serverID, serverURL string) *rules.Message {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		return nil
	}

	// Look for tool result content in the JSON-RPC result.
	result, ok := raw["result"]
	if !ok {
		return nil
	}

	resultBytes, _ := json.Marshal(result)
	toolResult := extractToolResultText(result)
	if toolResult == "" {
		return nil
	}

	msg := &rules.Message{
		Raw:        []byte(data),
		Direction:  rules.Inbound,
		ServerID:   serverID,
		ServerURL:  serverURL,
		Result:     resultBytes,
		ToolResult: toolResult,
	}

	if id, ok := raw["id"]; ok {
		msg.ID = id
	}

	return msg
}

func extractToolResultText(result interface{}) string {
	// MCP tool results have shape: {content: [{type:"text", text:"..."}]}
	m, ok := result.(map[string]interface{})
	if !ok {
		return ""
	}
	content, ok := m["content"].([]interface{})
	if !ok {
		return ""
	}
	var parts []string
	for _, item := range content {
		if block, ok := item.(map[string]interface{}); ok {
			if t, ok := block["text"].(string); ok {
				parts = append(parts, t)
			}
		}
	}
	return strings.Join(parts, "\n")
}

func extractSSEData(event string) string {
	for _, line := range strings.Split(event, "\n") {
		if strings.HasPrefix(line, "data: ") {
			return strings.TrimPrefix(line, "data: ")
		}
	}
	return ""
}

func buildSafeSSEEvent(id interface{}, reason string) string {
	errResp, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]interface{}{
			"code":    -32600,
			"message": fmt.Sprintf("Blocked by MCP Firewall: %s", reason),
		},
	})
	return fmt.Sprintf("data: %s\n\n", errResp)
}

func writeJSONRPCError(w http.ResponseWriter, id interface{}, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // JSON-RPC errors use 200 with error body
	resp, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]interface{}{"code": code, "message": message},
	})
	w.Write(resp)
}

// forwardAndScanResponse forwards the request to the upstream server, reads the
// full response body, runs inbound firewall inspection on it, and either returns
// the safe response to the client or replaces it with a JSON-RPC error.
func forwardAndScanResponse(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	body []byte,
	target *url.URL,
	timeout time.Duration,
	outboundMsg *rules.Message,
	serverID string,
	srv *config.ServerConfig,
	p *Proxy,
) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	upURL := *target
	upReq, err := http.NewRequestWithContext(ctx, r.Method, upURL.String(), strings.NewReader(string(body)))
	if err != nil {
		http.Error(w, "failed to build upstream request", http.StatusInternalServerError)
		return
	}
	upReq.Header = r.Header.Clone()

	client := &http.Client{}
	resp, err := client.Do(upReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read the full response body so we can inspect it.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		http.Error(w, "failed to read upstream response", http.StatusBadGateway)
		return
	}

	// Build an inbound message from the response and run it through the firewall.
	inboundMsg := parseInboundResponse(respBody, serverID, srv.URL, outboundMsg.ToolName)
	if inboundMsg != nil {
		requestID := newRequestID()
		decision := p.arbiter.Evaluate(ctx, inboundMsg)
		p.logger.Log(requestID, inboundMsg, &decision)

		if decision.Verdict == rules.Block {
			writeJSONRPCError(w, inboundMsg.ID, -32600,
				fmt.Sprintf("Blocked by MCP Firewall: %s", decision.Reason))
			return
		}
	} else {
		// Not a tool result (e.g. tools/list response) — log it as allowed for visibility.
		inboundLog := &rules.Message{
			Direction: rules.Inbound,
			ServerID:  serverID,
			ServerURL: srv.URL,
			Method:    outboundMsg.Method,
			ToolName:  outboundMsg.ToolName,
			Raw:       respBody,
		}
		allowDecision := &arbiter.Decision{
			Verdict:    rules.Allow,
			Severity:   rules.SeverityInfo,
			Reason:     "Non-tool-result response forwarded.",
			RuledBy:    "rules",
			Confidence: 1.0,
		}
		p.logger.Log(newRequestID(), inboundLog, allowDecision)
	}

	// Safe — write response back to client.
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// parseInboundResponse parses a JSON-RPC response body into an inbound Message
// if it contains a tool result. Returns nil for non-tool-result responses.
func parseInboundResponse(raw []byte, serverID, serverURL, toolName string) *rules.Message {
	var base struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      interface{}     `json:"id"`
		Result  json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &base); err != nil {
		return nil
	}
	if base.Result == nil {
		return nil
	}

	var result interface{}
	if err := json.Unmarshal(base.Result, &result); err != nil {
		return nil
	}

	toolResult := extractToolResultText(result)
	if toolResult == "" {
		return nil
	}

	return &rules.Message{
		Raw:        raw,
		JSONRPC:    base.JSONRPC,
		ID:         base.ID,
		Direction:  rules.Inbound,
		ServerID:   serverID,
		ServerURL:  serverURL,
		ToolName:   toolName,
		Result:     base.Result,
		ToolResult: toolResult,
	}
}

func newRequestID() string {
	n := atomic.AddUint64(&requestCounter, 1)
	return fmt.Sprintf("mcpfw-%d-%d", time.Now().UnixNano(), n)
}
