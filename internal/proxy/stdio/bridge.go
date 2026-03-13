// Package stdio implements MCP Firewall support for the stdio transport.
//
// A stdio MCP server is a local process that speaks JSON-RPC 2.0 over
// stdin/stdout. This package:
//
//  1. Spawns the server process as a child.
//  2. Wraps its stdin/stdout with firewall inspection.
//  3. Exposes a net.Conn-like interface so the proxy can treat it
//     identically to an HTTP server.
//
// Usage (in firewall.yaml):
//
//	trusted_servers:
//	  filesystem:
//	    transport: stdio
//	    command: "npx"
//	    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
//	    allowed_tools: [read_file, list_directory]
package stdio

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mcp-firewall/mcpfw/internal/arbiter"
	"github.com/mcp-firewall/mcpfw/internal/audit"
	"github.com/mcp-firewall/mcpfw/internal/config"
	"github.com/mcp-firewall/mcpfw/internal/rules"
)

// ServerConfig extends config.ServerConfig for stdio-specific fields.
// These are read from the same trusted_servers entry in firewall.yaml.
type ServerConfig struct {
	Command string   // executable to run, e.g. "npx" or "python"
	Args    []string // arguments passed to the command
	Env     []string // additional environment variables ("KEY=VALUE")
	Dir     string   // working directory for the process (defaults to CWD)
}

// Bridge manages a single stdio MCP server process and bidirectional
// firewall-inspected message passing.
type Bridge struct {
	serverID string
	srv      *config.ServerConfig
	stdio    *ServerConfig
	arb      *arbiter.Arbiter
	logger   *audit.Logger

	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr io.ReadCloser

	// clientCh receives messages from the MCP client (host app → bridge → server).
	clientCh chan []byte
	// serverCh receives messages from the MCP server (server → bridge → host).
	serverCh chan []byte
	// errCh receives fatal errors that should terminate the bridge.
	errCh chan error

	mu     sync.Mutex
	closed bool
}

// NewBridge creates a Bridge for a stdio MCP server.
// Call Start() to spawn the process and begin message routing.
func NewBridge(
	serverID string,
	srv *config.ServerConfig,
	stdio *ServerConfig,
	arb *arbiter.Arbiter,
	logger *audit.Logger,
) *Bridge {
	return &Bridge{
		serverID: serverID,
		srv:      srv,
		stdio:    stdio,
		arb:      arb,
		logger:   logger,
		clientCh: make(chan []byte, 64),
		serverCh: make(chan []byte, 64),
		errCh:    make(chan error, 1),
	}
}

// Start spawns the MCP server process and begins bidirectional inspection.
// The context controls the lifetime of the server process.
func (b *Bridge) Start(ctx context.Context) error {
	if b.stdio.Command == "" {
		return fmt.Errorf("stdio server %q: command must not be empty", b.serverID)
	}

	b.cmd = exec.CommandContext(ctx, b.stdio.Command, b.stdio.Args...)

	if b.stdio.Dir != "" {
		b.cmd.Dir = b.stdio.Dir
	}
	if len(b.stdio.Env) > 0 {
		b.cmd.Env = append(b.cmd.Environ(), b.stdio.Env...)
	}

	var err error
	b.stdin, err = b.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("creating stdin pipe: %w", err)
	}

	stdoutPipe, err := b.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("creating stdout pipe: %w", err)
	}
	b.stdout = bufio.NewReader(stdoutPipe)

	b.stderr, err = b.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("creating stderr pipe: %w", err)
	}

	if err := b.cmd.Start(); err != nil {
		return fmt.Errorf("starting server process %q: %w", b.stdio.Command, err)
	}

	log.Printf("[stdio/%s] process started (pid %d): %s %v",
		b.serverID, b.cmd.Process.Pid, b.stdio.Command, b.stdio.Args)

	// Drain stderr to logs so errors from the child process are visible.
	go b.drainStderr()

	// Read from server stdout → inspect → forward to host.
	go b.readFromServer(ctx)

	// Read from clientCh → inspect → write to server stdin.
	go b.writeToServer(ctx)

	// Wait for process exit.
	go func() {
		err := b.cmd.Wait()
		if err != nil && ctx.Err() == nil {
			log.Printf("[stdio/%s] process exited unexpectedly: %v", b.serverID, err)
		}
		b.errCh <- err
	}()

	return nil
}

// Send queues a JSON-RPC message from the client to be forwarded to the server.
// The message is inspected by the firewall before being sent.
func (b *Bridge) Send(msg []byte) {
	b.clientCh <- msg
}

// Receive returns a channel from which the caller can read firewall-approved
// messages coming from the MCP server.
func (b *Bridge) Receive() <-chan []byte {
	return b.serverCh
}

// Errors returns a channel that receives fatal errors (e.g. process exit).
func (b *Bridge) Errors() <-chan error {
	return b.errCh
}

// Close shuts down the bridge and terminates the server process.
func (b *Bridge) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	b.stdin.Close()
	if b.cmd != nil && b.cmd.Process != nil {
		b.cmd.Process.Kill()
	}
	return nil
}

// ── internal goroutines ───────────────────────────────────────────────────────

// readFromServer reads newline-delimited JSON from the server's stdout,
// inspects each message with the firewall, and forwards approved messages
// to serverCh.
func (b *Bridge) readFromServer(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line, err := b.stdout.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("[stdio/%s] read error: %v", b.serverID, err)
			}
			return
		}

		line = trimNewline(line)
		if len(line) == 0 {
			continue
		}

		// Parse the inbound message.
		msg := b.parseInbound(line)
		if msg == nil {
			// Not a tool result — forward without inspection.
			b.serverCh <- line
			continue
		}

		// Firewall inspection.
		requestID := newRequestID()
		decision := b.arb.Evaluate(ctx, msg)
		b.logger.Log(requestID, msg, &decision)

		switch decision.Verdict {
		case rules.Block:
			log.Printf("[stdio/%s] BLOCKED inbound message: %s", b.serverID, decision.Reason)
			// Replace with a sanitised error response.
			errMsg := buildErrorResponse(msg.ID, decision.Reason)
			b.serverCh <- errMsg
		default:
			b.serverCh <- line
		}
	}
}

// writeToServer reads from clientCh, inspects outbound messages, and
// writes approved messages to the server's stdin.
func (b *Bridge) writeToServer(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case raw, ok := <-b.clientCh:
			if !ok {
				return
			}
			msg := b.parseOutbound(raw)
			if msg == nil {
				// Non-tool message (e.g. initialize, ping) — forward directly.
				b.writeRaw(raw)
				continue
			}

			// Firewall inspection.
			requestID := newRequestID()
			decision := b.arb.Evaluate(ctx, msg)
			b.logger.Log(requestID, msg, &decision)

			switch decision.Verdict {
			case rules.Block:
				log.Printf("[stdio/%s] BLOCKED outbound call to %q: %s",
					b.serverID, msg.ToolName, decision.Reason)
				// Send error back to host via serverCh (reverse direction).
				errMsg := buildErrorResponse(msg.ID, decision.Reason)
				b.serverCh <- errMsg
			case rules.Confirm:
				log.Printf("[stdio/%s] CONFIRM required for %q: %s",
					b.serverID, msg.ToolName, decision.Reason)
				errMsg := buildConfirmResponse(msg.ID, decision.Reason)
				b.serverCh <- errMsg
			default:
				b.writeRaw(raw)
			}
		}
	}
}

func (b *Bridge) writeRaw(msg []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	// MCP stdio transport: each message on its own line.
	b.stdin.Write(msg)
	b.stdin.Write([]byte("\n"))
}

func (b *Bridge) drainStderr() {
	scanner := bufio.NewScanner(b.stderr)
	for scanner.Scan() {
		log.Printf("[stdio/%s] stderr: %s", b.serverID, scanner.Text())
	}
}

// ── message parsing ───────────────────────────────────────────────────────────

func (b *Bridge) parseOutbound(raw []byte) *rules.Message {
	var base struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      interface{}     `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(raw, &base); err != nil {
		return nil
	}
	if base.Method == "" {
		return nil
	}

	msg := &rules.Message{
		Raw:       raw,
		Direction: rules.Outbound,
		JSONRPC:   base.JSONRPC,
		ID:        base.ID,
		Method:    base.Method,
		Params:    base.Params,
		ServerID:  b.serverID,
		ServerURL: b.srv.URL,
	}

	if base.Method == "tools/call" && base.Params != nil {
		var params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(base.Params, &params); err == nil {
			msg.ToolName = params.Name
			msg.ToolArgs = params.Arguments
		}
	}

	return msg
}

func (b *Bridge) parseInbound(raw []byte) *rules.Message {
	var base struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      interface{}     `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(raw, &base); err != nil {
		return nil
	}
	if base.Result == nil {
		return nil
	}

	toolResult := extractToolResultText(base.Result)
	if toolResult == "" {
		return nil
	}

	return &rules.Message{
		Raw:        raw,
		Direction:  rules.Inbound,
		JSONRPC:    base.JSONRPC,
		ID:         base.ID,
		Result:     base.Result,
		ServerID:   b.serverID,
		ServerURL:  b.srv.URL,
		ToolResult: toolResult,
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func extractToolResultText(result json.RawMessage) string {
	var r struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(result, &r); err != nil {
		return ""
	}
	var parts []string
	for _, c := range r.Content {
		if c.Type == "text" && c.Text != "" {
			parts = append(parts, c.Text)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "\n"
		}
		out += p
	}
	return out
}

func buildErrorResponse(id interface{}, reason string) []byte {
	resp, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]interface{}{
			"code":    -32600,
			"message": fmt.Sprintf("Blocked by MCP Firewall: %s", reason),
		},
	})
	return resp
}

func buildConfirmResponse(id interface{}, reason string) []byte {
	resp, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]interface{}{
			"code":    -32601,
			"message": fmt.Sprintf("Confirmation required: %s — resend with confirmed=true to proceed.", reason),
		},
	})
	return resp
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

var requestCounter uint64

func newRequestID() string {
	n := atomic.AddUint64(&requestCounter, 1)
	return fmt.Sprintf("stdio-%d-%d", time.Now().UnixNano(), n)
}
