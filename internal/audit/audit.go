package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/DiegoMuneraT/MCP-Proxy/internal/arbiter"
	"github.com/DiegoMuneraT/MCP-Proxy/internal/config"
	"github.com/DiegoMuneraT/MCP-Proxy/internal/rules"
)

// Event is a single audit record written for every firewall decision.
type Event struct {
	Timestamp  time.Time       `json:"timestamp"`
	RequestID  string          `json:"request_id"`
	Direction  rules.Direction `json:"direction"`
	ServerID   string          `json:"server_id"`
	ServerURL  string          `json:"server_url"`
	Method     string          `json:"method"`
	ToolName   string          `json:"tool_name,omitempty"`
	Verdict    rules.Verdict   `json:"verdict"`
	Severity   rules.Severity  `json:"severity"`
	Reason     string          `json:"reason"`
	RuledBy    string          `json:"ruled_by"`
	Confidence float64         `json:"confidence"`
	Findings   []rules.Finding `json:"findings,omitempty"`
}

// Logger writes audit events to one or more outputs.
type Logger struct {
	cfg     *config.AuditConfig
	writers []io.Writer
	mu      sync.Mutex
}

// New creates an audit Logger from config.
func New(cfg *config.AuditConfig) (*Logger, error) {
	if !cfg.Enabled {
		return &Logger{cfg: cfg}, nil
	}

	var writers []io.Writer

	switch cfg.Output {
	case "stdout":
		writers = append(writers, os.Stdout)
	case "file":
		f, err := openLogFile(cfg.FilePath)
		if err != nil {
			return nil, err
		}
		writers = append(writers, f)
	case "both":
		writers = append(writers, os.Stdout)
		f, err := openLogFile(cfg.FilePath)
		if err != nil {
			return nil, err
		}
		writers = append(writers, f)
	default:
		writers = append(writers, os.Stdout)
	}

	return &Logger{cfg: cfg, writers: writers}, nil
}

// NewWithWriter creates an audit Logger that writes to an explicit io.Writer.
// Primarily used in tests to capture output without touching the filesystem.
func NewWithWriter(cfg *config.AuditConfig, w io.Writer) (*Logger, error) {
	return &Logger{cfg: cfg, writers: []io.Writer{w}}, nil
}

// Log writes an audit event derived from a message and decision.
func (l *Logger) Log(requestID string, msg *rules.Message, decision *arbiter.Decision) {
	if !l.cfg.Enabled {
		return
	}
	if decision.Verdict == rules.Allow && !l.cfg.LogAllowed {
		return
	}

	event := Event{
		Timestamp:  time.Now().UTC(),
		RequestID:  requestID,
		Direction:  msg.Direction,
		ServerID:   msg.ServerID,
		ServerURL:  msg.ServerURL,
		Method:     msg.Method,
		ToolName:   msg.ToolName,
		Verdict:    decision.Verdict,
		Severity:   decision.Severity,
		Reason:     decision.Reason,
		RuledBy:    decision.RuledBy,
		Confidence: decision.Confidence,
		Findings:   decision.Findings,
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	for _, w := range l.writers {
		switch l.cfg.Format {
		case "text":
			l.writeText(w, event)
		default:
			l.writeJSON(w, event)
		}
	}
}

func (l *Logger) writeJSON(w io.Writer, event Event) {
	data, _ := json.Marshal(event)
	fmt.Fprintf(w, "%s\n", data)
}

func (l *Logger) writeText(w io.Writer, event Event) {
	fmt.Fprintf(w, "[%s] %s | server=%s tool=%s method=%s verdict=%s severity=%s ruled_by=%s | %s\n",
		event.Timestamp.Format(time.RFC3339),
		event.RequestID,
		event.ServerID,
		event.ToolName,
		event.Method,
		event.Verdict,
		event.Severity,
		event.RuledBy,
		event.Reason,
	)
}

func openLogFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
}
