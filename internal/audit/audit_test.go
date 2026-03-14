package audit_test

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/DiegoMuneraT/MCP-Proxy/internal/arbiter"
	"github.com/DiegoMuneraT/MCP-Proxy/internal/audit"
	"github.com/DiegoMuneraT/MCP-Proxy/internal/config"
	"github.com/DiegoMuneraT/MCP-Proxy/internal/rules"
)

// writerLogger is a test helper that captures log output.
type writerLogger struct {
	buf bytes.Buffer
}

func (w *writerLogger) Write(p []byte) (int, error) {
	return w.buf.Write(p)
}

func (w *writerLogger) String() string {
	return w.buf.String()
}

func newTestLogger(t *testing.T, format string, logAllowed bool, w io.Writer) *audit.Logger {
	t.Helper()
	cfg := &config.AuditConfig{
		Enabled:    true,
		Output:     "stdout",
		Format:     format,
		LogAllowed: logAllowed,
	}
	logger, err := audit.NewWithWriter(cfg, w)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	return logger
}

func sampleMsg() *rules.Message {
	return &rules.Message{
		Direction: rules.Inbound,
		Method:    "tools/call",
		ServerID:  "filesystem",
		ServerURL: "http://localhost:3001",
		ToolName:  "read_file",
	}
}

func blockDecision() *arbiter.Decision {
	return &arbiter.Decision{
		Verdict:    rules.Block,
		Severity:   rules.SeverityHigh,
		Reason:     "Injection pattern detected.",
		RuledBy:    "rules",
		Confidence: 0.95,
	}
}

func allowDecision() *arbiter.Decision {
	return &arbiter.Decision{
		Verdict:    rules.Allow,
		Severity:   rules.SeverityInfo,
		Reason:     "All rules passed.",
		RuledBy:    "rules",
		Confidence: 1.0,
	}
}

// ── JSON format tests ─────────────────────────────────────────────────────────

func TestAuditLogger_JSONFormat_BlockedEvent(t *testing.T) {
	w := &writerLogger{}
	logger := newTestLogger(t, "json", false, w)

	logger.Log("req-001", sampleMsg(), blockDecision())

	output := w.String()
	if output == "" {
		t.Fatal("expected log output, got nothing")
	}

	var event map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &event); err != nil {
		t.Fatalf("log output is not valid JSON: %v\noutput: %s", err, output)
	}

	checks := map[string]string{
		"request_id": "req-001",
		"verdict":    "block",
		"ruled_by":   "rules",
		"server_id":  "filesystem",
		"tool_name":  "read_file",
	}
	for key, want := range checks {
		if got, ok := event[key]; !ok {
			t.Errorf("JSON missing field %q", key)
		} else if got != want {
			t.Errorf("JSON field %q: got %v, want %v", key, got, want)
		}
	}

	if _, ok := event["timestamp"]; !ok {
		t.Error("JSON missing timestamp field")
	}
}

func TestAuditLogger_JSONFormat_AllowedEvent_LogAllowed(t *testing.T) {
	w := &writerLogger{}
	logger := newTestLogger(t, "json", true, w) // log_allowed = true

	logger.Log("req-002", sampleMsg(), allowDecision())

	output := w.String()
	if output == "" {
		t.Error("expected allowed event to be logged when log_allowed=true")
	}
}

func TestAuditLogger_JSONFormat_AllowedEvent_NotLogged(t *testing.T) {
	w := &writerLogger{}
	logger := newTestLogger(t, "json", false, w) // log_allowed = false

	logger.Log("req-003", sampleMsg(), allowDecision())

	output := w.String()
	if output != "" {
		t.Errorf("allowed event should NOT be logged when log_allowed=false, got: %s", output)
	}
}

// ── Text format tests ─────────────────────────────────────────────────────────

func TestAuditLogger_TextFormat(t *testing.T) {
	w := &writerLogger{}
	logger := newTestLogger(t, "text", true, w)

	logger.Log("req-004", sampleMsg(), blockDecision())

	output := w.String()
	if output == "" {
		t.Fatal("expected text log output")
	}

	// Text format should contain key identifiers.
	required := []string{"req-004", "filesystem", "read_file", "block", "rules"}
	for _, s := range required {
		if !strings.Contains(output, s) {
			t.Errorf("text log missing %q\noutput: %s", s, output)
		}
	}
}

// ── Disabled logger ───────────────────────────────────────────────────────────

func TestAuditLogger_Disabled(t *testing.T) {
	cfg := &config.AuditConfig{Enabled: false}
	logger, err := audit.New(cfg)
	if err != nil {
		t.Fatalf("failed to create disabled logger: %v", err)
	}
	// Should not panic.
	logger.Log("req-005", sampleMsg(), blockDecision())
}

// ── Multiple events ───────────────────────────────────────────────────────────

func TestAuditLogger_MultipleEvents(t *testing.T) {
	w := &writerLogger{}
	logger := newTestLogger(t, "json", true, w)

	for i := 0; i < 10; i++ {
		logger.Log("req-multi", sampleMsg(), blockDecision())
	}

	lines := strings.Split(strings.TrimSpace(w.String()), "\n")
	if len(lines) != 10 {
		t.Errorf("expected 10 log lines, got %d", len(lines))
	}

	// Each line must be valid JSON.
	for i, line := range lines {
		var event map[string]interface{}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i, err)
		}
	}
}
