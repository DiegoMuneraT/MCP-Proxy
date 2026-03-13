package rules

import (
	"context"
	"encoding/json"
)

// Direction indicates whether a message is going to or from the MCP server.
type Direction string

const (
	Outbound Direction = "outbound" // client → server
	Inbound  Direction = "inbound"  // server → client (tool results)
)

// Verdict is the decision a rule returns.
type Verdict string

const (
	Allow    Verdict = "allow"
	Block    Verdict = "block"
	Confirm  Verdict = "confirm"  // requires human/LLM confirmation before proceeding
	Escalate Verdict = "escalate" // rule is unsure — pass to arbiter
)

// Severity indicates how serious a finding is.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Message is the normalised representation of a JSON-RPC 2.0 message
// as it passes through the proxy.
type Message struct {
	// Raw is the original JSON-RPC payload.
	Raw json.RawMessage

	// Parsed fields (populated by the proxy before rule evaluation).
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`

	// Context populated by the proxy.
	Direction  Direction
	ServerID   string
	ServerURL  string
	ToolName   string // populated for tools/call requests
	ToolArgs   map[string]interface{}
	ToolResult string // populated for inbound tool results
}

// Finding describes what a rule detected.
type Finding struct {
	RuleName   string
	Verdict    Verdict
	Severity   Severity
	Confidence float64 // 0.0–1.0, how certain the rule is
	Reason     string
	Evidence   string // the specific substring or value that triggered the rule
}

// Rule is the interface every rule must implement.
// Rules are stateless — all context comes via Message.
type Rule interface {
	// Name returns a stable identifier for the rule (used in logs and config).
	Name() string

	// Description explains what the rule detects, shown in --list-rules output.
	Description() string

	// Directions returns which message directions this rule applies to.
	Directions() []Direction

	// Evaluate inspects the message and returns a Finding.
	// If the rule does not apply to this message, return a Finding with
	// Verdict == Allow and Confidence == 1.0.
	Evaluate(ctx context.Context, msg *Message) Finding
}

// Registry holds all registered rules.
type Registry struct {
	rules []Rule
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds a rule to the registry.
func (r *Registry) Register(rule Rule) {
	r.rules = append(r.rules, rule)
}

// All returns all registered rules.
func (r *Registry) All() []Rule {
	return r.rules
}

// ForDirection returns rules that apply to a given direction.
func (r *Registry) ForDirection(d Direction) []Rule {
	var out []Rule
	for _, rule := range r.rules {
		for _, dir := range rule.Directions() {
			if dir == d {
				out = append(out, rule)
				break
			}
		}
	}
	return out
}
