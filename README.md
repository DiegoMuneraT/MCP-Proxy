# MCP Firewall

**A transparent security proxy for MCP (Model Context Protocol) agents.**

MCP Firewall sits between your AI application and any MCP server, automatically enforcing security policies without requiring changes to your host app or the servers. It is designed for the future of autonomous AI agents — where decisions need to be safe even with minimal human involvement.

```
Your App (LLM + MCP Client)
        │
        ▼
  ┌─────────────┐
  │ MCP Firewall│  ← you are here
  │   (proxy)   │
  └─────────────┘
        │
        ▼
  MCP Server(s)
```

---

## Why this exists

MCP itself is a protocol, not a security system. Every security decision in the standard spec relies on developers remembering to do the right thing at the right time. This project makes the right thing structural — messages physically cannot pass through without clearing a rule pipeline.

---

## Features

- **Drop-in proxy** — point your MCP client at `127.0.0.1:4000` instead of the real server. No other code changes.
- **Hybrid decision engine** — rule-based checks run first (fast, free). An LLM arbiter is invoked only for ambiguous cases that rules cannot confidently judge.
- **Built-in rules**
  - `server-trust` — blocks connections to servers not in your trusted list
  - `tool-allowlist` — strips tools not on your approved list before the LLM even sees them
  - `destructive-action-gate` — gates write/delete operations behind confirmation
  - `injection-scanner` — scans inbound tool results for prompt injection patterns
  - `tool-result-size` — blocks oversized tool results (context flooding)
- **Extensible rule engine** — implement the `Rule` interface to add your own rules in any package
- **Single YAML config** — all policy in one file, env variable expansion supported
- **Structured audit log** — every decision logged as JSON or text, to stdout and/or file

---

## Quick start

```bash
# Build
go build -o mcpfw ./cmd/mcpfw

# Validate your config
./mcpfw validate

# List active rules
./mcpfw list-rules

# Start the proxy
export MCPFW_LLM_API_KEY=sk-ant-...
./mcpfw start
```

Configure your MCP client to connect to `http://127.0.0.1:4000/<server_id>/` instead of directly to the server. The `server_id` must match a key in `trusted_servers` in your `firewall.yaml`.

---

## Configuration

```yaml
firewall:
  listen_addr: "127.0.0.1:4000"
  block_unknown_servers: true
  default_action: "deny"

trusted_servers:
  filesystem:
    url: "http://127.0.0.1:3001"
    allowed_tools: [read_file, list_directory]
    requires_confirmation: [write_file, delete_file]
    risk_level: high

arbiter:
  confidence_threshold: 0.75   # below this → escalate to LLM
  llm_provider: "anthropic"
  llm_model: "claude-haiku-4-5-20251001"
  llm_api_key: "${MCPFW_LLM_API_KEY}"

audit:
  enabled: true
  output: "both"
  file_path: "./mcpfw-audit.log"
  format: "json"
  log_allowed: false
```

See `firewall.yaml` for the full annotated example.

---

## Writing a custom rule

```go
package myrules

import (
    "context"
    "github.com/mcp-firewall/mcpfw/internal/rules"
)

// BlockCryptoRule blocks any tool result mentioning wallet addresses.
type BlockCryptoRule struct{}

func (r *BlockCryptoRule) Name() string { return "block-crypto-exfil" }
func (r *BlockCryptoRule) Description() string {
    return "Blocks tool results containing cryptocurrency wallet addresses."
}
func (r *BlockCryptoRule) Directions() []rules.Direction {
    return []rules.Direction{rules.Inbound}
}
func (r *BlockCryptoRule) Evaluate(_ context.Context, msg *rules.Message) rules.Finding {
    if containsWalletAddress(msg.ToolResult) {
        return rules.Finding{
            RuleName:   r.Name(),
            Verdict:    rules.Block,
            Severity:   rules.SeverityHigh,
            Confidence: 0.9,
            Reason:     "Possible crypto wallet exfiltration detected.",
        }
    }
    return rules.Finding{Verdict: rules.Allow, Confidence: 1.0}
}
```

Then register it before starting the proxy:

```go
registry.Register(&myrules.BlockCryptoRule{})
```

---

## Security model

| Threat | Defence |
|---|---|
| Prompt injection via tool results | `injection-scanner` rule — pattern + optional LLM check |
| LLM calling disallowed tools | `tool-allowlist` rule — tools stripped before LLM sees them |
| Destructive actions | `destructive-action-gate` — confirmation required |
| Connecting to malicious servers | `server-trust` rule — unknown servers refused at connect time |
| Oversized payloads / context flooding | `tool-result-size` rule |
| Ambiguous cases rules can't judge | Hybrid arbiter escalates to LLM safety check |
| LLM arbiter failure | Fails closed — blocks the message |

### Confidence threshold 

The key design decision is how the arbiter fails closed: if a rule is uncertain, if the LLM is unavailable, 
if the LLM returns garbage — in every case the message is blocked, not allowed. 
The system defaults to safety without any human making that call. The confidence_threshold in config lets you 
tune how much you trust rules vs. LLM judgment.

The injection scanner has two tiers: hard patterns (block with 0.95 confidence — no LLM needed) and soft patterns 
(escalate to arbiter with 0.45 confidence — below the 0.75 threshold, so the LLM gets asked). 
This is exactly: "rules first, LLM only for ambiguous cases".

---

## Roadmap

- [ ] Async confirmation callbacks (Slack / webhook / web UI)
- [ ] Rate limiting per server and per tool
- [ ] `stdio` transport support (local MCP servers)
- [ ] WASM plugin API for community rules
- [ ] Prometheus metrics endpoint
- [ ] Docker image + Helm chart

---

## Contributing

Pull requests welcome. To add a rule to the built-in set, open an issue describing the threat it addresses and the false-positive rate you'd expect. Rules that are too aggressive (block legitimate content) won't be merged into `builtin` — they belong in community rule packages.

---

## License

MIT
