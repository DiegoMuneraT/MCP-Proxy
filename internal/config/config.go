package config

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"time"
)

// Config is the root configuration loaded from firewall.yaml.
type Config struct {
	Firewall FirewallConfig          `yaml:"firewall"`
	Servers  map[string]ServerConfig `yaml:"trusted_servers"`
	Arbiter  ArbiterConfig           `yaml:"arbiter"`
	Audit    AuditConfig             `yaml:"audit"`
}

// FirewallConfig holds global proxy settings.
type FirewallConfig struct {
	ListenAddr          string        `yaml:"listen_addr"` // e.g. "127.0.0.1:4000"
	BlockUnknownServers bool          `yaml:"block_unknown_servers"`
	DefaultAction       string        `yaml:"default_action"` // "allow" | "deny"
	RequestTimeout      time.Duration `yaml:"request_timeout"`
}

// ServerConfig describes a single trusted upstream MCP server.
type ServerConfig struct {
	URL                  string   `yaml:"url"`
	AllowedTools         []string `yaml:"allowed_tools"`
	RequiresConfirmation []string `yaml:"requires_confirmation"`
	RiskLevel            string   `yaml:"risk_level"` // "low" | "medium" | "high"
	TLSSkipVerify        bool     `yaml:"tls_skip_verify"`
}

// ArbiterConfig controls the hybrid decision engine.
type ArbiterConfig struct {
	// RulesFirst: always run rule engine before escalating to LLM.
	RulesFirst bool `yaml:"rules_first"`

	// ConfidenceThreshold: if rule score is below this, escalate to LLM.
	// Range 0.0–1.0. 1.0 means always use rules only.
	ConfidenceThreshold float64 `yaml:"confidence_threshold"`

	// LLM settings (only used for ambiguous cases).
	LLMProvider string `yaml:"llm_provider"` // "anthropic" | "openai" | "ollama"
	LLMModel    string `yaml:"llm_model"`
	LLMBaseURL  string `yaml:"llm_base_url"` // for ollama or custom endpoints
	LLMAPIKey   string `yaml:"llm_api_key"`  // can also be set via env MCPFW_LLM_API_KEY
}

// AuditConfig controls audit logging.
type AuditConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Output     string `yaml:"output"`      // "stdout" | "file" | "both"
	FilePath   string `yaml:"file_path"`   // used when output == "file" or "both"
	Format     string `yaml:"format"`      // "json" | "text"
	LogAllowed bool   `yaml:"log_allowed"` // if false, only logs blocked/flagged events
}

// Load reads and validates a config file from the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	// Expand environment variables in the raw YAML.
	expanded := os.ExpandEnv(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Apply defaults.
	if cfg.Firewall.ListenAddr == "" {
		cfg.Firewall.ListenAddr = "127.0.0.1:4000"
	}
	if cfg.Firewall.DefaultAction == "" {
		cfg.Firewall.DefaultAction = "deny"
	}
	if cfg.Firewall.RequestTimeout == 0 {
		cfg.Firewall.RequestTimeout = 30 * time.Second
	}
	if cfg.Arbiter.ConfidenceThreshold == 0 {
		cfg.Arbiter.ConfidenceThreshold = 0.75
	}
	if cfg.Arbiter.LLMModel == "" {
		cfg.Arbiter.LLMModel = "claude-haiku-4-5-20251001"
	}
	if cfg.Audit.Format == "" {
		cfg.Audit.Format = "json"
	}

	// Override LLM API key from env if set.
	if key := os.Getenv("MCPFW_LLM_API_KEY"); key != "" {
		cfg.Arbiter.LLMAPIKey = key
	}

	return &cfg, nil
}

// ServerByURL returns the ServerConfig for a given upstream URL, if trusted.
func (c *Config) ServerByURL(url string) (*ServerConfig, bool) {
	for _, s := range c.Servers {
		if s.URL == url {
			return &s, true
		}
	}
	return nil, false
}
