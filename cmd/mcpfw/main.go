package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/DiegoMuneraT/MCP-Proxy/internal/arbiter"
	"github.com/DiegoMuneraT/MCP-Proxy/internal/audit"
	"github.com/DiegoMuneraT/MCP-Proxy/internal/config"
	"github.com/DiegoMuneraT/MCP-Proxy/internal/proxy"
	"github.com/DiegoMuneraT/MCP-Proxy/internal/rules"
	"github.com/DiegoMuneraT/MCP-Proxy/internal/rules/builtin"
)

const version = "0.1.0"

func main() {
	// ── Flags ──────────────────────────────────────────────────────────────
	configPath := flag.String("config", "firewall.yaml", "Path to firewall config file")
	flag.Usage = usage
	flag.Parse()

	cmd := "start"
	if flag.NArg() > 0 {
		cmd = flag.Arg(0)
	}

	switch cmd {
	case "start":
		runStart(*configPath)
	case "list-rules":
		runListRules(*configPath)
	case "validate":
		runValidate(*configPath)
	case "version":
		fmt.Printf("mcpfw version %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		os.Exit(1)
	}
}

func runStart(configPath string) {
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Build rule registry with all built-in rules.
	registry := rules.NewRegistry()
	builtin.RegisterAll(registry, cfg)

	// Build arbiter (hybrid: rules first, LLM for ambiguous).
	arb := arbiter.New(cfg, registry)

	// Build audit logger.
	logger, err := audit.New(&cfg.Audit)
	if err != nil {
		log.Fatalf("Failed to initialise audit logger: %v", err)
	}

	// Build and start proxy.
	p := proxy.New(cfg, arb, logger)

	log.Printf("MCP Firewall v%s starting on %s", version, cfg.Firewall.ListenAddr)
	log.Printf("Trusted servers: %d | Rules: %d | Audit: %v",
		len(cfg.Servers), len(registry.All()), cfg.Audit.Enabled)

	if err := http.ListenAndServe(cfg.Firewall.ListenAddr, p.Handler()); err != nil {
		log.Fatalf("Proxy failed: %v", err)
	}
}

func runListRules(configPath string) {
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	registry := rules.NewRegistry()
	builtin.RegisterAll(registry, cfg)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "RULE\tDIRECTIONS\tDESCRIPTION")
	fmt.Fprintln(w, "────\t──────────\t───────────")
	for _, r := range registry.All() {
		dirs := make([]string, 0, len(r.Directions()))
		for _, d := range r.Directions() {
			dirs = append(dirs, string(d))
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", r.Name(), joinStrings(dirs, ", "), r.Description())
	}
	w.Flush()
}

func runValidate(configPath string) {
	_, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config invalid: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Config OK: %s\n", configPath)
}

func joinStrings(ss []string, sep string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}

func usage() {
	fmt.Fprintf(os.Stderr, `MCP Firewall — transparent security proxy for MCP agents

USAGE:
  mcpfw [--config <path>] <command>

COMMANDS:
  start          Start the firewall proxy (default)
  list-rules     List all active rules and their descriptions
  validate       Validate the config file without starting
  version        Print version

FLAGS:
  --config       Path to firewall.yaml (default: ./firewall.yaml)

EXAMPLES:
  mcpfw start
  mcpfw --config /etc/mcpfw/firewall.yaml start
  mcpfw list-rules
  mcpfw validate

`)
}
