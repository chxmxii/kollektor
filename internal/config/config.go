// Package config parses agent configuration from flags and environment.
package config

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

type Config struct {
	NodeName    string
	MetricsAddr string
	ProcRoot    string
	Kubeconfig  string
	EnableK8s   bool
	Probes      []string
	LogLevel    slog.Level
	LogEvents   bool
}

// Parse reads flags from args. Env vars provide defaults so the DaemonSet can
// inject NODE_NAME through the downward API.
func Parse(args []string) (*Config, error) {
	fs := flag.NewFlagSet("kollektor-agent", flag.ContinueOnError)
	c := &Config{}
	var probes, level string

	fs.StringVar(&c.NodeName, "node-name", os.Getenv("NODE_NAME"), "Kubernetes node this agent runs on (env NODE_NAME)")
	fs.StringVar(&c.MetricsAddr, "metrics-addr", ":9090", "address for /metrics and /healthz")
	fs.StringVar(&c.ProcRoot, "proc-root", "/proc", "procfs mount showing host PIDs (requires hostPID)")
	fs.StringVar(&c.Kubeconfig, "kubeconfig", "", "kubeconfig for out-of-cluster use (in-cluster config is preferred)")
	fs.BoolVar(&c.EnableK8s, "k8s", true, "enrich events with pod metadata")
	fs.StringVar(&probes, "probes", "exec", "comma-separated probes to enable")
	fs.StringVar(&level, "log-level", "info", "debug|info|warn|error")
	fs.BoolVar(&c.LogEvents, "log-events", false, "write every event to stdout as JSON")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if err := c.LogLevel.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("invalid -log-level: %w", err)
	}
	for p := range strings.SplitSeq(probes, ",") {
		if p = strings.TrimSpace(p); p != "" {
			c.Probes = append(c.Probes, p)
		}
	}
	if c.EnableK8s && c.NodeName == "" {
		return nil, fmt.Errorf("-node-name (or NODE_NAME) is required when -k8s is enabled")
	}
	return c, nil
}
