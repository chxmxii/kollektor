// Command kollektor-agent runs on every node, loads BPF probes and exports
// what they observe, enriched with Kubernetes metadata.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/chxmxii/kollektor/internal/agent"
	"github.com/chxmxii/kollektor/internal/config"
)

func main() {
	cfg, err := config.Parse(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	if err != nil {
		slog.Error("invalid configuration", "err", err)
		os.Exit(2)
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := agent.New(cfg, log)
	if err != nil {
		log.Error("creating agent", "err", err)
		os.Exit(1)
	}
	log.Info("starting kollektor-agent", "node", cfg.NodeName, "probes", cfg.Probes)
	if err := a.Run(ctx); err != nil {
		log.Error("agent stopped", "err", err)
		os.Exit(1)
	}
}
