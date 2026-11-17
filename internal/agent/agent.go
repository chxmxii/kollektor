// Package agent wires probes, enrichment and sinks together.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sync/errgroup"

	"github.com/chxmxii/kollektor/internal/config"
	"github.com/chxmxii/kollektor/internal/events"
	"github.com/chxmxii/kollektor/internal/k8s"
	"github.com/chxmxii/kollektor/internal/metrics"
	"github.com/chxmxii/kollektor/internal/probes"
	"github.com/chxmxii/kollektor/internal/probes/exec"
)

const eventBuffer = 4096

type Agent struct {
	cfg     *config.Config
	log     *slog.Logger
	metrics *metrics.Metrics
	probes  []probes.Probe
}

func New(cfg *config.Config, log *slog.Logger) (*Agent, error) {
	a := &Agent{cfg: cfg, log: log, metrics: metrics.New()}
	for _, name := range cfg.Probes {
		switch name {
		case string(events.TypeExec):
			a.probes = append(a.probes, exec.New(log))
		default:
			return nil, fmt.Errorf("unknown probe %q", name)
		}
	}
	return a, nil
}

func (a *Agent) Run(ctx context.Context) error {
	// Needed on kernels < 5.11 that account BPF memory against RLIMIT_MEMLOCK.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock rlimit: %w", err)
	}

	var resolver *k8s.Resolver
	if a.cfg.EnableK8s {
		cs, err := k8s.NewClientset(a.cfg.Kubeconfig)
		if err != nil {
			return err
		}
		pods, err := k8s.NewPodCache(cs, a.cfg.NodeName, a.log)
		if err != nil {
			return err
		}
		if err := pods.Start(ctx); err != nil {
			return err
		}
		resolver = k8s.NewResolver(pods, a.cfg.ProcRoot)
	}

	g, ctx := errgroup.WithContext(ctx)
	in := make(chan events.Event, eventBuffer)

	g.Go(func() error { return a.metrics.Serve(ctx, a.cfg.MetricsAddr, a.log) })
	for _, p := range a.probes {
		g.Go(func() error {
			if err := p.Run(ctx, in); err != nil {
				return fmt.Errorf("probe %s: %w", p.Name(), err)
			}
			return nil
		})
	}
	g.Go(func() error { return a.consume(ctx, in, resolver) })

	return g.Wait()
}

func (a *Agent) consume(ctx context.Context, in <-chan events.Event, resolver *k8s.Resolver) error {
	enc := json.NewEncoder(os.Stdout)
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-in:
			ev.Node = a.cfg.NodeName
			if resolver != nil {
				resolver.Enrich(&ev)
			}
			a.metrics.Observe(&ev)
			if a.cfg.LogEvents {
				_ = enc.Encode(&ev)
			}
		}
	}
}
