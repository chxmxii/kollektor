// Package metrics exposes Prometheus metrics derived from probe events.
package metrics

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/chxmxii/kollektor/internal/events"
)

type Metrics struct {
	reg    *prometheus.Registry
	events *prometheus.CounterVec
	drops  *prometheus.CounterVec
}

func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg: reg,
		// Per-pod labels keep cardinality bounded by pods-per-node; avoid
		// adding per-process labels (comm, pid) here.
		events: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "kollektor",
			Name:      "events_total",
			Help:      "Events observed by BPF probes.",
		}, []string{"type", "namespace", "pod"}),
		drops: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "kollektor",
			Name:      "events_dropped_total",
			Help:      "Events dropped in userspace because a consumer was too slow.",
		}, []string{"type"}),
	}
	reg.MustRegister(m.events, m.drops,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

func (m *Metrics) Observe(ev *events.Event) {
	ns, pod := "", ""
	if ev.Pod != nil {
		ns, pod = ev.Pod.Namespace, ev.Pod.Name
	}
	m.events.WithLabelValues(string(ev.Type), ns, pod).Inc()
}

func (m *Metrics) Dropped(t events.Type) { m.drops.WithLabelValues(string(t)).Inc() }

// Serve exposes /metrics and /healthz until ctx is cancelled.
func (m *Metrics) Serve(ctx context.Context, addr string, log *slog.Logger) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Info("serving metrics", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
