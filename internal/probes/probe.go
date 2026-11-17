// Package probes holds the BPF probes kollektor can run. Each probe lives in
// its own subpackage with its generated bpf2go bindings.
package probes

import (
	"context"

	"github.com/chxmxii/kollektor/internal/events"
)

// Probe loads a BPF program, attaches it, and streams decoded events.
type Probe interface {
	// Name is a stable identifier used in config and metrics.
	Name() string
	// Run loads and attaches the probe, then emits events to out until ctx
	// is cancelled. It must release all kernel resources before returning.
	Run(ctx context.Context, out chan<- events.Event) error
}
