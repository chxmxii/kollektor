// Package exec traces process executions via the sched_process_exec
// raw tracepoint.
package exec

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/chxmxii/kollektor/internal/events"
)

//go:generate go tool bpf2go -tags linux -type exec_event -target bpfel,bpfeb bpf ../../../bpf/exec.c -- -O2 -g -Wall -Werror -I../../../bpf -I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu

// Probe implements probes.Probe for exec events.
type Probe struct {
	log *slog.Logger
}

func New(log *slog.Logger) *Probe {
	return &Probe{log: log.With("probe", "exec")}
}

func (p *Probe) Name() string { return string(events.TypeExec) }

func (p *Probe) Run(ctx context.Context, out chan<- events.Event) error {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading BPF objects: %w", err)
	}
	defer objs.Close()

	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exec",
		Program: objs.HandleExec,
	})
	if err != nil {
		return fmt.Errorf("attaching raw tracepoint: %w", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}
	defer rd.Close()

	// Unblock rd.Read when the context is cancelled.
	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()

	p.log.Info("probe attached")

	var raw bpfExecEvent
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("reading ringbuf: %w", err)
		}
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &raw); err != nil {
			p.log.Warn("decoding event", "err", err)
			continue
		}

		ev := events.Event{
			Type:     events.TypeExec,
			Time:     time.Now(), // TODO: convert raw.KtimeNs to wall clock via boot-time offset.
			PID:      raw.Tgid,
			TID:      raw.Pid,
			UID:      raw.Uid,
			Comm:     cString(raw.Comm[:]),
			CgroupID: raw.CgroupId,
		}

		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
}

func cString(b []uint8) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
