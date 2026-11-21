package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf/rlimit"

	"github.com/chxmxii/kollektor/internal/archive"
	"github.com/chxmxii/kollektor/internal/events"
	"github.com/chxmxii/kollektor/internal/probes"
	"github.com/chxmxii/kollektor/internal/probes/exec"
)

// maxTraceEvents caps memory use during a capture window.
const maxTraceEvents = 1_000_000

// collectTrace runs the eBPF probes for TraceDuration and writes one NDJSON
// file per probe. eBPF failures (old kernel, missing privileges) are
// recorded, not fatal: the rest of the node evidence is still valuable.
func collectTrace(ctx context.Context, opts Options, w *archive.Writer, log *slog.Logger) error {
	if opts.TraceDuration <= 0 {
		return nil
	}
	// Only needed on kernels < 5.11; if it fails, still try to load the
	// probes so the recorded error is the real one.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Warn("could not remove memlock rlimit", "err", err)
	}

	ctx, cancel := context.WithTimeout(ctx, opts.TraceDuration)
	defer cancel()

	ps := []probes.Probe{exec.New(log)}
	ch := make(chan events.Event, 4096)
	errs := make(chan error, len(ps))
	for _, p := range ps {
		go func() {
			if err := p.Run(ctx, ch); err != nil {
				errs <- errors.New(p.Name() + ": " + err.Error())
				return
			}
			errs <- nil
		}()
	}

	cgroupRoots := []string{opts.CgroupRoot, filepath.Join(opts.HostRoot, "sys/fs/cgroup")}
	cgroups := buildCgroupIndex(cgroupRoots...)
	log.Info("tracing", "duration", opts.TraceDuration, "cgroups", len(cgroups))

	var evs []events.Event
	n, dropped, running := 0, 0, len(ps)
	for running > 0 {
		select {
		case ev := <-ch:
			if n >= maxTraceEvents {
				dropped++
				continue
			}
			enrich(opts.ProcRoot, &ev)
			evs = append(evs, ev)
			n++
		case err := <-errs:
			running--
			if err != nil {
				w.RecordError("trace: %v", err)
			}
		}
	}
	// Drain events emitted just before the probes stopped.
	for len(ch) > 0 {
		ev := <-ch
		enrich(opts.ProcRoot, &ev)
		evs = append(evs, ev)
		n++
	}

	// Attribute events whose process was gone by cgroup ID. Containers
	// started during the window are picked up by re-indexing once.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	reindexed := false
	unattributed := 0
	for i := range evs {
		ev := &evs[i]
		if ev.ContainerID == "" {
			id, ok := cgroups[ev.CgroupID]
			if !ok && !reindexed {
				cgroups, reindexed = buildCgroupIndex(cgroupRoots...), true
				id, ok = cgroups[ev.CgroupID]
			}
			if ok {
				ev.ContainerID = id
			} else if ev.ProcGone {
				unattributed++
			}
		}
		if err := enc.Encode(ev); err != nil {
			return err
		}
	}
	if dropped > 0 {
		w.RecordError("trace: %d events dropped after reaching %d", dropped, maxTraceEvents)
	}
	log.Info("trace finished", "events", n)

	if err := w.WriteJSON("trace/info.json", map[string]any{
		"probes":   []string{"exec"},
		"duration": opts.TraceDuration.String(),
		"ended":    time.Now().UTC(),
		"events":   n,
		// Exited before /proc could be read and not in a container cgroup:
		// host processes, or containers that were already removed.
		"unattributedExited": unattributed,
		"cgroupsIndexed":     len(cgroups),
	}); err != nil {
		return err
	}
	return w.WriteFile("trace/exec.ndjson", buf.Bytes())
}

// enrich reads details the kernel event does not carry from /proc. This
// races with the process: short-lived processes may already be gone.
func enrich(procRoot string, ev *events.Event) {
	dir := filepath.Join(procRoot, strconv.Itoa(int(ev.PID)))
	cmd, err := os.ReadFile(filepath.Join(dir, "cmdline"))
	if err != nil {
		ev.ProcGone = true
		return
	}
	ev.Cmdline = splitNull(cmd)
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		ev.Exe = exe
	}
	if stat, err := os.ReadFile(filepath.Join(dir, "stat")); err == nil {
		if end := bytes.LastIndexByte(stat, ')'); end > 0 {
			if f := strings.Fields(string(stat[end+1:])); len(f) > 1 {
				ev.PPID, _ = strconv.Atoi(f[1])
			}
		}
	}
	ev.ContainerID, _ = containerIDForPID(procRoot, int(ev.PID))
}
