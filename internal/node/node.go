// Package node collects host-level evidence on a single Kubernetes node.
//
// It runs inside a privileged, hostPID pod with the node's root filesystem
// mounted read-only at HostRoot, and writes a kollektor archive (with its own
// manifest) to an io.Writer — stdout when driven by `kollektor collect`.
package node

import (
	"context"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/chxmxii/kollektor/internal/archive"
)

type Options struct {
	HostRoot       string        // node root filesystem, e.g. /host
	ProcRoot       string        // procfs showing host PIDs (needs hostPID)
	CgroupRoot     string        // host cgroupfs (cgroup v2), for attributing trace events
	TraceDuration  time.Duration // eBPF capture window; 0 disables tracing
	IncludeSecrets bool          // keep private keys, tokens, environment values
	MaxFileSize    int64         // larger host files keep only their last MaxFileSize bytes
	ToolVersion    string
}

// Run collects everything and writes the archive to out. Individual
// collection failures are recorded in the archive's manifest; only failures
// to write the archive are returned.
func Run(ctx context.Context, opts Options, out io.Writer, log *slog.Logger) error {
	if opts.ProcRoot == "" {
		opts.ProcRoot = "/proc"
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = 64 << 20
	}
	started := time.Now().UTC()

	w, err := archive.NewWriter(out, "node")
	if err != nil {
		return err
	}

	steps := []struct {
		name string
		fn   func(context.Context, Options, *archive.Writer, *slog.Logger) error
	}{
		{"host files", collectHostFiles},
		{"kernel and system state", collectSystemState},
		{"processes", collectProcesses},
		{"sockets", collectSockets},
		{"trace", collectTrace},
	}
	for _, s := range steps {
		log.Info("collecting", "step", s.name)
		if err := s.fn(ctx, opts, w, log); err != nil {
			w.Abort()
			return err
		}
	}

	host, _ := os.ReadFile(opts.HostRoot + "/etc/hostname")
	meta := archive.Metadata{
		ToolVersion: opts.ToolVersion,
		Started:     started,
		Finished:    time.Now().UTC(),
		Command:     os.Args,
		Host:        string(trimNL(host)),
		OSUser:      "root",
		SecretsRaw:  opts.IncludeSecrets,
	}
	_, err = w.Close(meta)
	return err
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
