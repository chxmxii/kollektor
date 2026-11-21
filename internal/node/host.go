package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/chxmxii/kollektor/internal/archive"
)

// hostFiles are glob patterns relative to the node root. They cover OS
// identity, accounts, persistence mechanisms (cron, systemd, ssh keys,
// ld.so.preload), shell history, Kubernetes/runtime configuration and
// system logs.
var hostFiles = []string{
	// identity & configuration
	"etc/os-release", "etc/hostname", "etc/hosts", "etc/resolv.conf",
	"etc/passwd", "etc/group", "etc/sudoers", "etc/sudoers.d/*",
	"etc/ld.so.preload", "etc/ld.so.conf", "etc/ld.so.conf.d/*",
	"etc/fstab", "etc/modules", "etc/modules-load.d/*", "etc/modprobe.d/*",
	"etc/sysctl.conf", "etc/sysctl.d/*",
	// persistence
	"etc/crontab", "etc/cron.d/*", "etc/cron.hourly/*", "etc/cron.daily/*",
	"var/spool/cron/*", "var/spool/cron/crontabs/*",
	"etc/systemd/system/*.service", "etc/systemd/system/*.timer",
	"etc/systemd/system/*/*.service", "etc/systemd/system/*.service.d/*",
	"etc/rc.local", "etc/profile", "etc/profile.d/*", "etc/bash.bashrc",
	"root/.bashrc", "root/.profile",
	// remote access
	"etc/ssh/sshd_config", "etc/ssh/sshd_config.d/*",
	"root/.ssh/authorized_keys", "root/.ssh/authorized_keys2",
	"home/*/.ssh/authorized_keys", "home/*/.ssh/authorized_keys2",
	// shell history
	"root/.bash_history", "root/.ash_history", "root/.zsh_history", "root/.python_history",
	"home/*/.bash_history", "home/*/.ash_history", "home/*/.zsh_history",
	// kubernetes & container runtime
	"etc/kubernetes/manifests/*", "etc/kubernetes/*.conf", "etc/kubernetes/*.yaml",
	"etc/kubernetes/pki/*.crt", "etc/kubernetes/pki/etcd/*.crt",
	"var/lib/kubelet/config.yaml", "var/lib/kubelet/kubeadm-flags.env", "var/lib/kubelet/kubeconfig",
	"etc/systemd/system/kubelet.service.d/*", "usr/lib/systemd/system/kubelet.service",
	"usr/lib/systemd/system/kubelet.service.d/*", "etc/default/kubelet",
	"etc/containerd/config.toml", "etc/containerd/certs.d/*/hosts.toml", "etc/crictl.yaml",
	"etc/docker/daemon.json", "etc/crio/crio.conf", "etc/crio/crio.conf.d/*",
	"etc/cni/net.d/*",
	// logs (large ones keep their most recent MaxFileSize bytes)
	"var/log/auth.log", "var/log/secure", "var/log/syslog", "var/log/messages",
	"var/log/kern.log", "var/log/audit/audit.log", "var/log/kubernetes/*.log",
	"var/log/kubernetes/audit/*.log", "var/log/kube-apiserver/*.log",
}

// sensitiveHostFiles are only collected with IncludeSecrets.
var sensitiveHostFiles = []string{
	"etc/shadow", "etc/gshadow",
	"etc/kubernetes/pki/*.key", "etc/kubernetes/pki/etcd/*.key",
}

// Credentials inside kubeconfigs and similar YAML.
var secretLineRe = regexp.MustCompile(`(?m)^(\s*(?:client-key-data|token|password|client-secret):\s*)(\S+)\s*$`)

type symlink struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}

func collectHostFiles(_ context.Context, opts Options, w *archive.Writer, _ *slog.Logger) error {
	patterns := hostFiles
	if opts.IncludeSecrets {
		patterns = append(append([]string{}, hostFiles...), sensitiveHostFiles...)
	}

	seen := map[string]bool{}
	var links []symlink
	for _, pat := range patterns {
		matches, _ := filepath.Glob(filepath.Join(opts.HostRoot, pat))
		for _, m := range matches {
			rel, err := filepath.Rel(opts.HostRoot, m)
			if err != nil || seen[rel] {
				continue
			}
			seen[rel] = true

			real, target, err := resolveInRoot(opts.HostRoot, rel)
			if err != nil {
				w.RecordError("host %s: %v", rel, err)
				continue
			}
			if target != "" {
				links = append(links, symlink{Path: "/" + rel, Target: target})
			}
			if err := copyHostFile(opts, w, real, path.Join("host", filepath.ToSlash(rel))); err != nil {
				return err
			}
		}
	}
	if len(links) > 0 {
		return w.WriteJSON("host/symlinks.json", links)
	}
	return nil
}

// copyHostFile copies one file. Unreadable files are recorded, not fatal.
func copyHostFile(opts Options, w *archive.Writer, src, name string) error {
	f, err := os.Open(src)
	if err != nil {
		w.RecordError("host %s: %v", name, err)
		return nil
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil
	}

	size := fi.Size()
	if size > opts.MaxFileSize {
		// Keep the most recent part: for logs that is what matters.
		if _, err := f.Seek(size-opts.MaxFileSize, io.SeekStart); err != nil {
			w.RecordError("host %s: %v", name, err)
			return nil
		}
		w.RecordError("host %s: truncated to last %d of %d bytes", name, opts.MaxFileSize, size)
		size = opts.MaxFileSize
	}

	if !opts.IncludeSecrets && isKubeconfigLike(name) {
		data, err := io.ReadAll(io.LimitReader(f, size))
		if err != nil {
			w.RecordError("host %s: %v", name, err)
			return nil
		}
		return w.WriteFile(name, redactSecretLines(data))
	}

	// Files on a live system can change size while being read; read what
	// is there now so the declared tar size is exact.
	data, err := io.ReadAll(io.LimitReader(f, size))
	if err != nil {
		w.RecordError("host %s: %v", name, err)
		return nil
	}
	return w.WriteFile(name, data)
}

func isKubeconfigLike(name string) bool {
	return strings.HasPrefix(name, "host/etc/kubernetes/") || strings.HasPrefix(name, "host/var/lib/kubelet/")
}

// redactSecretLines replaces credential values with their SHA-256.
func redactSecretLines(data []byte) []byte {
	return secretLineRe.ReplaceAllFunc(data, func(line []byte) []byte {
		m := secretLineRe.FindSubmatch(line)
		sum := sha256.Sum256(m[2])
		return append(append([]byte{}, m[1]...), []byte(`"kollektor-redacted:sha256:`+hex.EncodeToString(sum[:])+`"`)...)
	})
}

// resolveInRoot follows symlinks of the final path component so that an
// absolute link target (e.g. /etc/resolv.conf -> /run/systemd/...) is
// resolved against the node root, not the collector container. It returns
// the real path to open and the first link target, if any.
func resolveInRoot(root, rel string) (string, string, error) {
	p := filepath.Join(root, rel)
	first := ""
	for range 16 {
		fi, err := os.Lstat(p)
		if err != nil {
			return "", first, err
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			return p, first, nil
		}
		t, err := os.Readlink(p)
		if err != nil {
			return "", first, err
		}
		if first == "" {
			first = t
		}
		if filepath.IsAbs(t) {
			p = filepath.Join(root, t)
		} else {
			p = filepath.Join(filepath.Dir(p), t)
		}
		if r, err := filepath.Rel(root, p); err != nil || strings.HasPrefix(r, "..") {
			return "", first, errors.New("symlink escapes node root")
		}
	}
	return "", first, errors.New("too many symlinks")
}

// systemFiles are read from procfs (host PID namespace) and /sys.
var systemFiles = map[string]string{
	"system/kernel-version":   "version",
	"system/kernel-cmdline":   "cmdline",
	"system/modules":          "modules",
	"system/mounts":           "1/mounts",
	"system/uptime":           "uptime",
	"system/loadavg":          "loadavg",
	"system/meminfo":          "meminfo",
	"system/cpuinfo":          "cpuinfo",
	"system/kernel-tainted":   "sys/kernel/tainted",
	"system/kptr_restrict":    "sys/kernel/kptr_restrict",
	"system/unprivileged_bpf": "sys/kernel/unprivileged_bpf_disabled",
	"system/ip_forward":       "sys/net/ipv4/ip_forward",
	"system/stat":             "stat",
	"network/routes":          "1/net/route",
	"network/routes6":         "1/net/ipv6_route",
	"network/arp":             "1/net/arp",
	"network/interfaces":      "1/net/dev",
	"network/conntrack":       "1/net/nf_conntrack",
}

func collectSystemState(_ context.Context, opts Options, w *archive.Writer, _ *slog.Logger) error {
	for name, src := range systemFiles {
		data, err := os.ReadFile(filepath.Join(opts.ProcRoot, src))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				w.RecordError("%s: %v", name, err)
			}
			continue
		}
		if err := w.WriteFile(name, data); err != nil {
			return err
		}
	}
	return nil
}
