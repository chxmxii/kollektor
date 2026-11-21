package node

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/chxmxii/kollektor/internal/archive"
)

// userHZ is the clock tick rate used by /proc/<pid>/stat. It is 100 on every
// mainstream Linux architecture.
const userHZ = 100

// maxHashSize bounds how much of a binary is hashed.
const maxHashSize = 512 << 20

// Process is a snapshot of one host process.
type Process struct {
	PID         int               `json:"pid"`
	PPID        int               `json:"ppid"`
	Name        string            `json:"name"`
	State       string            `json:"state"`
	UID         []int             `json:"uid,omitempty"` // real, effective, saved, fs
	GID         []int             `json:"gid,omitempty"`
	Cmdline     []string          `json:"cmdline,omitempty"`
	Exe         string            `json:"exe,omitempty"`
	ExeDeleted  bool              `json:"exeDeleted,omitempty"` // running binary was deleted from disk
	ExeSHA256   string            `json:"exeSha256,omitempty"`
	Cwd         string            `json:"cwd,omitempty"`
	Started     time.Time         `json:"started"`
	Threads     int               `json:"threads,omitempty"`
	CapEff      string            `json:"capEff,omitempty"`
	Seccomp     string            `json:"seccomp,omitempty"`
	ContainerID string            `json:"containerId,omitempty"` // join with cluster/container-index.json
	Namespaces  map[string]string `json:"namespaces,omitempty"`
	LDPreload   string            `json:"ldPreload,omitempty"`
	Environ     []string          `json:"environ,omitempty"` // only with IncludeSecrets
	Self        bool              `json:"self,omitempty"`    // the kollektor collector itself
	Error       string            `json:"error,omitempty"`
}

func collectProcesses(_ context.Context, opts Options, w *archive.Writer, log *slog.Logger) error {
	procs, err := snapshotProcesses(opts)
	if err != nil {
		w.RecordError("processes: %v", err)
		return nil
	}
	log.Info("process snapshot", "processes", len(procs))
	return w.WriteJSON("processes.json", procs)
}

func snapshotProcesses(opts Options) ([]Process, error) {
	bootTime, err := readBootTime(opts.ProcRoot)
	if err != nil {
		return nil, err
	}
	pids, err := listPIDs(opts.ProcRoot)
	if err != nil {
		return nil, err
	}

	hashes := map[[2]uint64]string{} // (dev, inode) → sha256, so shared binaries are hashed once
	self := os.Getpid()
	var procs []Process
	for _, pid := range pids {
		p := readProcess(opts, pid, bootTime, hashes)
		p.Self = pid == self
		procs = append(procs, p)
	}
	return procs, nil
}

func readProcess(opts Options, pid int, bootTime time.Time, hashes map[[2]uint64]string) Process {
	dir := filepath.Join(opts.ProcRoot, strconv.Itoa(pid))
	p := Process{PID: pid}

	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		p.Error = err.Error()
		return p
	}
	if err := parseStat(stat, &p, bootTime); err != nil {
		p.Error = err.Error()
	}
	parseStatus(filepath.Join(dir, "status"), &p)

	if cmd, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		p.Cmdline = splitNull(cmd)
	}
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		p.Exe = strings.TrimSuffix(exe, " (deleted)")
		p.ExeDeleted = strings.HasSuffix(exe, " (deleted)")
		// Hash via /proc/<pid>/exe: works even when the file was deleted
		// or lives in another mount namespace (container image).
		p.ExeSHA256 = hashExe(filepath.Join(dir, "exe"), hashes)
	}
	if cwd, err := os.Readlink(filepath.Join(dir, "cwd")); err == nil {
		p.Cwd = cwd
	}
	p.ContainerID, _ = containerIDForPID(opts.ProcRoot, pid)

	p.Namespaces = map[string]string{}
	for _, ns := range []string{"pid", "net", "mnt", "user", "uts", "ipc", "cgroup"} {
		if l, err := os.Readlink(filepath.Join(dir, "ns", ns)); err == nil {
			p.Namespaces[ns] = l
		}
	}

	if env, err := os.ReadFile(filepath.Join(dir, "environ")); err == nil {
		vars := splitNull(env)
		for _, v := range vars {
			if strings.HasPrefix(v, "LD_PRELOAD=") {
				p.LDPreload = strings.TrimPrefix(v, "LD_PRELOAD=")
			}
		}
		if opts.IncludeSecrets {
			p.Environ = vars
		}
	}
	return p
}

// parseStat parses /proc/<pid>/stat. The command name is in parentheses and
// may itself contain spaces or parentheses, so split after the last ')'.
func parseStat(b []byte, p *Process, bootTime time.Time) error {
	open := bytes.IndexByte(b, '(')
	end := bytes.LastIndexByte(b, ')')
	if open < 0 || end < open {
		return fmt.Errorf("malformed stat")
	}
	p.Name = string(b[open+1 : end])
	f := strings.Fields(string(b[end+1:]))
	// f[0] = state (field 3), f[1] = ppid (field 4), f[19] = starttime (field 22)
	if len(f) < 20 {
		return fmt.Errorf("short stat")
	}
	p.State = f[0]
	p.PPID, _ = strconv.Atoi(f[1])
	if ticks, err := strconv.ParseUint(f[19], 10, 64); err == nil {
		p.Started = bootTime.Add(time.Duration(ticks) * time.Second / userHZ).UTC()
	}
	return nil
}

func parseStatus(file string, p *Process) {
	f, err := os.Open(file)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Uid":
			p.UID = atoiFields(v)
		case "Gid":
			p.GID = atoiFields(v)
		case "Threads":
			p.Threads, _ = strconv.Atoi(v)
		case "CapEff":
			p.CapEff = v
		case "Seccomp":
			p.Seccomp = v
		}
	}
}

func hashExe(path string, cache map[[2]uint64]string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return ""
	}
	var key [2]uint64
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		key = [2]uint64{uint64(st.Dev), st.Ino}
		if h, ok := cache[key]; ok {
			return h
		}
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxHashSize)); err != nil {
		return ""
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if fi.Size() > maxHashSize {
		sum = "partial:" + sum
	}
	if key != [2]uint64{} {
		cache[key] = sum
	}
	return sum
}

func readBootTime(procRoot string) (time.Time, error) {
	f, err := os.Open(filepath.Join(procRoot, "stat"))
	if err != nil {
		return time.Time{}, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "btime "); ok {
			s, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return time.Time{}, err
			}
			return time.Unix(s, 0), nil
		}
	}
	return time.Time{}, fmt.Errorf("btime not found in %s/stat", procRoot)
}

func listPIDs(procRoot string) ([]int, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	return pids, nil
}

func splitNull(b []byte) []string {
	b = bytes.TrimRight(b, "\x00")
	if len(b) == 0 {
		return nil
	}
	parts := bytes.Split(b, []byte{0})
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = string(p)
	}
	return out
}

func atoiFields(s string) []int {
	var out []int
	for _, f := range strings.Fields(s) {
		n, _ := strconv.Atoi(f)
		out = append(out, n)
	}
	return out
}
