package k8s

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/chxmxii/kollektor/internal/events"
)

// containerIDRe matches the 64-hex container ID that containerd, CRI-O and
// docker embed in cgroup paths, e.g.
//
//	/kubepods/burstable/pod<uid>/<id>
//	/kubepods.slice/.../cri-containerd-<id>.scope
//	/kubepods.slice/.../crio-<id>.scope
var containerIDRe = regexp.MustCompile(`[0-9a-f]{64}`)

// maxCacheEntries bounds the cgroup → pod cache; it is reset when full.
const maxCacheEntries = 16384

// Resolver maps a process to its pod using /proc/<pid>/cgroup and the PodCache.
// Lookups are memoized by cgroup ID, so each container is resolved via procfs
// only once.
//
// Requires hostPID so that procRoot shows host PIDs.
type Resolver struct {
	pods     *PodCache
	procRoot string

	mu    sync.Mutex
	cache map[uint64]*events.PodRef
}

func NewResolver(pods *PodCache, procRoot string) *Resolver {
	return &Resolver{pods: pods, procRoot: procRoot, cache: make(map[uint64]*events.PodRef)}
}

// Enrich fills ev.Pod if the process belongs to a known pod.
func (r *Resolver) Enrich(ev *events.Event) {
	r.mu.Lock()
	ref, ok := r.cache[ev.CgroupID]
	r.mu.Unlock()
	if ok {
		ev.Pod = ref
		return
	}

	cid, err := r.containerIDForPID(ev.PID)
	if err != nil || cid == "" {
		// Host process, or it exited before we could read procfs.
		return
	}
	ref = r.pods.ByContainerID(cid)
	if ref == nil {
		// Not cached: the pod status may not carry the container ID yet.
		return
	}

	r.mu.Lock()
	if len(r.cache) >= maxCacheEntries {
		clear(r.cache)
	}
	r.cache[ev.CgroupID] = ref
	r.mu.Unlock()
	ev.Pod = ref
}

func (r *Resolver) containerIDForPID(pid uint32) (string, error) {
	f, err := os.Open(filepath.Join(r.procRoot, fmt.Sprint(pid), "cgroup"))
	if err != nil {
		return "", err
	}
	defer f.Close()

	var id string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := containerIDRe.FindAllString(sc.Text(), -1); len(m) > 0 {
			id = m[len(m)-1]
		}
	}
	return id, sc.Err()
}
