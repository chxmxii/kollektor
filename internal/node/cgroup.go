package node

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
)

// containerIDRe matches the 64-hex container ID that containerd, CRI-O and
// docker embed in cgroup paths, e.g.
//
//	/kubepods/burstable/pod<uid>/<id>
//	/kubepods.slice/.../cri-containerd-<id>.scope
//	/kubepods.slice/.../crio-<id>.scope
var containerIDRe = regexp.MustCompile(`[0-9a-f]{64}`)

// containerIDForPID returns the container ID of a process, or "" for host
// processes. Join it with cluster/container-index.json to get the pod.
func containerIDForPID(procRoot string, pid int) (string, error) {
	f, err := os.Open(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
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

// cgroupIndex maps cgroup IDs (as returned by bpf_get_current_cgroup_id) to
// container IDs. On cgroup v2 a cgroup's ID is the inode number of its
// directory, so the index can be built by walking cgroupfs. Unlike /proc, it
// still resolves events from processes that have already exited.
type cgroupIndex map[uint64]string

func buildCgroupIndex(roots ...string) cgroupIndex {
	idx := cgroupIndex{}
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return nil
			}
			m := containerIDRe.FindAllString(p, -1)
			if len(m) == 0 {
				return nil
			}
			if fi, err := d.Info(); err == nil {
				if st, ok := fi.Sys().(*syscall.Stat_t); ok {
					idx[st.Ino] = m[len(m)-1]
				}
			}
			return nil
		})
	}
	return idx
}
