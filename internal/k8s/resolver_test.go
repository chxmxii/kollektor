package k8s

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContainerIDForPID(t *testing.T) {
	id := strings.Repeat("ab", 32)
	cases := map[string]string{
		"cgroupfs v1": "12:pids:/kubepods/burstable/pod1234-5678/" + id + "\n",
		"systemd v2":  "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234.slice/cri-containerd-" + id + ".scope\n",
		"crio v2":     "0::/kubepods.slice/kubepods-pod1234.slice/crio-" + id + ".scope\n",
		"host":        "0::/init.scope\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "42"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "42", "cgroup"), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := NewResolver(nil, root).containerIDForPID(42)
			if err != nil {
				t.Fatal(err)
			}
			want := id
			if name == "host" {
				want = ""
			}
			if got != want {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}
}

func TestStripRuntime(t *testing.T) {
	for in, want := range map[string]string{
		"containerd://abc": "abc",
		"cri-o://abc":      "abc",
		"abc":              "abc",
		"":                 "",
	} {
		if got := stripRuntime(in); got != want {
			t.Errorf("stripRuntime(%q) = %q, want %q", in, got, want)
		}
	}
}
