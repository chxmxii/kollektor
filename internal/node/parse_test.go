package node

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseHexAddr(t *testing.T) {
	for in, want := range map[string]string{
		"0100007F:0035":                         "127.0.0.1:53",
		"00000000:1F90":                         "0.0.0.0:8080",
		"00000000000000000000000001000000:0016": "[::1]:22",
		"0000000000000000FFFF00000100007F:01BB": "127.0.0.1:443", // v4-mapped; proto (tcp6) keeps the family
	} {
		got, err := parseHexAddr(in)
		if err != nil || got != want {
			t.Errorf("parseHexAddr(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestParseSocketTable(t *testing.T) {
	table := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0A00000A:C350 08080808:0D05 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 20 4 30 10 -1
`
	socks, err := parseSocketTable(strings.NewReader(table), "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if len(socks) != 2 {
		t.Fatalf("got %d sockets", len(socks))
	}
	if s := socks[0]; s.Local != "127.0.0.1:53" || s.State != "LISTEN" || s.Inode != 12345 {
		t.Errorf("socket 0 = %+v", s)
	}
	if s := socks[1]; s.Remote != "8.8.8.8:3333" || s.State != "ESTABLISHED" || s.UID != 1000 {
		t.Errorf("socket 1 = %+v", s)
	}
}

func TestParseStat(t *testing.T) {
	// comm containing spaces and parentheses must not break field parsing.
	stat := "4242 (evil) (miner x) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 500 1000 100 0 0"
	boot := time.Unix(1_700_000_000, 0)
	var p Process
	if err := parseStat([]byte(stat), &p, boot); err != nil {
		t.Fatal(err)
	}
	if p.Name != "evil) (miner x" || p.State != "S" || p.PPID != 1 {
		t.Errorf("got name=%q state=%q ppid=%d", p.Name, p.State, p.PPID)
	}
	if want := boot.Add(5 * time.Second).UTC(); !p.Started.Equal(want) {
		t.Errorf("started = %v, want %v", p.Started, want)
	}
}

func TestRedactSecretLines(t *testing.T) {
	in := "users:\n- name: admin\n  user:\n    client-certificate-data: LS0tQ0VSVA==\n    client-key-data: LS0tS0VZ\n    token: abc.def\n"
	out := string(redactSecretLines([]byte(in)))
	if strings.Contains(out, "LS0tS0VZ") || strings.Contains(out, "abc.def") {
		t.Errorf("secrets not redacted:\n%s", out)
	}
	if !strings.Contains(out, "client-certificate-data: LS0tQ0VSVA==") {
		t.Errorf("certificate (public) should be kept:\n%s", out)
	}
	if !strings.Contains(out, `client-key-data: "kollektor-redacted:sha256:`) {
		t.Errorf("missing redaction marker:\n%s", out)
	}
}

func TestResolveInRoot(t *testing.T) {
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "etc"), 0o755))
	must(os.MkdirAll(filepath.Join(root, "run/systemd"), 0o755))
	must(os.WriteFile(filepath.Join(root, "run/systemd/resolv.conf"), []byte("nameserver 10.0.0.1"), 0o644))
	// Absolute link: must resolve inside root, not on the collector's own /run.
	must(os.Symlink("/run/systemd/resolv.conf", filepath.Join(root, "etc/resolv.conf")))
	must(os.Symlink("../../../../../etc/passwd", filepath.Join(root, "etc/escape")))

	real, target, err := resolveInRoot(root, "etc/resolv.conf")
	if err != nil || real != filepath.Join(root, "run/systemd/resolv.conf") || target != "/run/systemd/resolv.conf" {
		t.Errorf("resolv.conf: real=%q target=%q err=%v", real, target, err)
	}
	if _, _, err := resolveInRoot(root, "etc/escape"); err == nil {
		t.Error("escaping symlink was followed")
	}
}
