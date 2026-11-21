package archive

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundTripAndVerify(t *testing.T) {
	p := filepath.Join(t.TempDir(), "case-1.tar.zst")
	w, err := Create(p)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"cluster/default/pods/a.yaml": "kind: Pod\n",
		"logs/default/a/c.log":        strings.Repeat("line\n", 1000),
	}
	for name, content := range files {
		if err := w.WriteFile(name, []byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	w.RecordError("list foo: forbidden")
	m, err := w.Close(Metadata{ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 2 || len(m.Errors) != 1 {
		t.Fatalf("manifest: %d files, %d errors", len(m.Files), len(m.Errors))
	}

	got := map[string]string{}
	err = Walk(p, func(name string, _ int64, r io.Reader) error {
		b, err := io.ReadAll(r)
		got[name] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if got[name] != content {
			t.Errorf("%s: content mismatch", name)
		}
	}
	if _, ok := got[ManifestName]; !ok {
		t.Error("manifest.json missing")
	}

	res, err := Verify(p)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verified != 2 || len(res.Problems) != 0 {
		t.Fatalf("verify: %d ok, problems %v", res.Verified, res.Problems)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o400 {
		t.Errorf("archive mode = %v, want read-only", fi.Mode().Perm())
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "case.tar.zst")
	w, _ := Create(p)
	_ = w.WriteFile("logs/x.log", []byte("original evidence"))
	if _, err := w.Close(Metadata{}); err != nil {
		t.Fatal(err)
	}

	// Rewrite the archive with modified content but the original manifest.
	tampered := filepath.Join(dir, "case-t.tar.zst")
	tw, _ := Create(tampered)
	_ = Walk(p, func(name string, _ int64, r io.Reader) error {
		b, _ := io.ReadAll(r)
		if name == "logs/x.log" {
			b = []byte("modified evidence")
		}
		return tw.WriteFile(name, b) // manifest.json copied verbatim
	})
	tw.mu.Lock()
	tw.closed = true
	_ = tw.tw.Close()
	_ = tw.zw.Close()
	_ = tw.f.Close()
	tw.mu.Unlock()

	res, err := Verify(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) != 1 || !strings.HasPrefix(res.Problems[0], "hash mismatch") {
		t.Fatalf("problems = %v, want one hash mismatch", res.Problems)
	}
}

func TestRejectsUnsafePaths(t *testing.T) {
	w, _ := Create(filepath.Join(t.TempDir(), "x.tar.zst"))
	defer w.Abort()
	for _, bad := range []string{"../etc/passwd", "/abs", ".", ""} {
		if err := w.WriteFile(bad, nil); err == nil {
			t.Errorf("WriteFile(%q) accepted", bad)
		}
	}
}
