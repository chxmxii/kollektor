// Package archive reads and writes kollektor evidence archives.
//
// An archive is a zstd-compressed tar stream. All entries live under a single
// root directory; manifest.json is always the last entry and records the
// SHA-256 and size of every other file, so an archive can be verified in one
// streaming pass.
package archive

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
)

const (
	Format       = "kollektor/v1"
	ManifestName = "manifest.json"
)

// Entry describes one file in the archive.
type Entry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Metadata describes how, when, where and by whom an archive was collected.
type Metadata struct {
	ToolVersion   string    `json:"toolVersion"`
	Started       time.Time `json:"started"`
	Finished      time.Time `json:"finished"`
	Command       []string  `json:"command"`
	Host          string    `json:"host"`
	OSUser        string    `json:"osUser"`
	KubeContext   string    `json:"kubeContext"`
	KubeServer    string    `json:"kubeServer"`
	KubeUser      string    `json:"kubeUser,omitempty"`
	KubeGroups    []string  `json:"kubeGroups,omitempty"`
	ServerVersion string    `json:"serverVersion,omitempty"`
	Namespaces    []string  `json:"namespaces,omitempty"` // empty = all
	SecretsRaw    bool      `json:"secretsRaw"`
}

// Manifest is the content of manifest.json.
type Manifest struct {
	Format   string   `json:"format"`
	Metadata Metadata `json:"metadata"`
	// Errors lists everything that could not be collected (forbidden
	// resources, failed log streams, ...). An incomplete collection is still
	// evidence, but the gaps must be documented.
	Errors []string `json:"errors,omitempty"`
	Files  []Entry  `json:"files"`
}

// Writer streams files into an archive. It is safe for concurrent use.
type Writer struct {
	path  string
	root  string
	mtime time.Time

	mu     sync.Mutex
	f      *os.File
	zw     *zstd.Encoder
	tw     *tar.Writer
	files  []Entry
	errs   []string
	closed bool
}

// Create creates a new archive at path. Entries are stored under a root
// directory named after the file (without extension).
func Create(p string) (*Writer, error) {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	zw, err := zstd.NewWriter(f, zstd.WithEncoderLevel(zstd.SpeedBetterCompression))
	if err != nil {
		f.Close()
		return nil, err
	}
	return &Writer{
		path:  p,
		root:  rootName(p),
		mtime: time.Now().UTC(),
		f:     f,
		zw:    zw,
		tw:    tar.NewWriter(zw),
	}, nil
}

// WriteFile adds a file with the given content.
func (w *Writer) WriteFile(name string, data []byte) error {
	return w.WriteFrom(name, bytes.NewReader(data), int64(len(data)))
}

// WriteFrom adds a file of exactly size bytes read from r.
func (w *Writer) WriteFrom(name string, r io.Reader, size int64) error {
	name, err := cleanName(name)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("archive is closed")
	}
	hdr := &tar.Header{
		Name:     path.Join(w.root, name),
		Mode:     0o644,
		Size:     size,
		ModTime:  w.mtime,
		Typeflag: tar.TypeReg,
		Format:   tar.FormatPAX,
	}
	if err := w.tw.WriteHeader(hdr); err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(w.tw, io.TeeReader(io.LimitReader(r, size), h))
	if err != nil {
		return err
	}
	if n != size {
		return fmt.Errorf("%s: wrote %d bytes, expected %d", name, n, size)
	}
	w.files = append(w.files, Entry{Path: name, Size: size, SHA256: hex.EncodeToString(h.Sum(nil))})
	return nil
}

// RecordError notes something that could not be collected.
func (w *Writer) RecordError(format string, args ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.errs = append(w.errs, fmt.Sprintf(format, args...))
}

// Close writes manifest.json and finalizes the archive.
func (w *Writer) Close(meta Metadata) (*Manifest, error) {
	w.mu.Lock()
	m := &Manifest{Format: Format, Metadata: meta, Errors: w.errs, Files: w.files}
	w.mu.Unlock()

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := w.WriteFile(ManifestName, data); err != nil {
		return nil, err
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	err = errors.Join(w.tw.Close(), w.zw.Close(), w.f.Sync(), w.f.Close())
	if err != nil {
		return nil, err
	}
	// Archives are evidence: make the result read-only.
	_ = os.Chmod(w.path, 0o400)
	return m, nil
}

// Abort closes and deletes a partially written archive.
func (w *Writer) Abort() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	w.closed = true
	_ = w.tw.Close()
	_ = w.zw.Close()
	_ = w.f.Close()
	_ = os.Remove(w.path)
}

// Walk calls fn for every regular file in the archive, in order, with its
// path relative to the archive root. fn must not retain r.
func Walk(p string, fn func(name string, r io.Reader) error) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := zstd.NewReader(f)
	if err != nil {
		return err
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		_, rel, ok := strings.Cut(hdr.Name, "/")
		if !ok {
			continue
		}
		if err := fn(rel, tr); err != nil {
			return err
		}
	}
}

// VerifyResult reports the outcome of Verify.
type VerifyResult struct {
	Manifest *Manifest
	Verified int
	Problems []string
}

// Verify reads the whole archive, hashes every file and checks it against
// manifest.json.
func Verify(p string) (*VerifyResult, error) {
	seen := map[string]Entry{}
	var manifest *Manifest
	err := Walk(p, func(name string, r io.Reader) error {
		if name == ManifestName {
			manifest = &Manifest{}
			return json.NewDecoder(r).Decode(manifest)
		}
		h := sha256.New()
		n, err := io.Copy(h, r)
		if err != nil {
			return err
		}
		seen[name] = Entry{Path: name, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if manifest == nil {
		return nil, errors.New("archive has no manifest.json (truncated or not a kollektor archive)")
	}

	res := &VerifyResult{Manifest: manifest}
	for _, want := range manifest.Files {
		got, ok := seen[want.Path]
		switch {
		case !ok:
			res.Problems = append(res.Problems, "missing: "+want.Path)
		case got.SHA256 != want.SHA256 || got.Size != want.Size:
			res.Problems = append(res.Problems, "hash mismatch: "+want.Path)
		default:
			res.Verified++
		}
		delete(seen, want.Path)
	}
	for name := range seen {
		res.Problems = append(res.Problems, "not in manifest: "+name)
	}
	return res, nil
}

func rootName(p string) string {
	base := path.Base(strings.ReplaceAll(p, "\\", "/"))
	for _, ext := range []string{".tar.zst", ".tzst", ".zst", ".tar"} {
		if strings.HasSuffix(base, ext) {
			return strings.TrimSuffix(base, ext)
		}
	}
	return base
}

func cleanName(name string) (string, error) {
	c := path.Clean(name)
	if c == "." || path.IsAbs(c) || c == ".." || strings.HasPrefix(c, "../") {
		return "", fmt.Errorf("invalid archive path %q", name)
	}
	return c, nil
}

// Extract writes every file in the archive below dir. Paths are validated so
// a crafted archive cannot write outside dir.
func Extract(p, dir string) (int, error) {
	n := 0
	err := Walk(p, func(name string, r io.Reader) error {
		clean, err := cleanName(name)
		if err != nil {
			return err
		}
		dst := filepath.Join(dir, filepath.FromSlash(clean))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, r); err != nil {
			f.Close()
			return err
		}
		n++
		return f.Close()
	})
	return n, err
}
