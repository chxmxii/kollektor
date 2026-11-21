package collect

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/chxmxii/kollektor/internal/archive"
)

const (
	collectorContainer = "collector"
	runLabel           = "kollektor.io/run"
	podReadyTimeout    = 3 * time.Minute
	nodeExecGrace      = 15 * time.Minute // on top of the trace duration
	maxCollectorLog    = 1 << 20
)

// NodeOptions controls host-level collection through temporary pods.
type NodeOptions struct {
	Nodes         string // "all", "none", or comma-separated node names
	Namespace     string // where collection pods run (created and removed if missing)
	Image         string // image containing /kollektor; empty = upload this binary
	HelperImage   string // image with sh/cat/sleep used when uploading this binary
	TraceDuration time.Duration
}

type nodeRun struct {
	c        *collector
	runID    string
	selfPath string // binary to upload, when not using Image
}

// collectNodes runs the hidden `kollektor node` command on every selected
// node and imports each node archive under nodes/<node>/.
func (c *collector) collectNodes(ctx context.Context) error {
	o := c.opts.Node
	if o.Nodes == "none" {
		return nil
	}
	nodes, err := c.selectNodes(ctx, o.Nodes)
	if err != nil {
		c.out.RecordError("nodes: %v", err)
		return nil
	}

	r := &nodeRun{c: c, runID: fmt.Sprintf("%d", time.Now().Unix())}
	if o.Image == "" {
		r.selfPath, err = uploadableBinary()
		if err != nil {
			c.out.RecordError("nodes: skipped, cannot upload this binary (%v); pass --image with a kollektor image", err)
			c.log.Warn("skipping node collection", "err", err)
			return nil
		}
	}

	created, err := c.ensureNamespace(ctx, o.Namespace)
	if err != nil {
		c.out.RecordError("nodes: namespace %s: %v", o.Namespace, err)
		return nil
	}
	defer r.cleanup(o.Namespace, created)

	c.log.Info("collecting from nodes", "nodes", len(nodes), "trace", o.TraceDuration)
	sem := make(chan struct{}, c.opts.Concurrency)
	var wg sync.WaitGroup
	errc := make(chan error, 1)
	for _, n := range nodes {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if err := r.collectNode(ctx, n); err != nil {
				select {
				case errc <- err:
				default:
				}
			}
		}()
	}
	wg.Wait()
	select {
	case err := <-errc:
		return err
	default:
		return nil
	}
}

func (c *collector) selectNodes(ctx context.Context, sel string) ([]corev1.Node, error) {
	list, err := c.cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	if sel == "" || sel == "all" {
		return list.Items, nil
	}
	want := strings.Split(sel, ",")
	var out []corev1.Node
	for _, n := range list.Items {
		if slices.Contains(want, n.Name) {
			out = append(out, n)
		}
	}
	if len(out) != len(want) {
		return out, fmt.Errorf("some requested nodes were not found (requested %v)", want)
	}
	return out, nil
}

func (c *collector) ensureNamespace(ctx context.Context, name string) (bool, error) {
	_, err := c.cs.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return false, nil
	}
	if !apierrors.IsNotFound(err) {
		return false, err
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: name,
		Labels: map[string]string{
			"app.kubernetes.io/managed-by":       "kollektor",
			"pod-security.kubernetes.io/enforce": "privileged",
		},
	}}
	if _, err := c.cs.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil {
		return false, err
	}
	c.addFootprint("created namespace %s", name)
	return true, nil
}

func (r *nodeRun) collectNode(ctx context.Context, n corev1.Node) error {
	c, o := r.c, r.c.opts.Node
	log := c.log.With("node", n.Name)

	if r.selfPath != "" {
		info := n.Status.NodeInfo
		if info.OperatingSystem != "linux" || info.Architecture != runtime.GOARCH {
			c.out.RecordError("node %s: skipped, node is %s/%s but this binary is linux/%s; pass --image",
				n.Name, info.OperatingSystem, info.Architecture, runtime.GOARCH)
			return nil
		}
	}

	pod, err := c.cs.CoreV1().Pods(o.Namespace).Create(ctx, r.podSpec(n.Name), metav1.CreateOptions{})
	if err != nil {
		c.out.RecordError("node %s: creating collection pod: %v", n.Name, err)
		return nil
	}
	c.addFootprint("created pod %s/%s on node %s (privileged, hostPID, node root mounted read-only)", o.Namespace, pod.Name, n.Name)

	if err := c.waitRunning(ctx, o.Namespace, pod.Name); err != nil {
		c.out.RecordError("node %s: collection pod did not start: %v", n.Name, err)
		return nil
	}

	cmd, stdin, err := r.nodeCommand()
	if err != nil {
		return err
	}
	if stdin != nil {
		defer stdin.Close()
	}

	spool, err := os.CreateTemp("", "kollektor-node-")
	if err != nil {
		return err
	}
	defer os.Remove(spool.Name())
	defer spool.Close()

	stderr := &capped{max: maxCollectorLog}
	execCtx, cancel := context.WithTimeout(ctx, o.TraceDuration+nodeExecGrace)
	defer cancel()

	log.Info("running node collector")
	var in io.Reader
	if stdin != nil {
		in = stdin
	}
	execErr := c.exec(execCtx, o.Namespace, pod.Name, cmd, in, spool, stderr)
	if execErr != nil {
		c.out.RecordError("node %s: node collector: %v", n.Name, execErr)
	}

	prefix := path.Join("nodes", n.Name)
	if err := c.out.WriteFile(path.Join(prefix, "collector.log"), stderr.Bytes()); err != nil {
		return err
	}
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return r.importNodeArchive(n.Name, prefix, spool)
}

// importNodeArchive copies the node's archive into the main archive and
// checks every file against the node's own manifest, so tampering or
// corruption between the node and the workstation is detected.
func (r *nodeRun) importNodeArchive(node, prefix string, src io.Reader) error {
	c := r.c
	seen := map[string]archive.Entry{}
	var manifest *archive.Manifest
	var writeErr error

	walkErr := archive.WalkReader(src, func(name string, size int64, rd io.Reader) error {
		if name == archive.ManifestName {
			data, err := io.ReadAll(rd)
			if err != nil {
				return err
			}
			manifest = &archive.Manifest{}
			if err := json.Unmarshal(data, manifest); err != nil {
				return err
			}
			if err := c.out.WriteFile(path.Join(prefix, archive.ManifestName), data); err != nil {
				writeErr = err
				return err
			}
			return nil
		}
		e, err := c.out.WriteFrom(path.Join(prefix, name), rd, size)
		if err != nil {
			writeErr = err
			return err
		}
		seen[name] = archive.Entry{Path: name, Size: e.Size, SHA256: e.SHA256}
		return nil
	})
	if writeErr != nil {
		return writeErr
	}
	if walkErr != nil {
		c.out.RecordError("node %s: node archive truncated or unreadable: %v", node, walkErr)
	}
	if manifest == nil {
		c.out.RecordError("node %s: node archive has no manifest; %d files imported unverified", node, len(seen))
		return nil
	}

	verified, problems := archive.Compare(manifest.Files, seen)
	for _, p := range problems {
		c.out.RecordError("node %s: integrity: %s", node, p)
	}
	for _, e := range manifest.Errors {
		c.out.RecordError("node %s: %s", node, e)
	}
	c.log.Info("node collected", "node", node, "files", verified, "errors", len(manifest.Errors))
	return nil
}

func (r *nodeRun) podSpec(node string) *corev1.Pod {
	o := r.c.opts.Node
	image, cmd := o.HelperImage, []string{"sleep", "86400"}
	if o.Image != "" {
		image, cmd = o.Image, []string{"/kollektor", "idle"}
	}
	t := true
	grace := int64(1)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "kollektor-node-",
			Labels: map[string]string{
				"app.kubernetes.io/name":       "kollektor",
				"app.kubernetes.io/managed-by": "kollektor",
				runLabel:                       r.runID,
			},
		},
		Spec: corev1.PodSpec{
			NodeName:                      node, // bypass the scheduler: run even on cordoned/tainted nodes
			HostPID:                       true,
			RestartPolicy:                 corev1.RestartPolicyNever,
			AutomountServiceAccountToken:  new(bool),
			TerminationGracePeriodSeconds: &grace,
			Tolerations:                   []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
			Containers: []corev1.Container{{
				Name:            collectorContainer,
				Image:           image,
				ImagePullPolicy: corev1.PullIfNotPresent,
				Command:         cmd,
				SecurityContext: &corev1.SecurityContext{Privileged: &t},
				VolumeMounts: []corev1.VolumeMount{
					{Name: "host", MountPath: "/host", ReadOnly: true},
					// cgroupfs is a separate mount, not always visible under /host.
					{Name: "cgroup", MountPath: "/hostcgroup", ReadOnly: true},
				},
			}},
			Volumes: []corev1.Volume{
				{Name: "host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/"}}},
				{Name: "cgroup", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/cgroup"}}},
			},
		},
	}
}

// nodeCommand returns the exec command and, when uploading this binary, the
// file to stream to its stdin.
func (r *nodeRun) nodeCommand() ([]string, *os.File, error) {
	o := r.c.opts
	args := []string{"node", "--host-root", "/host", "--cgroup-root", "/hostcgroup", "--trace-duration", o.Node.TraceDuration.String(), "--tool-version", o.ToolVersion}
	if o.IncludeSecrets {
		args = append(args, "--include-secrets")
	}
	if r.selfPath == "" {
		return append([]string{"/kollektor"}, args...), nil, nil
	}
	f, err := os.Open(r.selfPath)
	if err != nil {
		return nil, nil, err
	}
	script := "cat > /tmp/kollektor && chmod +x /tmp/kollektor && exec /tmp/kollektor " + strings.Join(args, " ")
	return []string{"sh", "-c", script}, f, nil
}

func (c *collector) waitRunning(ctx context.Context, ns, name string) error {
	var last string
	err := wait.PollUntilContextTimeout(ctx, 2*time.Second, podReadyTimeout, true, func(ctx context.Context) (bool, error) {
		p, err := c.cs.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		switch p.Status.Phase {
		case corev1.PodRunning:
			return true, nil
		case corev1.PodFailed, corev1.PodSucceeded:
			return false, fmt.Errorf("pod %s", p.Status.Phase)
		}
		for _, s := range p.Status.ContainerStatuses {
			if w := s.State.Waiting; w != nil {
				last = w.Reason + ": " + w.Message
				if w.Reason == "ErrImagePull" || w.Reason == "ImagePullBackOff" || w.Reason == "InvalidImageName" {
					return false, errors.New(last)
				}
			}
		}
		return false, nil
	})
	if err != nil && last != "" && !strings.Contains(err.Error(), last) {
		return fmt.Errorf("%w (last status: %s)", err, last)
	}
	return err
}

func (c *collector) exec(ctx context.Context, ns, pod string, cmd []string, stdin io.Reader, stdout, stderr io.Writer) error {
	req := c.cs.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(ns).Name(pod).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: collectorContainer,
			Command:   cmd,
			Stdin:     stdin != nil,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	spdy, err := remotecommand.NewSPDYExecutor(c.restConfig, "POST", req.URL())
	if err != nil {
		return err
	}
	ws, err := remotecommand.NewWebSocketExecutor(c.restConfig, "GET", req.URL().String())
	if err != nil {
		return err
	}
	ex, err := remotecommand.NewFallbackExecutor(ws, spdy, func(err error) bool {
		return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
	})
	if err != nil {
		return err
	}
	return ex.StreamWithContext(ctx, remotecommand.StreamOptions{Stdin: stdin, Stdout: stdout, Stderr: stderr})
}

// cleanup deletes the collection pods (and the namespace, if kollektor
// created it). It runs even if the collection was interrupted.
func (r *nodeRun) cleanup(ns string, deleteNamespace bool) {
	c := r.c
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	sel := metav1.ListOptions{LabelSelector: runLabel + "=" + r.runID}
	pods, err := c.cs.CoreV1().Pods(ns).List(ctx, sel)
	if err == nil {
		grace := int64(0)
		for _, p := range pods.Items {
			if err := c.cs.CoreV1().Pods(ns).Delete(ctx, p.Name, metav1.DeleteOptions{GracePeriodSeconds: &grace}); err != nil && !apierrors.IsNotFound(err) {
				c.out.RecordError("cleanup: deleting pod %s/%s: %v (delete it manually)", ns, p.Name, err)
			} else {
				c.addFootprint("deleted pod %s/%s", ns, p.Name)
			}
		}
	} else {
		c.out.RecordError("cleanup: listing collection pods: %v (delete pods labeled %s=%s manually)", err, runLabel, r.runID)
	}

	if deleteNamespace {
		if err := c.cs.CoreV1().Namespaces().Delete(ctx, ns, metav1.DeleteOptions{}); err != nil {
			c.out.RecordError("cleanup: deleting namespace %s: %v", ns, err)
		} else {
			c.addFootprint("deleted namespace %s", ns)
		}
	}
}

// uploadableBinary returns the path of this executable if it can run inside
// an arbitrary Linux container: a static linux binary.
func uploadableBinary() (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("this binary is built for %s", runtime.GOOS)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	f, err := elf.Open(exe)
	if err != nil {
		return "", err
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return "", errors.New("binary is dynamically linked; rebuild with CGO_ENABLED=0 (make build)")
		}
	}
	return exe, nil
}

// capped is a bytes.Buffer that stops growing after max bytes.
type capped struct {
	bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.Len(); room > 0 {
		if len(p) > room {
			c.Buffer.Write(p[:room])
		} else {
			c.Buffer.Write(p)
		}
	}
	return len(p), nil
}
