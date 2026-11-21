// Package collect gathers cluster state and logs into a kollektor archive.
package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"

	"github.com/chxmxii/kollektor/internal/archive"
	"github.com/chxmxii/kollektor/internal/k8s"
)

// ClusterScopeDir is the namespace directory used for cluster-scoped objects.
const ClusterScopeDir = "_cluster"

type Options struct {
	Output         string
	Kubeconfig     string
	Context        string
	Namespaces     []string // empty = all namespaces
	IncludeSecrets bool     // store raw Secret values instead of hashes
	Logs           bool
	LogSince       time.Duration // 0 = full log
	Concurrency    int
	ToolVersion    string
	Node           NodeOptions
}

// skipResources are listable but useless or duplicated as evidence.
var skipResources = map[schema.GroupResource]bool{
	{Group: "events.k8s.io", Resource: "events"}: true, // same objects as core/v1 events
	{Group: "", Resource: "componentstatuses"}:   true, // deprecated, always warns
}

type collector struct {
	opts       Options
	log        *slog.Logger
	restConfig *rest.Config
	cs         kubernetes.Interface
	dyn        dynamic.Interface
	out        *archive.Writer

	mu        sync.Mutex
	pods      []corev1.Pod
	objs      int
	footprint []string
}

func (c *collector) addFootprint(format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.footprint = append(c.footprint, time.Now().UTC().Format(time.RFC3339)+" "+fmt.Sprintf(format, args...))
}

// Run performs a full collection and returns the archive path and manifest.
func Run(ctx context.Context, opts Options, log *slog.Logger) (string, *archive.Manifest, error) {
	started := time.Now().UTC()

	target, err := k8s.LoadTarget(opts.Kubeconfig, opts.Context)
	if err != nil {
		return "", nil, err
	}
	cs, err := kubernetes.NewForConfig(target.Config)
	if err != nil {
		return "", nil, err
	}
	dyn, err := dynamic.NewForConfig(target.Config)
	if err != nil {
		return "", nil, err
	}

	if opts.Output == "" {
		opts.Output = fmt.Sprintf("kollektor-%s-%s.tar.zst", safeName(target.Context), started.Format("20060102T150405Z"))
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}

	out, err := archive.Create(opts.Output)
	if err != nil {
		return "", nil, err
	}
	c := &collector{opts: opts, log: log, restConfig: target.Config, cs: cs, dyn: dyn, out: out}

	meta := archive.Metadata{
		ToolVersion: opts.ToolVersion,
		Started:     started,
		Command:     os.Args,
		KubeContext: target.Context,
		KubeServer:  target.Server,
		Namespaces:  opts.Namespaces,
		SecretsRaw:  opts.IncludeSecrets,
	}
	meta.Host, _ = os.Hostname()
	if u, err := user.Current(); err == nil {
		meta.OSUser = u.Username
	}

	log.Info("collecting", "context", target.Context, "server", target.Server, "output", opts.Output)

	if err := c.collectIdentity(ctx, &meta); err != nil {
		out.Abort()
		return "", nil, err
	}
	if err := c.collectResources(ctx); err != nil {
		out.Abort()
		return "", nil, err
	}
	log.Info("resources collected", "objects", c.objs, "pods", len(c.pods))
	if err := c.writeContainerIndex(); err != nil {
		out.Abort()
		return "", nil, err
	}

	if opts.Logs {
		if err := c.collectLogs(ctx); err != nil {
			out.Abort()
			return "", nil, err
		}
	}

	// Nodes last: the collection pods must not show up in cluster/.
	if err := c.collectNodes(ctx); err != nil {
		out.Abort()
		return "", nil, err
	}

	meta.Footprint = c.footprint
	meta.Finished = time.Now().UTC()
	m, err := out.Close(meta)
	return opts.Output, m, err
}

// collectIdentity records the server version and which identity performed
// the collection. Failing to reach the API server at all is fatal.
func (c *collector) collectIdentity(ctx context.Context, meta *archive.Metadata) error {
	v, err := c.cs.Discovery().ServerVersion()
	if err != nil {
		return fmt.Errorf("contacting API server: %w", err)
	}
	meta.ServerVersion = v.GitVersion
	if err := c.writeJSON("cluster/version.json", v); err != nil {
		return err
	}

	ssr, err := c.cs.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		c.out.RecordError("whoami: %v", err)
		return nil
	}
	meta.KubeUser = ssr.Status.UserInfo.Username
	meta.KubeGroups = ssr.Status.UserInfo.Groups
	return nil
}

func (c *collector) collectResources(ctx context.Context) error {
	lists, err := c.cs.Discovery().ServerPreferredResources()
	if err != nil {
		if !discovery.IsGroupDiscoveryFailedError(err) {
			return fmt.Errorf("discovering API resources: %w", err)
		}
		// Typically an aggregated API whose backend is down. Keep going
		// with the groups that did answer.
		c.out.RecordError("discovery: %v", err)
	}
	if err := c.writeJSON("cluster/api-resources.json", lists); err != nil {
		return err
	}

	type job struct {
		gvr        schema.GroupVersionResource
		kind       string
		namespaced bool
	}
	var jobs []job
	for _, l := range lists {
		gv, err := schema.ParseGroupVersion(l.GroupVersion)
		if err != nil {
			continue
		}
		for _, r := range l.APIResources {
			if strings.Contains(r.Name, "/") || !slices.Contains(r.Verbs, "list") {
				continue
			}
			if skipResources[gv.WithResource(r.Name).GroupResource()] {
				continue
			}
			jobs = append(jobs, job{gv.WithResource(r.Name), r.Kind, r.Namespaced})
		}
	}

	sem := make(chan struct{}, c.opts.Concurrency)
	var wg sync.WaitGroup
	errc := make(chan error, 1)
	for _, j := range jobs {
		namespaces := []string{metav1.NamespaceAll}
		if j.namespaced && len(c.opts.Namespaces) > 0 {
			namespaces = c.opts.Namespaces
		}
		for _, ns := range namespaces {
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				if err := c.listAndWrite(ctx, j.gvr, j.kind, ns); err != nil {
					select {
					case errc <- err:
					default:
					}
				}
			}()
		}
	}
	wg.Wait()
	select {
	case err := <-errc:
		return err
	default:
		return ctx.Err()
	}
}

// listAndWrite lists one resource type and writes every object. API errors
// (forbidden, not found, ...) are recorded, not fatal; archive write errors
// are fatal.
func (c *collector) listAndWrite(ctx context.Context, gvr schema.GroupVersionResource, kind, ns string) error {
	ri := c.dyn.Resource(gvr).Namespace(ns)
	opts := metav1.ListOptions{Limit: 500}
	for {
		list, err := ri.List(ctx, opts)
		if err != nil {
			c.out.RecordError("list %s: %v", resourceDir(gvr), err)
			return nil
		}
		for i := range list.Items {
			obj := &list.Items[i]
			if obj.GetKind() == "" {
				obj.SetAPIVersion(gvr.GroupVersion().String())
				obj.SetKind(kind)
			}
			if err := c.writeObject(gvr, obj); err != nil {
				return err
			}
		}
		if opts.Continue = list.GetContinue(); opts.Continue == "" {
			return nil
		}
	}
}

func (c *collector) writeObject(gvr schema.GroupVersionResource, obj *unstructured.Unstructured) error {
	gr := gvr.GroupResource()
	if gr == (schema.GroupResource{Resource: "secrets"}) && !c.opts.IncludeSecrets {
		RedactSecret(obj)
	}
	if gr == (schema.GroupResource{Resource: "pods"}) {
		var pod corev1.Pod
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &pod); err == nil {
			c.mu.Lock()
			c.pods = append(c.pods, pod)
			c.mu.Unlock()
		}
	}

	data, err := yaml.Marshal(obj.Object)
	if err != nil {
		return err
	}
	ns := obj.GetNamespace()
	if ns == "" {
		ns = ClusterScopeDir
	}
	if err := c.out.WriteFile(path.Join("cluster", ns, resourceDir(gvr), obj.GetName()+".yaml"), data); err != nil {
		return err
	}
	c.mu.Lock()
	c.objs++
	c.mu.Unlock()
	return nil
}

func (c *collector) writeJSON(name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return c.out.WriteFile(name, data)
}

// resourceDir is "pods" for core resources and "deployments.apps" otherwise,
// matching kubectl's fully-qualified resource names.
func resourceDir(gvr schema.GroupVersionResource) string {
	if gvr.Group == "" {
		return gvr.Resource
	}
	return gvr.Resource + "." + gvr.Group
}

func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			return r
		}
		return '_'
	}, s)
}

// ContainerRef maps a container ID (as seen in node cgroups and traces) to
// its pod.
type ContainerRef struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	PodUID    string `json:"podUid"`
	Container string `json:"container"`
	Node      string `json:"node"`
	Image     string `json:"image"`
	ImageID   string `json:"imageId"`
}

// writeContainerIndex writes cluster/container-index.json: container ID →
// pod, for the current and previous instance of every container.
func (c *collector) writeContainerIndex() error {
	idx := map[string]ContainerRef{}
	for _, p := range c.pods {
		for _, st := range allStatuses(&p) {
			ref := ContainerRef{
				Namespace: p.Namespace, Pod: p.Name, PodUID: string(p.UID), Container: st.Name,
				Node: p.Spec.NodeName, Image: st.Image, ImageID: st.ImageID,
			}
			if id := stripRuntime(st.ContainerID); id != "" {
				idx[id] = ref
			}
			if t := st.LastTerminationState.Terminated; t != nil {
				if id := stripRuntime(t.ContainerID); id != "" {
					idx[id] = ref
				}
			}
		}
	}
	return c.writeJSON("cluster/container-index.json", idx)
}

// stripRuntime turns "containerd://abc" into "abc".
func stripRuntime(id string) string {
	if _, after, ok := strings.Cut(id, "://"); ok {
		return after
	}
	return id
}
