package replay

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/restmapper"
	"sigs.k8s.io/yaml"

	"github.com/chxmxii/kollektor/internal/k8s"
)

const fieldManager = "kollektor"

type Options struct {
	Archive    string
	Kubeconfig string
	Context    string
	Kind       string // create a kind cluster with this name and replay into it
	OutDir     string // write manifests instead of applying
	DryRun     bool   // server-side dry run
	Plan       PlanOptions
}

// Result summarizes a replay.
type Result struct {
	Plan    *Plan
	Applied int
	Failed  []string
	Context string
}

func Run(ctx context.Context, opts Options, log *slog.Logger) (*Result, error) {
	objs, err := Load(opts.Archive)
	if err != nil {
		return nil, fmt.Errorf("reading archive: %w", err)
	}
	plan := BuildPlan(objs, opts.Plan)
	res := &Result{Plan: plan}
	log.Info("replay plan", "objects", len(plan.Objects), "skipped", total(plan.Skipped))

	if opts.OutDir != "" {
		return res, WriteManifests(plan, opts.OutDir)
	}

	if opts.Kind != "" {
		if opts.Kubeconfig != "" || opts.Context != "" {
			return nil, fmt.Errorf("--kind cannot be combined with --kubeconfig/--context")
		}
		kc, err := createKindCluster(ctx, opts.Kind, filepath.Dir(opts.Archive))
		if err != nil {
			return nil, err
		}
		opts.Kubeconfig = kc
		log.Info("kind cluster ready", "name", opts.Kind, "kubeconfig", kc)
	}

	target, err := k8s.LoadTarget(opts.Kubeconfig, opts.Context)
	if err != nil {
		return nil, err
	}
	res.Context = target.Context
	dyn, err := dynamic.NewForConfig(target.Config)
	if err != nil {
		return nil, err
	}
	disc, err := discovery.NewDiscoveryClientForConfig(target.Config)
	if err != nil {
		return nil, err
	}
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(disc))

	applyOpts := metav1.ApplyOptions{FieldManager: fieldManager, Force: true}
	if opts.DryRun {
		applyOpts.DryRun = []string{metav1.DryRunAll}
	}

	log.Info("applying", "context", target.Context, "dryRun", opts.DryRun)
	var crds []string
	for i, o := range plan.Objects {
		if i > 0 && PhaseOf(plan.Objects[i-1]) == PhaseFoundation && PhaseOf(o) != PhaseFoundation {
			if !opts.DryRun {
				waitForCRDs(ctx, dyn, crds, log)
			}
			mapper.Reset()
		}
		if o.GetKind() == "CustomResourceDefinition" {
			crds = append(crds, o.GetName())
		}

		if err := apply(ctx, dyn, mapper, o, applyOpts); err != nil {
			res.Failed = append(res.Failed, fmt.Sprintf("%s: %v", describe(o), err))
			log.Warn("apply failed", "object", describe(o), "err", err)
			continue
		}
		res.Applied++
	}
	return res, nil
}

func apply(ctx context.Context, dyn dynamic.Interface, mapper meta.RESTMapper, o *unstructured.Unstructured, opts metav1.ApplyOptions) error {
	gvk := o.GroupVersionKind()
	m, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return err
	}
	var ri dynamic.ResourceInterface = dyn.Resource(m.Resource)
	if m.Scope.Name() == meta.RESTScopeNameNamespace {
		ri = dyn.Resource(m.Resource).Namespace(o.GetNamespace())
	}
	_, err = ri.Apply(ctx, o.GetName(), o, opts)
	return err
}

var crdGVR = schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}

func waitForCRDs(ctx context.Context, dyn dynamic.Interface, names []string, log *slog.Logger) {
	for _, name := range names {
		err := wait.PollUntilContextTimeout(ctx, time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
			crd, err := dyn.Resource(crdGVR).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return false, nil
			}
			conds, _, _ := unstructured.NestedSlice(crd.Object, "status", "conditions")
			for _, c := range conds {
				cm, _ := c.(map[string]any)
				if cm["type"] == "Established" && cm["status"] == "True" {
					return true, nil
				}
			}
			return false, nil
		})
		if err != nil {
			log.Warn("CRD not established", "crd", name, "err", err)
		}
	}
}

// WriteManifests writes one multi-document YAML file per phase so they can be
// applied with `kubectl apply -f` in order.
func WriteManifests(plan *Plan, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	files := map[Phase]*os.File{}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	for _, o := range plan.Objects {
		ph := PhaseOf(o)
		f, ok := files[ph]
		if !ok {
			var err error
			f, err = os.Create(filepath.Join(dir, fmt.Sprintf("%02d-%s.yaml", int(ph), ph)))
			if err != nil {
				return err
			}
			files[ph] = f
		}
		data, err := yaml.Marshal(o.Object)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(f, "---\n%s", data); err != nil {
			return err
		}
	}
	return nil
}

// createKindCluster creates a kind cluster with its kubeconfig written next to
// the archive, so the user's own kubeconfig is not modified.
func createKindCluster(ctx context.Context, name, dir string) (string, error) {
	kc, err := filepath.Abs(filepath.Join(dir, "kubeconfig-"+name))
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, "kind", "create", "cluster", "--name", name, "--kubeconfig", kc, "--wait", "120s")
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("kind create cluster: %w", err)
	}
	return kc, nil
}

func describe(o *unstructured.Unstructured) string {
	gk := o.GroupVersionKind().GroupKind().String()
	if ns := o.GetNamespace(); ns != "" {
		return fmt.Sprintf("%s %s/%s", gk, ns, o.GetName())
	}
	return fmt.Sprintf("%s %s", gk, o.GetName())
}

func total(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}
