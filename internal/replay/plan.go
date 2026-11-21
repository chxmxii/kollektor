// Package replay recreates a collected cluster's workloads and configuration
// on another cluster.
package replay

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/yaml"

	"github.com/chxmxii/kollektor/internal/archive"
	"github.com/chxmxii/kollektor/internal/collect"
)

// Phase groups objects that must exist before the next group is applied.
type Phase int

const (
	// PhaseFoundation: namespaces and CRDs (CRDs must be established before
	// their custom resources can be applied).
	PhaseFoundation Phase = iota
	// PhaseResources: everything else.
	PhaseResources
	// PhaseAdmission: webhooks last, so they can't block the replay itself.
	PhaseAdmission
)

func (p Phase) String() string {
	return [...]string{"foundation", "resources", "admission"}[p]
}

type PlanOptions struct {
	IncludeSystem   bool // replay objects in kube-system & co, and built-in RBAC
	IncludeWebhooks bool // replay admission webhook configurations
}

// Plan is the ordered list of sanitized objects to apply, plus what was
// skipped and why.
type Plan struct {
	Objects  []*unstructured.Unstructured
	Skipped  map[string]int // reason → count
	Redacted int            // secrets whose values were redacted at collection
}

var systemNamespaces = map[string]bool{
	"kube-system": true, "kube-public": true, "kube-node-lease": true, "default": true,
	"local-path-storage": true, // kind's provisioner
}

// Owned by the control plane or bound to the source cluster's nodes,
// network or storage: never replayed.
var neverReplay = map[schema.GroupKind]bool{
	{Kind: "Event"}:                                                             true,
	{Group: "events.k8s.io", Kind: "Event"}:                                     true,
	{Kind: "Node"}:                                                              true,
	{Kind: "Endpoints"}:                                                         true,
	{Kind: "ComponentStatus"}:                                                   true,
	{Kind: "PersistentVolume"}:                                                  true,
	{Kind: "Binding"}:                                                           true,
	{Group: "discovery.k8s.io", Kind: "EndpointSlice"}:                          true,
	{Group: "coordination.k8s.io", Kind: "Lease"}:                               true,
	{Group: "apps", Kind: "ControllerRevision"}:                                 true,
	{Group: "certificates.k8s.io", Kind: "CertificateSigningRequest"}:           true,
	{Group: "apiregistration.k8s.io", Kind: "APIService"}:                       true,
	{Group: "flowcontrol.apiserver.k8s.io", Kind: "FlowSchema"}:                 true,
	{Group: "flowcontrol.apiserver.k8s.io", Kind: "PriorityLevelConfiguration"}: true,
	{Group: "storage.k8s.io", Kind: "VolumeAttachment"}:                         true,
	{Group: "storage.k8s.io", Kind: "CSINode"}:                                  true,
	{Group: "storage.k8s.io", Kind: "CSIStorageCapacity"}:                       true,
	{Group: "networking.k8s.io", Kind: "IPAddress"}:                             true,
	{Group: "networking.k8s.io", Kind: "ServiceCIDR"}:                           true,
	{Group: "metrics.k8s.io", Kind: "PodMetrics"}:                               true,
	{Group: "metrics.k8s.io", Kind: "NodeMetrics"}:                              true,
}

var webhookKinds = map[schema.GroupKind]bool{
	{Group: "admissionregistration.k8s.io", Kind: "ValidatingWebhookConfiguration"}:   true,
	{Group: "admissionregistration.k8s.io", Kind: "MutatingWebhookConfiguration"}:     true,
	{Group: "admissionregistration.k8s.io", Kind: "ValidatingAdmissionPolicy"}:        true,
	{Group: "admissionregistration.k8s.io", Kind: "ValidatingAdmissionPolicyBinding"}: true,
	{Group: "admissionregistration.k8s.io", Kind: "MutatingAdmissionPolicy"}:          true,
	{Group: "admissionregistration.k8s.io", Kind: "MutatingAdmissionPolicyBinding"}:   true,
}

// kindOrder sorts objects inside PhaseResources so references resolve:
// identities and config before the workloads that mount them.
var kindOrder = map[string]int{
	"PriorityClass": 1, "StorageClass": 2, "IngressClass": 3, "RuntimeClass": 3,
	"ClusterRole": 4, "ClusterRoleBinding": 5,
	"ServiceAccount": 6, "Role": 7, "RoleBinding": 8,
	"ResourceQuota": 9, "LimitRange": 9,
	"ConfigMap": 10, "Secret": 10,
	"PersistentVolumeClaim": 11,
	"Service":               12, "NetworkPolicy": 12,
	"Deployment": 20, "StatefulSet": 20, "DaemonSet": 20, "ReplicaSet": 20,
	"Job": 20, "CronJob": 20, "Pod": 20,
	"HorizontalPodAutoscaler": 21, "PodDisruptionBudget": 21, "Ingress": 21,
}

// Load reads every object under cluster/ in the archive.
func Load(archivePath string) ([]*unstructured.Unstructured, error) {
	var objs []*unstructured.Unstructured
	err := archive.Walk(archivePath, func(name string, _ int64, r io.Reader) error {
		if !strings.HasPrefix(name, "cluster/") || !strings.HasSuffix(name, ".yaml") {
			return nil
		}
		data, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		u := &unstructured.Unstructured{}
		if err := yaml.Unmarshal(data, &u.Object); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		objs = append(objs, u)
		return nil
	})
	return objs, err
}

// BuildPlan filters, sanitizes and orders collected objects for replay.
func BuildPlan(objs []*unstructured.Unstructured, opts PlanOptions) *Plan {
	p := &Plan{Skipped: map[string]int{}}
	for _, o := range objs {
		if reason := skipReason(o, opts); reason != "" {
			p.Skipped[reason]++
			continue
		}
		o = o.DeepCopy()
		Sanitize(o)
		if o.GetAnnotations()[collect.AnnotationRedacted] == "true" {
			p.Redacted++
		}
		p.Objects = append(p.Objects, o)
	}
	slices.SortStableFunc(p.Objects, func(a, b *unstructured.Unstructured) int {
		return cmp.Or(
			cmp.Compare(PhaseOf(a), PhaseOf(b)),
			cmp.Compare(rank(a), rank(b)),
			cmp.Compare(a.GetNamespace(), b.GetNamespace()),
			cmp.Compare(a.GetKind(), b.GetKind()),
			cmp.Compare(a.GetName(), b.GetName()),
		)
	})
	return p
}

func PhaseOf(o *unstructured.Unstructured) Phase {
	gk := o.GroupVersionKind().GroupKind()
	switch {
	case gk == schema.GroupKind{Kind: "Namespace"},
		gk == schema.GroupKind{Group: "apiextensions.k8s.io", Kind: "CustomResourceDefinition"}:
		return PhaseFoundation
	case webhookKinds[gk]:
		return PhaseAdmission
	}
	return PhaseResources
}

func rank(o *unstructured.Unstructured) int {
	if o.GetKind() == "Namespace" {
		return 0
	}
	if r, ok := kindOrder[o.GetKind()]; ok {
		return r
	}
	return 50 // custom resources and anything unknown
}

func skipReason(o *unstructured.Unstructured, opts PlanOptions) string {
	gk := o.GroupVersionKind().GroupKind()
	switch {
	case neverReplay[gk]:
		return "cluster-managed kind (" + gk.Kind + ")"
	case webhookKinds[gk] && !opts.IncludeWebhooks:
		return "admission webhook/policy (use --include-webhooks)"
	case hasControllerOwner(o):
		return "created by a controller (recreated by its owner)"
	}

	if !opts.IncludeSystem {
		if gk.Kind == "Namespace" && systemNamespaces[o.GetName()] {
			return "system namespace (use --include-system)"
		}
		if ns := o.GetNamespace(); ns != "" && ns != "default" && systemNamespaces[ns] {
			return "system namespace (use --include-system)"
		}
		if isBuiltin(o) {
			return "built-in object (use --include-system)"
		}
	}

	switch {
	case gk.Kind == "ConfigMap" && o.GetName() == "kube-root-ca.crt":
		return "auto-published CA bundle"
	case gk.Kind == "Secret" && strings.HasSuffix(stringField(o, "type"), "service-account-token"):
		return "service account token"
	case gk.Kind == "Service" && o.GetNamespace() == "default" && o.GetName() == "kubernetes":
		return "built-in object (use --include-system)"
	}
	return ""
}

func isBuiltin(o *unstructured.Unstructured) bool {
	name := o.GetName()
	if o.GetLabels()["kubernetes.io/bootstrapping"] == "rbac-defaults" {
		return true
	}
	if strings.HasPrefix(name, "system:") || strings.HasPrefix(name, "kubeadm:") {
		return true
	}
	switch o.GetKind() {
	case "PriorityClass":
		return strings.HasPrefix(name, "system-")
	case "ClusterTrustBundle":
		// kubernetes.io:* bundles are published by the control plane.
		return strings.HasPrefix(name, "kubernetes.io:")
	case "ClusterRoleBinding":
		return bindsOnlySystemSubjects(o)
	}
	return false
}

// bindsOnlySystemSubjects reports whether every subject of a binding is a
// service account in a system namespace (CNI, CSI, kube-proxy, ...). Those
// components are not replayed, so neither are their grants.
func bindsOnlySystemSubjects(o *unstructured.Unstructured) bool {
	subjects, _, _ := unstructured.NestedSlice(o.Object, "subjects")
	if len(subjects) == 0 {
		return false
	}
	for _, s := range subjects {
		m, _ := s.(map[string]any)
		ns, _ := m["namespace"].(string)
		if m["kind"] != "ServiceAccount" || !systemNamespaces[ns] || ns == "default" {
			return false
		}
	}
	return true
}

func hasControllerOwner(o *unstructured.Unstructured) bool {
	for _, ref := range o.GetOwnerReferences() {
		if ref.Controller != nil && *ref.Controller {
			return true
		}
	}
	return false
}

func stringField(o *unstructured.Unstructured, fields ...string) string {
	s, _, _ := unstructured.NestedString(o.Object, fields...)
	return s
}
