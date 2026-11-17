package replay

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func obj(apiVersion, kind, ns, name string, extra map[string]any) *unstructured.Unstructured {
	meta := map[string]any{"name": name, "uid": "u-1", "resourceVersion": "7"}
	if ns != "" {
		meta["namespace"] = ns
	}
	o := map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": meta, "status": map[string]any{"x": int64(1)}}
	for k, v := range extra {
		o[k] = v
	}
	return &unstructured.Unstructured{Object: o}
}

func TestBuildPlanFiltersAndOrders(t *testing.T) {
	owned := obj("apps/v1", "ReplicaSet", "app", "web-123", nil)
	owned.SetOwnerReferences(nil)
	_ = unstructured.SetNestedSlice(owned.Object, []any{map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment", "name": "web", "uid": "x", "controller": true,
	}}, "metadata", "ownerReferences")

	objs := []*unstructured.Unstructured{
		obj("apps/v1", "Deployment", "app", "web", nil),
		obj("v1", "Service", "app", "web", map[string]any{"spec": map[string]any{"clusterIP": "10.0.0.5", "clusterIPs": []any{"10.0.0.5"}}}),
		obj("example.com/v1", "Widget", "app", "w", nil),
		obj("v1", "ConfigMap", "app", "cfg", nil),
		obj("apiextensions.k8s.io/v1", "CustomResourceDefinition", "", "widgets.example.com", nil),
		obj("v1", "Namespace", "", "app", nil),
		obj("v1", "Namespace", "", "kube-system", nil),
		obj("apps/v1", "Deployment", "kube-system", "coredns", nil),
		obj("v1", "Node", "", "n1", nil),
		obj("rbac.authorization.k8s.io/v1", "ClusterRole", "", "system:controller:foo", nil),
		obj("admissionregistration.k8s.io/v1", "ValidatingWebhookConfiguration", "", "wh", nil),
		obj("v1", "ConfigMap", "app", "kube-root-ca.crt", nil),
		owned,
	}

	p := BuildPlan(objs, PlanOptions{})
	var got []string
	for _, o := range p.Objects {
		got = append(got, o.GetKind()+"/"+o.GetName())
	}
	want := []string{
		"Namespace/app",
		"CustomResourceDefinition/widgets.example.com",
		"ConfigMap/cfg",
		"Service/web",
		"Deployment/web",
		"Widget/w",
	}
	if len(got) != len(want) {
		t.Fatalf("plan = %v\nwant %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("plan = %v\nwant %v", got, want)
		}
	}

	for _, o := range p.Objects {
		if o.GetUID() != "" || o.GetResourceVersion() != "" {
			t.Errorf("%s: uid/resourceVersion not stripped", o.GetName())
		}
		if _, ok := o.Object["status"]; ok {
			t.Errorf("%s: status not stripped", o.GetName())
		}
	}
	svc := p.Objects[3]
	if _, ok, _ := unstructured.NestedString(svc.Object, "spec", "clusterIP"); ok {
		t.Error("service clusterIP not stripped")
	}

	withWebhooks := BuildPlan(objs, PlanOptions{IncludeWebhooks: true})
	if last := withWebhooks.Objects[len(withWebhooks.Objects)-1]; last.GetKind() != "ValidatingWebhookConfiguration" {
		t.Errorf("webhooks should be applied last, got %s", last.GetKind())
	}
}
