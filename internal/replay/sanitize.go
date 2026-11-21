package replay

import (
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Annotations written by controllers that describe source-cluster state.
var droppedAnnotationPrefixes = []string{
	"deployment.kubernetes.io/",
	"pv.kubernetes.io/",
	"volume.kubernetes.io/",
	"volume.beta.kubernetes.io/",
	"control-plane.alpha.kubernetes.io/",
}

// Labels the Job controller adds; the API server rejects them on create
// unless they match the new Job's UID.
var jobControllerLabels = []string{"controller-uid", "batch.kubernetes.io/controller-uid"}

// Sanitize strips server-populated and cluster-specific fields so the object
// can be applied to a different cluster.
func Sanitize(o *unstructured.Unstructured) {
	for _, f := range []string{
		"uid", "resourceVersion", "generation", "creationTimestamp",
		"deletionTimestamp", "deletionGracePeriodSeconds", "managedFields",
		"selfLink", "ownerReferences", "finalizers",
	} {
		unstructured.RemoveNestedField(o.Object, "metadata", f)
	}
	unstructured.RemoveNestedField(o.Object, "status")

	if ann := o.GetAnnotations(); ann != nil {
		for k := range ann {
			for _, p := range droppedAnnotationPrefixes {
				if strings.HasPrefix(k, p) {
					delete(ann, k)
				}
			}
		}
		if len(ann) == 0 {
			ann = nil
		}
		o.SetAnnotations(ann)
	}

	switch o.GroupVersionKind().GroupKind().String() {
	case "Service":
		// Cluster IPs come from the source cluster's service CIDR.
		if ip, _, _ := unstructured.NestedString(o.Object, "spec", "clusterIP"); ip != "None" {
			unstructured.RemoveNestedField(o.Object, "spec", "clusterIP")
			unstructured.RemoveNestedField(o.Object, "spec", "clusterIPs")
		}
		unstructured.RemoveNestedField(o.Object, "spec", "healthCheckNodePort")
	case "PersistentVolumeClaim":
		unstructured.RemoveNestedField(o.Object, "spec", "volumeName")
	case "Pod":
		unstructured.RemoveNestedField(o.Object, "spec", "nodeName")
	case "ServiceAccount":
		unstructured.RemoveNestedField(o.Object, "secrets")
	case "Job.batch":
		unstructured.RemoveNestedField(o.Object, "spec", "selector")
		for _, l := range jobControllerLabels {
			unstructured.RemoveNestedField(o.Object, "metadata", "labels", l)
			unstructured.RemoveNestedField(o.Object, "spec", "template", "metadata", "labels", l)
		}
	}
}
