package collect

import (
	"encoding/json"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestRedactSecret(t *testing.T) {
	s := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name": "db",
			"annotations": map[string]any{
				lastAppliedConfig: `{"data":{"password":"aHVudGVyMg=="}}`,
			},
		},
		"data": map[string]any{"password": "aHVudGVyMg=="}, // "hunter2"
	}}
	RedactSecret(s)

	if v, _, _ := unstructured.NestedString(s.Object, "data", "password"); v != "" {
		t.Errorf("password not redacted: %q", v)
	}
	ann := s.GetAnnotations()
	if _, ok := ann[lastAppliedConfig]; ok {
		t.Error("last-applied-configuration still present (leaks secret values)")
	}
	if ann[AnnotationRedacted] != "true" {
		t.Error("missing redacted marker")
	}
	var hashes map[string]string
	if err := json.Unmarshal([]byte(ann[AnnotationDataSHA256]), &hashes); err != nil {
		t.Fatal(err)
	}
	// sha256("hunter2")
	if want := "f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7"; hashes["password"] != want {
		t.Errorf("hash = %s, want %s", hashes["password"], want)
	}
}
