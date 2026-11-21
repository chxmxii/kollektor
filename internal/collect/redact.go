package collect

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	AnnotationRedacted   = "kollektor.io/redacted"
	AnnotationDataSHA256 = "kollektor.io/data-sha256"
	lastAppliedConfig    = "kubectl.kubernetes.io/last-applied-configuration"
)

// RedactSecret replaces every value in a Secret's data with an empty string
// and records the SHA-256 of the decoded value in an annotation. Investigators
// can still tell which secrets share a value or changed between collections,
// and the object stays valid for replay.
func RedactSecret(obj *unstructured.Unstructured) {
	data, _, _ := unstructured.NestedMap(obj.Object, "data")
	hashes := make(map[string]string, len(data)+1)

	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s, _ := data[k].(string)
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			raw = []byte(s)
		}
		hashes[k] = sha256Hex(raw)
		data[k] = ""
	}
	if len(data) > 0 {
		_ = unstructured.SetNestedMap(obj.Object, data, "data")
	}

	ann := obj.GetAnnotations()
	if ann == nil {
		ann = map[string]string{}
	}
	// kubectl apply stores the full object, including secret values, here.
	if v, ok := ann[lastAppliedConfig]; ok {
		hashes["<"+lastAppliedConfig+">"] = sha256Hex([]byte(v))
		delete(ann, lastAppliedConfig)
	}
	enc, _ := json.Marshal(hashes)
	ann[AnnotationRedacted] = "true"
	ann[AnnotationDataSHA256] = string(enc)
	obj.SetAnnotations(ann)
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
