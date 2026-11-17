// Package events defines the normalized event model that every probe emits
// and every sink consumes.
package events

import "time"

// Type identifies which probe produced an event.
type Type string

const (
	TypeExec Type = "exec"
)

// Event is a single observation from a BPF probe, optionally enriched with
// Kubernetes metadata.
type Event struct {
	Type     Type      `json:"type"`
	Time     time.Time `json:"time"`
	Node     string    `json:"node,omitempty"`
	PID      uint32    `json:"pid"`
	TID      uint32    `json:"tid"`
	UID      uint32    `json:"uid"`
	Comm     string    `json:"comm"`
	CgroupID uint64    `json:"cgroupId"`

	// Pod is nil when the process does not belong to a known pod
	// (host processes, or enrichment disabled).
	Pod *PodRef `json:"pod,omitempty"`
}

// PodRef identifies the pod/container a process runs in.
type PodRef struct {
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	UID         string `json:"uid"`
	Container   string `json:"container"`
	ContainerID string `json:"containerId"`
}
