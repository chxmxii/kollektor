// Package events defines the event model emitted by eBPF probes.
package events

import "time"

// Type identifies which probe produced an event.
type Type string

const (
	TypeExec Type = "exec"
)

// Event is a single observation from an eBPF probe. Kernel fields are always
// set; the userspace fields (PPID, Cmdline, Exe, ContainerID) are read from
// /proc when the event arrives and are empty if the process already exited
// (ProcGone).
type Event struct {
	Type     Type      `json:"type"`
	Time     time.Time `json:"time"`
	PID      uint32    `json:"pid"`
	TID      uint32    `json:"tid"`
	UID      uint32    `json:"uid"`
	Comm     string    `json:"comm"`
	CgroupID uint64    `json:"cgroupId"`

	PPID        int      `json:"ppid,omitempty"`
	Cmdline     []string `json:"cmdline,omitempty"`
	Exe         string   `json:"exe,omitempty"`
	ContainerID string   `json:"containerId,omitempty"`
	ProcGone    bool     `json:"procGone,omitempty"`
}
