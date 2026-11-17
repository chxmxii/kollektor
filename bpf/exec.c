//go:build ignore

// exec.c emits one event per successful execve() on the node.
//
// It deliberately uses only BPF helpers (no kernel struct access), so it does
// not need vmlinux.h / CO-RE and builds with just linux + libbpf headers.
// It attaches as a raw tracepoint so no tracefs mount is required.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct exec_event {
	__u64 ktime_ns;
	__u64 cgroup_id;
	__u32 tgid; // userspace "PID"
	__u32 pid;  // kernel task id (userspace "TID")
	__u32 uid;
	__u8 comm[TASK_COMM_LEN];
};

// Force the type into BTF so bpf2go can generate a matching Go struct.
const struct exec_event *unused_exec_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

SEC("raw_tracepoint/sched_process_exec")
int handle_exec(void *ctx)
{
	struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	e->tgid = id >> 32;
	e->pid = (__u32)id;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->ktime_ns = bpf_ktime_get_ns();
	e->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
