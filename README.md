# kollektor

kollektor is a tool to gather real-time information and data about your kubernetes cluster using ebpf!

One binary. Point it at a cluster and it collects everything (API state,
logs, and host-level evidence from every node, including a live eBPF trace)
into a single compressed, hash-verified evidence archive. You can then
investigate that archive offline, or replay it to recreate the same setup on
another cluster.

```sh
kollektor collect --context prod -o case-042.tar.zst   # collect
kollektor inspect case-042.tar.zst                     # verify integrity + summary
kollektor extract case-042.tar.zst ./case-042          # verify, then unpack
kollektor replay  --kind case-042 case-042.tar.zst     # reproduce in a fresh kind cluster
```

## What gets collected

| Path in archive | Content |
|---|---|
| `manifest.json` | who/when/where (OS user, host, kube identity, context, server version, tool version), SHA-256 + size of every file, and every error hit during collection |
| `cluster/version.json`, `cluster/api-resources.json` | server version and full API discovery |
| `cluster/<namespace>/<resource>[.<group>]/<name>.yaml` | every object of every listable resource, CRDs and custom resources included, stored exactly as the API served it (`managedFields` kept, which shows who changed what). Cluster-scoped objects are under `_cluster/`. |
| `cluster/container-index.json` | container ID → namespace/pod/container/node/image digest. Use it to join node evidence (processes, traces) to pods |
| `logs/<namespace>/<pod>/<container>[.previous].log` | logs of every started container (with timestamps), plus the previous instance's log for restarted containers |
| `nodes/<node>/manifest.json` | the node's own manifest (hashes computed on the node; re-checked on arrival) |
| `nodes/<node>/processes.json` | every process: pid/ppid, uids, cmdline, exe path + SHA-256 (hashed via `/proc/<pid>/exe`, so it works for deleted binaries, flagged `exeDeleted`), cwd, start time, capabilities, seccomp, namespaces, `LD_PRELOAD`, container ID |
| `nodes/<node>/network/sockets.json` | TCP/UDP/raw sockets in **every** network namespace (host and each pod), with owning PIDs |
| `nodes/<node>/network/*`, `system/*` | routes, ARP, interfaces, conntrack; kernel version/cmdline, loaded modules, mounts, taint, BPF/kptr sysctls |
| `nodes/<node>/host/...` | OS identity, accounts, sudoers, `ld.so.preload`, cron, systemd units, sshd config + `authorized_keys`, shell histories, kubelet/containerd/CNI config, static pod manifests, kubeconfigs, auth/syslog/audit logs (large logs: last 64 MiB). `host/symlinks.json` records link targets |
| `nodes/<node>/trace/exec.ndjson` | eBPF capture of every `execve` during `--trace-duration`: kernel timestamp, pid/tid/uid, comm, cgroup, plus cmdline/exe/ppid/container ID read at event time |
| `nodes/<node>/collector.log` | the node collector's own log |

**Secrets** are redacted by default. Each value is replaced with `""`, and its
SHA-256 is recorded in the `kollektor.io/data-sha256` annotation, so you can
still compare secrets across objects and collections. The
`last-applied-configuration` annotation, which contains the plaintext values,
is removed. Use `--include-secrets` to store raw values.

On nodes, private keys (`*.key`), `/etc/shadow` and process environments are
skipped, and kubeconfig credentials (`client-key-data`, `token`, ...) are
replaced with SHA-256 hashes. `--include-secrets` collects them all.

**Gaps are documented, not hidden.** Forbidden resources, unreachable
aggregated APIs, and logs the kubelet has already rotated away are listed
under `errors` in the manifest, and `inspect` prints them.

### Node collection and footprint

After the API and logs are collected, kollektor creates a namespace
(`--node-namespace`, default `kollektor`) and one short-lived pod per node:
privileged, `hostPID`, node root mounted **read-only** at `/host`, scheduled
directly with `nodeName` (so cordoned/tainted nodes work too). By default it
**uploads its own binary** into a `busybox` pod through `exec`, so no
registry or published image is needed. Use `--image` for a kollektor image
instead (required when your workstation isn't linux on the node's CPU
architecture, or for air-gapped clusters; `--helper-image` swaps busybox).

The pods and namespace are deleted afterwards, even on Ctrl-C. Every change
kollektor makes to the cluster is listed with timestamps under
`metadata.footprint` in the manifest, for chain of custody. `--nodes none`
collects API state only; `--nodes a,b` limits to specific nodes;
`--trace-duration 0` skips eBPF.

eBPF tracing needs Linux ≥ 5.8 and real kernel privileges. In clusters where
"privileged" isn't real (e.g. kind on rootless podman/docker, gVisor), the
trace fails and the failure is recorded; everything else is still collected.

### Integrity

`manifest.json` is the last entry of the archive and lists the hash of every
other file. `inspect` and `extract` re-hash everything and fail if anything is
missing, altered or unlisted. The archive is written with mode `0400`.

> Next steps: store the archive's own SHA-256 in your case notes, and sign the
> manifest (planned).

## Replay

`replay` reads `cluster/` from the archive and applies it with server-side
apply, in dependency order: namespaces and CRDs (waiting until they are
established), then RBAC and config, then workloads, custom resources, and
finally admission webhooks.

It removes server-populated and cluster-specific fields (UIDs,
resourceVersion, status, managedFields, owner references, cluster IPs, node
names, PV bindings, Job selectors). It skips:

- objects created by controllers (Pods of a ReplicaSet, ReplicaSets of a Deployment, ...), since their owners recreate them
- control-plane-managed kinds: Events, Nodes, Leases, Endpoints/EndpointSlices, APIServices, FlowSchemas, ...
- system namespaces and built-in RBAC/priority classes (`--include-system` to keep them)
- admission webhooks and policies (`--include-webhooks`), because a webhook whose backend isn't running would block the replay

```sh
kollektor replay --context staging case.tar.zst      # into an existing cluster
kollektor replay --kind repro case.tar.zst           # create kind cluster "repro" (kubeconfig written next to the archive)
kollektor replay --dry-run --context staging case.tar.zst
kollektor replay --out ./manifests case.tar.zst      # just write ordered YAML for kubectl apply
```

Redacted secrets are replayed with empty values. Workloads that need them
will start but may misbehave until you fill them in.

## Roadmap

- More eBPF probes: TCP connect/accept, DNS, file opens under sensitive paths,
  privilege changes, module loads. Read argv and parent in-kernel (CO-RE) so
  very short-lived processes are fully attributed.
- Container runtime state (images, mounts, overlay diffs of running containers).
- Signed manifests, `inspect` queries (timeline, RBAC "who can").

## Development

```
cmd/kollektor/         CLI (collect, inspect, extract, replay)
internal/archive/      tar.zst writer/reader, manifest, verification
internal/collect/      API discovery + listing, secret redaction, logs, node pods
internal/node/         node-side collector (`kollektor node`, runs in the pod)
internal/replay/       plan (filter/sanitize/order) and apply
internal/k8s/          kubeconfig loading
internal/probes/       eBPF probes with generated bpf2go bindings
bpf/                   eBPF C sources
```

```sh
make build test lint
make generate   # after editing bpf/*.c (uses clang, or a builder container if missing)
```
