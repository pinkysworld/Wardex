# Linux kernel telemetry

This document describes what Wardex's Linux collector actually does today,
replacing an earlier description that called it "eBPF" when it was, in
fact, `/proc`/`/sys` polling.

## What runs today

Linux telemetry is split across two collectors that run side by side:

1. **The pre-existing periodic collector** (`src/collector_linux.rs`) —
   reads `/proc` and `/sys` on a timer for process snapshots, SUID/SGID
   scans, sudo config checks, socket tables, DNS config, and container
   detection. This has not changed.
2. **Real, kernel-driven event backends** (`src/kernel_linux/`, Linux-only,
   new) — the kernel pushes events to us as they happen, instead of us
   polling for them:
   - **Process lifecycle** (`netlink_proc.rs`): the `CN_PROC` netlink
     process connector delivers fork/exec/exit/uid-change events the
     instant the kernel emits them. Each event is enriched from
     `/proc/<pid>` at receipt time (cmdline, exe, ppid, uid, cgroup /
     container id). **Requires `CAP_NET_ADMIN`.**
   - **File activity** (`fanotify_backend.rs`): `fanotify(7)` in mark-mount
     mode, watching `FAN_CLOSE_WRITE`, `FAN_MODIFY`, and `FAN_OPEN_EXEC`.
     **Requires `CAP_SYS_ADMIN`.**
   - **File activity fallback** (`inotify_backend.rs`): `inotify(7)` on the
     configured watch paths, used automatically when fanotify can't be
     opened. Needs no special privilege beyond normal file read access,
     and additionally covers create/delete/rename (see the gap below).
   - **Process lifecycle fallback**: the existing `/proc`-polling collector
     keeps running regardless, so process visibility never disappears —
     it just loses real-time granularity — when `CAP_NET_ADMIN` isn't
     available.

Both new backends feed the same normalized model in `src/kernel_events.rs`
(`KernelEvent` / `KernelEventKind`), tagged with an accurate `EventSource`:
`NetlinkProcConnector`, `Fanotify`, or `Inotify`. The pre-existing
`EbpfLinux` source variant is *reserved* for a real eBPF backend and is
never produced by any collector today — see below.

## Backend selection & fallback order

At startup (`src/kernel_linux/capability.rs::detect_capability`), Wardex
probes the running process's effective capabilities (parsing `CapEff` from
`/proc/self/status`) and picks:

| Domain  | 1st choice              | Needs           | Fallback   | Needs                  | Last resort |
|---------|--------------------------|-----------------|------------|------------------------|-------------|
| Process | `CN_PROC` netlink connector | `CAP_NET_ADMIN` | —          | —                      | `/proc` polling |
| File    | `fanotify` (mark-mount)  | `CAP_SYS_ADMIN` + kernel fanotify support | `inotify` | ordinary file read access | `/proc`/directory snapshotting |

The choice and its reason are recorded in a
`KernelTelemetryCapability` value, surfaced by:

- `wardex doctor` (both the human-readable report and `--json`, under the
  `kernel_telemetry` report and the `"Kernel telemetry (Linux)"` check row).
- `collector_linux::LinuxCapabilities::kernel_telemetry` (`Option`, Linux
  builds only) alongside the pre-existing `has_ebpf` field, which is kept
  for backward compatibility but has always meant "kernel new enough for
  eBPF", never "eBPF telemetry is active."

If both domains fall back to polling, this is logged clearly at startup
(`kernel_linux: no kernel-pushed event source is active; ...`) rather than
silently degrading.

## Known gap: fanotify create/delete/rename

`FAN_REPORT_FID` / `FAN_REPORT_DFID_NAME` (Linux 5.1+) would let fanotify
report create/delete/rename events directly. They are not exposed by our
safe wrapper (`nix` 0.31's `fanotify::InitFlags`) at the time of writing,
so the fanotify backend only covers open/write/exec. Create/delete/rename
coverage instead comes from the `inotify` fallback backend on the
configured watch paths. This is a real, documented limitation, not
something papered over — a future `nix` release exposing those flags can
close it without changing `fanotify_backend`'s external shape.

## eBPF: planned, not implemented

A cargo feature `ebpf` exists (off by default) purely to reserve the seam:
`KernelBackendKind::Ebpf` and `EventSource::EbpfLinux` are real enum
variants, but nothing ever selects or produces them.

Why it isn't implemented: a real eBPF backend (evaluated via `aya`, the
pure-Rust userspace loader) needs the *BPF object itself* compiled, which
in practice means a nightly toolchain and `bpf-linker`. This repository
pins Rust `1.95` stable for its whole build and release pipeline
(`Cargo.toml`'s `rust-version`, and the CI matrix in
`.github/workflows/ci.yml`), so adding a nightly-only compilation step
would break the default build for every contributor and the release
pipeline. Rather than force that tradeoff in, or ship a fake/partial eBPF
path, this work stops at the trait/backend seam described above so a
follow-up change (e.g. shipping a prebuilt `.o`/`.bpf.o` object, or adding
a clearly-optional nightly build lane) can land eBPF without another
public API break.

## Configuration

No new config keys were required: the file backends reuse the existing
`monitor.watch_paths` configuration already used by the FIM/file-activity
pipeline. If `watch_paths` is empty, the fanotify backend marks `/`
(the whole root mount) rather than nothing.

## Testing

- `src/kernel_linux/netlink_proc.rs` and `src/kernel_linux/fanotify_backend.rs`
  hand-decode the kernel wire formats (`nlmsghdr`/`cn_msg`/`proc_event` and
  `fanotify_event_metadata` respectively) on plain byte slices, and are
  unit-tested with byte fixtures — no privileges or live sockets needed.
- `src/kernel_linux/capability.rs` is unit-tested against the live host's
  actual `/proc/self/status` (assertions are structural: "whichever
  backend was chosen matches the capability that justifies it", not a
  fixed outcome, since CI runners vary in what they grant).
- `tests/kernel_linux_cn_proc_live.rs` is a live integration test that
  opens a real `CN_PROC` netlink socket, execs a child process, and
  asserts the resulting `Exec`/`Exit` events are observed. It requires
  `CAP_NET_ADMIN`; when that capability isn't held (checked the same way
  the runtime capability probe checks it) the test prints why and returns
  early rather than failing — a runtime skip on a genuinely missing
  privilege, not a hidden failure.
