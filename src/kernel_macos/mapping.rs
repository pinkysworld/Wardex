//! Pure, platform-independent mapping from Endpoint Security Framework
//! (ESF)-extracted field structs to the normalized [`KernelEventKind`].
//!
//! Mirrors `kernel_windows::mapping`: every function here takes plain data
//! (no `endpoint-sec` types, no macOS API calls) so the mapping logic is
//! unit-tested on every CI host, including Linux, independent of whether
//! `es_consumer.rs` (`#[cfg(all(target_os = "macos", feature = "macos-es"))]`)
//! can be built there at all.

use crate::kernel_events::KernelEventKind;

/// A decoded `ES_EVENT_TYPE_NOTIFY_EXEC` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub exe: String,
    pub args: Vec<String>,
    pub cwd: String,
}

/// A decoded `ES_EVENT_TYPE_NOTIFY_EXIT` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EsExitEvent {
    pub pid: u32,
    pub exit_code: i32,
}

/// File operation kind, decoded from an ESF event type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EsFileOp {
    Create,
    Write,
    Delete,
    Rename,
}

/// A decoded ESF file-activity event (`NOTIFY_CREATE`, `NOTIFY_WRITE`,
/// `NOTIFY_UNLINK`, or `NOTIFY_RENAME`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsFileEvent {
    pub pid: u32,
    pub path: String,
    /// Populated only for `Rename` (the pre-rename path); `path` holds the
    /// post-rename path in that case.
    pub old_path: Option<String>,
    pub op: EsFileOp,
}

pub fn map_exec_event(ev: EsExecEvent) -> KernelEventKind {
    KernelEventKind::ProcessExec {
        pid: ev.pid,
        ppid: ev.ppid,
        uid: ev.uid,
        exe: ev.exe,
        args: ev.args,
        cwd: ev.cwd,
        container_id: None,
    }
}

pub fn map_exit_event(ev: EsExitEvent) -> KernelEventKind {
    KernelEventKind::ProcessExit {
        pid: ev.pid,
        exit_code: ev.exit_code,
    }
}

pub fn map_file_event(ev: EsFileEvent) -> KernelEventKind {
    match ev.op {
        EsFileOp::Create => KernelEventKind::FileOpen {
            pid: ev.pid,
            path: ev.path,
            flags: 0,
        },
        EsFileOp::Write => KernelEventKind::FileWrite {
            pid: ev.pid,
            path: ev.path,
            // ESF's NOTIFY_WRITE/NOTIFY_CLOSE events report *that* a file
            // was modified, not a byte count the way `fanotify`/ETW can;
            // callers that need exact sizes must `stat(2)` the path
            // themselves.
            bytes_written: 0,
        },
        EsFileOp::Delete => KernelEventKind::FileDelete {
            pid: ev.pid,
            path: ev.path,
        },
        EsFileOp::Rename => KernelEventKind::FileRename {
            pid: ev.pid,
            old_path: ev.old_path.unwrap_or_default(),
            new_path: ev.path,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_event_maps_all_fields() {
        let kind = map_exec_event(EsExecEvent {
            pid: 100,
            ppid: 1,
            uid: 501,
            exe: "/usr/bin/curl".into(),
            args: vec!["curl".into(), "-s".into(), "http://example.com".into()],
            cwd: "/Users/a".into(),
        });
        match kind {
            KernelEventKind::ProcessExec {
                pid,
                ppid,
                uid,
                exe,
                args,
                cwd,
                container_id,
            } => {
                assert_eq!(pid, 100);
                assert_eq!(ppid, 1);
                assert_eq!(uid, 501);
                assert_eq!(exe, "/usr/bin/curl");
                assert_eq!(args.len(), 3);
                assert_eq!(cwd, "/Users/a");
                assert!(container_id.is_none());
            }
            other => panic!("expected ProcessExec, got {other:?}"),
        }
    }

    #[test]
    fn exit_event_maps() {
        let kind = map_exit_event(EsExitEvent {
            pid: 100,
            exit_code: 1,
        });
        assert!(matches!(
            kind,
            KernelEventKind::ProcessExit {
                pid: 100,
                exit_code: 1
            }
        ));
    }

    #[test]
    fn file_create_maps_to_open() {
        let kind = map_file_event(EsFileEvent {
            pid: 1,
            path: "/tmp/x".into(),
            old_path: None,
            op: EsFileOp::Create,
        });
        assert!(matches!(kind, KernelEventKind::FileOpen { pid: 1, .. }));
    }

    #[test]
    fn file_delete_maps() {
        let kind = map_file_event(EsFileEvent {
            pid: 1,
            path: "/tmp/x".into(),
            old_path: None,
            op: EsFileOp::Delete,
        });
        assert!(matches!(kind, KernelEventKind::FileDelete { pid: 1, .. }));
    }

    #[test]
    fn file_rename_carries_both_paths() {
        let kind = map_file_event(EsFileEvent {
            pid: 1,
            path: "/tmp/new".into(),
            old_path: Some("/tmp/old".into()),
            op: EsFileOp::Rename,
        });
        match kind {
            KernelEventKind::FileRename {
                old_path, new_path, ..
            } => {
                assert_eq!(old_path, "/tmp/old");
                assert_eq!(new_path, "/tmp/new");
            }
            other => panic!("expected FileRename, got {other:?}"),
        }
    }

    #[test]
    fn suggest_mitre_runs_on_mapped_exec() {
        let kind = map_exec_event(EsExecEvent {
            pid: 1,
            ppid: 0,
            uid: 0,
            exe: "/bin/bash".into(),
            args: vec!["bash".into(), "-c".into(), "base64 -d".into()],
            cwd: "/".into(),
        });
        let mitre = crate::kernel_events::suggest_mitre(&kind);
        assert!(mitre.iter().any(|t| t.technique_id == "T1059"));
    }
}
