//! Best-effort `/proc/<pid>` enrichment for events that only carry a bare
//! pid (as netlink `CN_PROC` events do). The process may have already
//! exited by the time we read `/proc/<pid>` (exec/exit races are inherent
//! to any out-of-band event source), so every field degrades to an empty
//! default rather than erroring.

use std::fs;

/// Snapshot of what we could learn about a pid at event time.
pub struct ProcSnapshot {
    pub ppid: u32,
    pub uid: u32,
    pub exe: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub container_id: Option<String>,
}

/// Read what's available from `/proc/<pid>` right now. Never fails: an
/// unreadable or already-gone process simply yields empty/zeroed fields.
pub fn snapshot(pid: i32) -> ProcSnapshot {
    let base = format!("/proc/{pid}");

    let mut ppid = 0u32;
    let mut uid = 0u32;
    if let Ok(status) = fs::read_to_string(format!("{base}/status")) {
        for line in status.lines() {
            if let Some(v) = line.strip_prefix("PPid:\t") {
                ppid = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("Uid:\t") {
                uid = v
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
        }
    }

    let exe = fs::read_link(format!("{base}/exe"))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    let args: Vec<String> = fs::read_to_string(format!("{base}/cmdline"))
        .unwrap_or_default()
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    let cwd = fs::read_link(format!("{base}/cwd"))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    let cgroup = fs::read_to_string(format!("{base}/cgroup")).unwrap_or_default();
    let (_, _, container_id) = crate::collector_linux::parse_container_from_cgroup(cgroup.trim());

    ProcSnapshot {
        ppid,
        uid,
        exe,
        args,
        cwd,
        container_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_of_pid1_never_panics_and_has_plausible_shape() {
        // pid 1 always exists in any Linux environment (including this
        // container). We don't assert exact values since they vary by
        // host, only that the call is safe and returns a sane shape.
        let snap = snapshot(1);
        // exe may be unreadable without privilege, but the call must not
        // panic either way.
        let _ = snap.exe;
        let _ = snap.args;
    }

    #[test]
    fn snapshot_of_nonexistent_pid_is_all_defaults() {
        let snap = snapshot(i32::MAX);
        assert_eq!(snap.ppid, 0);
        assert_eq!(snap.uid, 0);
        assert!(snap.exe.is_empty());
        assert!(snap.args.is_empty());
        assert!(snap.container_id.is_none());
    }
}
