//! inotify(7)-based file activity telemetry — the fallback backend used
//! when fanotify is unavailable (no `CAP_SYS_ADMIN`, or an old kernel).
//!
//! Unlike fanotify's mark-mount mode, inotify only watches the specific
//! paths it is told about (non-recursively), so the caller's configured
//! watch paths are used directly rather than falling back to "/". It has
//! no process/exec context (no pid on events), but it does natively cover
//! create/delete/rename, which our fanotify backend currently cannot (see
//! `fanotify_backend`'s module docs).
//!
//! All syscalls go through `nix::sys::inotify`, which already returns
//! fully-parsed, safe `InotifyEvent` values — there is no raw byte layout
//! for us to hand-decode here (that's what distinguishes this backend from
//! `netlink_proc`/`fanotify_backend`).

use std::io;

use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, InotifyEvent};

use crate::kernel_events::{EventSource, KernelEventKind};

fn classify(event: &InotifyEvent, watch_path: &str) -> Option<KernelEventKind> {
    let name = event
        .name
        .as_ref()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let path = if name.is_empty() {
        watch_path.to_string()
    } else {
        format!("{}/{}", watch_path.trim_end_matches('/'), name)
    };
    let mask = event.mask;
    if mask.contains(AddWatchFlags::IN_CREATE) {
        Some(KernelEventKind::FileWrite {
            pid: 0,
            path,
            bytes_written: 0,
        })
    } else if mask.contains(AddWatchFlags::IN_DELETE) {
        Some(KernelEventKind::FileDelete { pid: 0, path })
    } else if mask.contains(AddWatchFlags::IN_MOVED_FROM)
        || mask.contains(AddWatchFlags::IN_MOVED_TO)
    {
        Some(KernelEventKind::FileRename {
            pid: 0,
            old_path: path.clone(),
            new_path: path,
        })
    } else if mask.contains(AddWatchFlags::IN_CLOSE_WRITE)
        || mask.contains(AddWatchFlags::IN_MODIFY)
    {
        Some(KernelEventKind::FileWrite {
            pid: 0,
            path,
            bytes_written: 0,
        })
    } else {
        None
    }
}

/// An open inotify instance with watches installed on each configured path.
pub struct InotifyWatcher {
    inotify: Inotify,
    /// Maps a watch descriptor's raw id back to the path it watches, since
    /// `InotifyEvent` only carries the descriptor, not the path.
    watches: Vec<(i32, String)>,
}

impl InotifyWatcher {
    pub fn open(watch_paths: &[String]) -> io::Result<Self> {
        let inotify = Inotify::init(InitFlags::IN_CLOEXEC).map_err(nix_to_io)?;
        let flags = AddWatchFlags::IN_CREATE
            | AddWatchFlags::IN_DELETE
            | AddWatchFlags::IN_MODIFY
            | AddWatchFlags::IN_CLOSE_WRITE
            | AddWatchFlags::IN_MOVED_FROM
            | AddWatchFlags::IN_MOVED_TO;
        let mut watches = Vec::new();
        for path in watch_paths {
            match inotify.add_watch(path.as_str(), flags) {
                Ok(wd) => watches.push((wd.as_raw(), path.clone())),
                Err(e) => {
                    log::warn!("kernel_linux: inotify could not watch {path}: {e}");
                }
            }
        }
        if watches.is_empty() {
            return Err(io::Error::other(
                "no watch paths could be registered with inotify",
            ));
        }
        Ok(Self { inotify, watches })
    }

    fn path_for(&self, wd: i32) -> &str {
        self.watches
            .iter()
            .find(|(id, _)| *id == wd)
            .map(|(_, p)| p.as_str())
            .unwrap_or("<unknown>")
    }
}

fn nix_to_io(e: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

pub(crate) fn run(
    watcher: InotifyWatcher,
    tx: std::sync::mpsc::SyncSender<super::RawEvent>,
    stats: &super::KernelTelemetryStats,
) {
    loop {
        let events = match watcher.inotify.read_events() {
            Ok(events) => events,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => {
                log::warn!("kernel_linux: inotify listener stopped: {e}");
                break;
            }
        };
        for event in events {
            let watch_path = watcher.path_for(event.wd.as_raw());
            if let Some(kind) = classify(&event, watch_path) {
                super::send_or_drop(&tx, stats, EventSource::Inotify, kind, &stats.file_events);
            }
        }
    }
}
