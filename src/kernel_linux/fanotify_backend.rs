//! fanotify(7)-based file activity telemetry.
//!
//! Uses mark-mount mode (`FAN_MARK_MOUNT`) rather than `FAN_REPORT_FID` /
//! `FAN_REPORT_DFID_NAME`: the latter would let us observe create/delete/
//! rename without a path-walk, but those init flags are not exposed by our
//! safe wrapper (`nix` 0.31's `fanotify::InitFlags`) at the time of writing.
//! Being honest about the gap: create/delete/rename coverage instead comes
//! from the `inotify` fallback backend, which this module's caller uses
//! whenever fanotify itself is unavailable (missing `CAP_SYS_ADMIN`, or an
//! old kernel). A future upgrade can add `FAN_REPORT_DFID_NAME` support
//! once it lands in a released `nix`, without changing this module's shape.
//!
//! The raw `fanotify_event_metadata` decode is implemented by hand on a
//! `&[u8]` buffer (mirroring `linux/fanotify.h`) so it can be exercised
//! with byte fixtures in tests with no privileges and no live fd.

use std::io;
use std::os::fd::AsRawFd;

use nix::fcntl::AT_FDCWD;
use nix::sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags};

use crate::kernel_events::{EventSource, KernelEventKind};

/// `struct fanotify_event_metadata` layout (`linux/fanotify.h`), 24 bytes:
/// `u32 event_len; u8 vers; u8 reserved; u16 metadata_len; u64 mask; i32 fd; i32 pid;`
const METADATA_LEN: usize = 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFanotifyEvent {
    pub event_len: u32,
    pub mask: u64,
    /// `None` for an `FAN_NOFD` overflow notification.
    pub fd: Option<i32>,
    pub pid: i32,
}

const FAN_NOFD: i32 = -1;

fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    let s = buf.get(off..off + 4)?;
    Some(u32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
}
fn read_u64(buf: &[u8], off: usize) -> Option<u64> {
    let s = buf.get(off..off + 8)?;
    Some(u64::from_ne_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}
fn read_i32(buf: &[u8], off: usize) -> Option<i32> {
    read_u32(buf, off).map(|v| v as i32)
}

/// Decode a raw `read(2)` result from a fanotify group fd into individual
/// event records. Fanotify may pack several fixed/variable-length records
/// into one read; each record's own `event_len` tells us where the next
/// one starts.
pub fn decode_events(buf: &[u8]) -> Vec<RawFanotifyEvent> {
    let mut events = Vec::new();
    let mut offset = 0usize;
    while offset + METADATA_LEN <= buf.len() {
        let event_len = match read_u32(buf, offset) {
            Some(v) => v,
            None => break,
        };
        if (event_len as usize) < METADATA_LEN {
            break;
        }
        let mask = read_u64(buf, offset + 8).unwrap_or(0);
        let fd_raw = read_i32(buf, offset + 16).unwrap_or(FAN_NOFD);
        let pid = read_i32(buf, offset + 20).unwrap_or(0);
        events.push(RawFanotifyEvent {
            event_len,
            mask,
            fd: if fd_raw == FAN_NOFD {
                None
            } else {
                Some(fd_raw)
            },
            pid,
        });
        if offset + event_len as usize <= offset {
            break; // guard against a zero/overflow step
        }
        offset += event_len as usize;
    }
    events
}

/// Map a raw event's mask bits to our normalized `KernelEventKind`. A
/// single fanotify record can carry multiple bits; we prioritize the most
/// specific/actionable one for a single normalized event, since the
/// existing `KernelEventKind` model is one-kind-per-event.
fn classify(mask: u64, pid: u32, path: String) -> Option<KernelEventKind> {
    let mask = MaskFlags::from_bits_truncate(mask);
    if mask.contains(MaskFlags::FAN_OPEN_EXEC) {
        Some(KernelEventKind::FileOpen {
            pid,
            path,
            flags: mask.bits() as u32,
        })
    } else if mask.contains(MaskFlags::FAN_CLOSE_WRITE) || mask.contains(MaskFlags::FAN_MODIFY) {
        Some(KernelEventKind::FileWrite {
            pid,
            path,
            bytes_written: 0,
        })
    } else if mask.contains(MaskFlags::FAN_OPEN) {
        Some(KernelEventKind::FileOpen {
            pid,
            path,
            flags: mask.bits() as u32,
        })
    } else {
        None
    }
}

/// An open, marked fanotify group.
pub struct FanotifyWatcher {
    group: Fanotify,
}

impl FanotifyWatcher {
    /// Initialize a notification-class fanotify group and mark each given
    /// path's mount for the events we care about. Fails (typically
    /// `EPERM`) without `CAP_SYS_ADMIN`.
    pub fn open(watch_paths: &[String]) -> io::Result<Self> {
        let group = Fanotify::init(
            InitFlags::FAN_CLASS_NOTIF | InitFlags::FAN_CLOEXEC,
            EventFFlags::O_RDONLY,
        )
        .map_err(nix_to_io)?;

        let mask = MaskFlags::FAN_CLOSE_WRITE | MaskFlags::FAN_MODIFY | MaskFlags::FAN_OPEN_EXEC;
        let paths = if watch_paths.is_empty() {
            vec!["/".to_string()]
        } else {
            watch_paths.to_vec()
        };
        for path in &paths {
            group
                .mark(
                    MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_MOUNT,
                    mask,
                    AT_FDCWD,
                    Some(path.as_str()),
                )
                .map_err(nix_to_io)?;
        }
        Ok(Self { group })
    }
}

fn nix_to_io(e: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

fn resolve_fd_path(fd: i32) -> String {
    std::fs::read_link(format!("/proc/self/fd/{fd}"))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| format!("<fd:{fd}>"))
}

/// Backend loop: reads events off the fanotify group via `nix`'s safe
/// `read_events()` (which owns each event's fd for its lifetime and closes
/// it on drop — no manual fd bookkeeping needed here), resolves the fd to a
/// path, and forwards a normalized event.
///
/// [`decode_events`] above implements the same wire format by hand and is
/// exercised with byte fixtures in tests; it documents and guards our
/// understanding of the layout even though the live path goes through
/// `nix`'s higher-level, fd-owning API for safety.
pub(crate) fn run(
    watcher: FanotifyWatcher,
    tx: std::sync::mpsc::SyncSender<super::RawEvent>,
    stats: &super::KernelTelemetryStats,
) {
    loop {
        let events = match watcher.group.read_events() {
            Ok(events) => events,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => {
                log::warn!("kernel_linux: fanotify listener stopped: {e}");
                break;
            }
        };
        for event in events {
            let Some(fd) = event.fd() else {
                log::warn!("kernel_linux: fanotify event queue overflowed");
                continue;
            };
            let path = resolve_fd_path(fd.as_raw_fd());
            let pid = if event.pid() < 0 {
                0
            } else {
                event.pid() as u32
            };
            if let Some(kind) = classify(event.mask().bits(), pid, path) {
                super::send_or_drop(&tx, stats, EventSource::Fanotify, kind, &stats.file_events);
            }
            // `event` (and the fd it owns) drops here, closing the fd.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fanotify_record(event_len: u32, mask: u64, fd: i32, pid: i32) -> Vec<u8> {
        let mut b = Vec::with_capacity(METADATA_LEN);
        b.extend_from_slice(&event_len.to_ne_bytes());
        b.push(3); // vers (FANOTIFY_METADATA_VERSION on modern kernels)
        b.push(0); // reserved
        b.extend_from_slice(&(METADATA_LEN as u16).to_ne_bytes());
        b.extend_from_slice(&mask.to_ne_bytes());
        b.extend_from_slice(&fd.to_ne_bytes());
        b.extend_from_slice(&pid.to_ne_bytes());
        assert_eq!(b.len(), METADATA_LEN);
        b
    }

    #[test]
    fn decodes_single_close_write_event() {
        let buf = fanotify_record(
            METADATA_LEN as u32,
            MaskFlags::FAN_CLOSE_WRITE.bits(),
            7,
            4242,
        );
        let events = decode_events(&buf);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].fd, Some(7));
        assert_eq!(events[0].pid, 4242);
        assert_eq!(events[0].mask, MaskFlags::FAN_CLOSE_WRITE.bits());
    }

    #[test]
    fn decodes_multiple_packed_events() {
        let mut buf = Vec::new();
        buf.extend(fanotify_record(
            METADATA_LEN as u32,
            MaskFlags::FAN_OPEN_EXEC.bits(),
            3,
            10,
        ));
        buf.extend(fanotify_record(
            METADATA_LEN as u32,
            MaskFlags::FAN_MODIFY.bits(),
            5,
            11,
        ));
        let events = decode_events(&buf);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].pid, 10);
        assert_eq!(events[1].pid, 11);
    }

    #[test]
    fn overflow_event_has_no_fd() {
        let buf = fanotify_record(
            METADATA_LEN as u32,
            MaskFlags::FAN_Q_OVERFLOW.bits(),
            FAN_NOFD,
            0,
        );
        let events = decode_events(&buf);
        assert_eq!(events[0].fd, None);
    }

    #[test]
    fn truncated_buffer_yields_no_events_and_does_not_panic() {
        let buf = fanotify_record(METADATA_LEN as u32, 0, 1, 1);
        let truncated = &buf[..METADATA_LEN - 5];
        assert!(decode_events(truncated).is_empty());
    }

    #[test]
    fn zero_length_record_stops_decoding_without_panic() {
        let mut buf = vec![0u8; METADATA_LEN];
        // event_len = 0 is invalid (< METADATA_LEN), must be rejected.
        assert!(decode_events(&buf).is_empty());
        // A well-formed record followed by garbage shorter than a header.
        buf = fanotify_record(METADATA_LEN as u32, 0, 1, 1);
        buf.extend_from_slice(&[0u8; 4]);
        let events = decode_events(&buf);
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn classify_prioritizes_exec_over_write() {
        let mask = (MaskFlags::FAN_OPEN_EXEC | MaskFlags::FAN_MODIFY).bits();
        let kind = classify(mask, 1, "/bin/sh".into()).unwrap();
        assert!(matches!(kind, KernelEventKind::FileOpen { .. }));
    }

    #[test]
    fn classify_unrelated_mask_is_none() {
        assert!(classify(MaskFlags::FAN_ACCESS.bits(), 1, "/tmp/x".into()).is_none());
    }
}
