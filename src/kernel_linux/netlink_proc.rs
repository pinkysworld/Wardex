//! `CN_PROC` process connector: real-time process lifecycle events pushed
//! by the kernel over a netlink socket.
//!
//! See `Documentation/connector/cn_proc.rst` and `linux/cn_proc.h` in the
//! kernel source. Message layout (all little-endian on every Linux arch we
//! ship for):
//!
//! ```text
//! struct nlmsghdr {          16 bytes
//!     u32 nlmsg_len;
//!     u16 nlmsg_type;
//!     u16 nlmsg_flags;
//!     u32 nlmsg_seq;
//!     u32 nlmsg_pid;
//! }
//! struct cn_msg {            20-byte header, then `len` bytes of payload
//!     struct cb_id { u32 idx; u32 val; } id;
//!     u32 seq;
//!     u32 ack;
//!     u16 len;
//!     u16 flags;
//! }
//! struct proc_event {        16-byte header + up to 16-byte union
//!     u32 what;
//!     u32 cpu;
//!     u64 timestamp_ns;
//!     union { fork{4×i32} exec{2×i32} exit{2×i32,2×u32} id{2×i32,2×u32} ... }
//! }
//! ```
//!
//! All parsing here is on plain `&[u8]` slices with `from_le_bytes`, so it
//! needs no `unsafe` and is fully testable with byte fixtures, independent
//! of any live socket.

use std::io;
use std::os::fd::AsRawFd;

use netlink_sys::{Socket, SocketAddr};

use crate::kernel_events::{EventSource, KernelEventKind};

/// Netlink protocol number for the kernel connector (`NETLINK_CONNECTOR`).
/// Not exposed by the `libc` crate at the time of writing, so it is spelled
/// out here from `linux/netlink.h`.
pub const NETLINK_CONNECTOR: isize = 11;
/// Connector multiplexing ID used by the process connector.
const CN_IDX_PROC: u32 = 0x0000_0001;
const CN_VAL_PROC: u32 = 0x0000_0001;
/// Ask the kernel to start/stop sending us proc events.
const PROC_CN_MCAST_LISTEN: u32 = 1;
#[allow(dead_code)]
const PROC_CN_MCAST_IGNORE: u32 = 2;

const NLMSG_HDR_LEN: usize = 16;
const CN_MSG_HDR_LEN: usize = 20;
const PROC_EVENT_HDR_LEN: usize = 16;

/// `what` values from `enum proc_cn_event` (`linux/cn_proc.h`).
mod what {
    pub const FORK: u32 = 0x0000_0001;
    pub const EXEC: u32 = 0x0000_0002;
    pub const UID: u32 = 0x0000_0004;
    pub const GID: u32 = 0x0000_0040;
    pub const EXIT: u32 = 0x8000_0000;
}

/// A decoded `CN_PROC` event, independent of enrichment (no `/proc` lookups
/// have happened yet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcConnectorEvent {
    Fork {
        parent_pid: i32,
        parent_tgid: i32,
        child_pid: i32,
        child_tgid: i32,
    },
    Exec {
        pid: i32,
        tgid: i32,
    },
    Exit {
        pid: i32,
        tgid: i32,
        exit_code: i32,
    },
    UidChange {
        pid: i32,
        ruid: u32,
        euid: u32,
    },
    GidChange {
        pid: i32,
        rgid: u32,
        egid: u32,
    },
    /// A `proc_event` variant we don't specifically model (e.g. SID,
    /// PTRACE, COMM, COREDUMP). Carried through so callers can at least
    /// count/log it.
    Other {
        what: u32,
    },
}

#[derive(Debug)]
pub enum ParseError {
    Truncated,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Truncated => write!(f, "truncated netlink/cn_proc message"),
        }
    }
}

fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    let s = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
    let s = buf.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn read_i32(buf: &[u8], off: usize) -> Option<i32> {
    read_u32(buf, off).map(|v| v as i32)
}

/// Parse one `proc_event` payload (starting right after the `cn_msg`
/// header) into a [`ProcConnectorEvent`].
fn parse_proc_event(buf: &[u8]) -> Result<ProcConnectorEvent, ParseError> {
    if buf.len() < PROC_EVENT_HDR_LEN {
        return Err(ParseError::Truncated);
    }
    let what_val = read_u32(buf, 0).ok_or(ParseError::Truncated)?;
    let union = &buf[PROC_EVENT_HDR_LEN..];

    let event = match what_val {
        what::FORK => {
            if union.len() < 16 {
                return Err(ParseError::Truncated);
            }
            ProcConnectorEvent::Fork {
                parent_pid: read_i32(union, 0).ok_or(ParseError::Truncated)?,
                parent_tgid: read_i32(union, 4).ok_or(ParseError::Truncated)?,
                child_pid: read_i32(union, 8).ok_or(ParseError::Truncated)?,
                child_tgid: read_i32(union, 12).ok_or(ParseError::Truncated)?,
            }
        }
        what::EXEC => {
            if union.len() < 8 {
                return Err(ParseError::Truncated);
            }
            ProcConnectorEvent::Exec {
                pid: read_i32(union, 0).ok_or(ParseError::Truncated)?,
                tgid: read_i32(union, 4).ok_or(ParseError::Truncated)?,
            }
        }
        what::EXIT => {
            if union.len() < 16 {
                return Err(ParseError::Truncated);
            }
            ProcConnectorEvent::Exit {
                pid: read_i32(union, 0).ok_or(ParseError::Truncated)?,
                tgid: read_i32(union, 4).ok_or(ParseError::Truncated)?,
                exit_code: read_i32(union, 8).ok_or(ParseError::Truncated)?,
            }
        }
        what::UID => {
            if union.len() < 16 {
                return Err(ParseError::Truncated);
            }
            ProcConnectorEvent::UidChange {
                pid: read_i32(union, 0).ok_or(ParseError::Truncated)?,
                ruid: read_u32(union, 8).ok_or(ParseError::Truncated)?,
                euid: read_u32(union, 12).ok_or(ParseError::Truncated)?,
            }
        }
        what::GID => {
            if union.len() < 16 {
                return Err(ParseError::Truncated);
            }
            ProcConnectorEvent::GidChange {
                pid: read_i32(union, 0).ok_or(ParseError::Truncated)?,
                rgid: read_u32(union, 8).ok_or(ParseError::Truncated)?,
                egid: read_u32(union, 12).ok_or(ParseError::Truncated)?,
            }
        }
        other => ProcConnectorEvent::Other { what: other },
    };
    Ok(event)
}

/// Parse a full netlink receive buffer, which may contain multiple
/// `nlmsghdr`-framed `cn_msg` packets, into zero or more proc events.
/// Malformed trailing bytes are ignored rather than treated as a hard
/// error, matching how the kernel pads/aligns netlink messages.
pub fn parse_netlink_buffer(buf: &[u8]) -> Vec<ProcConnectorEvent> {
    let mut events = Vec::new();
    let mut offset = 0usize;

    while offset + NLMSG_HDR_LEN <= buf.len() {
        let nlmsg_len = match read_u32(buf, offset) {
            Some(v) => v as usize,
            None => break,
        };
        if nlmsg_len < NLMSG_HDR_LEN || offset + nlmsg_len > buf.len() {
            break;
        }
        let nlmsg_type = read_u16(buf, offset + 4).unwrap_or(0);
        // NLMSG_ERROR (2) carries a `struct nlmsgerr`, not a `cn_msg` —
        // skip it. Note that real `cn_proc` events are, perhaps
        // surprisingly, sent with `nlmsg_type == NLMSG_DONE` (3): the
        // kernel's connector code reuses that constant for its own
        // messages rather than defining a dedicated type, so NLMSG_DONE
        // must NOT be filtered out here (a prior version of this parser
        // did, and silently dropped every real event as a result — see
        // the `parses_nlmsg_done_typed_events` test below, which pins
        // this against regressing).
        if nlmsg_type != 2 {
            let cn_start = offset + NLMSG_HDR_LEN;
            if cn_start + CN_MSG_HDR_LEN <= offset + nlmsg_len {
                let idx = read_u32(buf, cn_start).unwrap_or(0);
                let val = read_u32(buf, cn_start + 4).unwrap_or(0);
                let payload_len = read_u16(buf, cn_start + 16).unwrap_or(0) as usize;
                let payload_start = cn_start + CN_MSG_HDR_LEN;
                if idx == CN_IDX_PROC
                    && val == CN_VAL_PROC
                    && payload_start + payload_len <= buf.len()
                    && let Ok(ev) =
                        parse_proc_event(&buf[payload_start..payload_start + payload_len])
                {
                    events.push(ev);
                }
            }
        }

        // Netlink messages are 4-byte aligned (`NLMSG_ALIGN`).
        let aligned = nlmsg_len.div_ceil(4) * 4;
        if aligned == 0 {
            break;
        }
        offset += aligned;
    }

    events
}

/// Build the small control message that tells the kernel connector to
/// start (or stop) multicasting proc events to us.
pub fn build_listen_control_message(listen: bool) -> Vec<u8> {
    let op = if listen {
        PROC_CN_MCAST_LISTEN
    } else {
        PROC_CN_MCAST_IGNORE
    };
    let payload = op.to_le_bytes(); // 4 bytes
    let cn_msg_len = CN_MSG_HDR_LEN + payload.len();
    let total_len = NLMSG_HDR_LEN + cn_msg_len;

    let mut msg = Vec::with_capacity(total_len);
    // nlmsghdr
    msg.extend_from_slice(&(total_len as u32).to_le_bytes()); // nlmsg_len
    msg.extend_from_slice(&0u16.to_le_bytes()); // nlmsg_type (NLMSG_DONE-ish; kernel ignores for cn)
    msg.extend_from_slice(&0u16.to_le_bytes()); // nlmsg_flags
    msg.extend_from_slice(&0u32.to_le_bytes()); // nlmsg_seq
    msg.extend_from_slice(&(std::process::id()).to_le_bytes()); // nlmsg_pid
    // cn_msg
    msg.extend_from_slice(&CN_IDX_PROC.to_le_bytes());
    msg.extend_from_slice(&CN_VAL_PROC.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes()); // seq
    msg.extend_from_slice(&0u32.to_le_bytes()); // ack
    msg.extend_from_slice(&(payload.len() as u16).to_le_bytes()); // len
    msg.extend_from_slice(&0u16.to_le_bytes()); // flags
    msg.extend_from_slice(&payload);
    msg
}

/// An open, bound, and subscribed `CN_PROC` netlink socket.
pub struct NetlinkProcListener {
    socket: Socket,
}

impl NetlinkProcListener {
    /// Open the connector socket, join the proc-event multicast group, and
    /// ask the kernel to start sending events. Fails (typically `EPERM`)
    /// without `CAP_NET_ADMIN`.
    pub fn open() -> io::Result<Self> {
        let mut socket = Socket::new(NETLINK_CONNECTOR)?;
        socket.bind(&SocketAddr::new(0, CN_IDX_PROC))?;
        socket.add_membership(CN_IDX_PROC)?;
        let kernel_addr = SocketAddr::new(0, 0);
        let listen_msg = build_listen_control_message(true);
        socket.send_to(&listen_msg, &kernel_addr, 0)?;
        Ok(Self { socket })
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut writer: &mut [u8] = buf;
        let (n, _addr) = self.socket.recv_from(&mut writer, 0)?;
        Ok(n)
    }

    /// Wait up to `timeout` for data, then receive it. Returns `None` on a
    /// timeout (no data ready) so callers can loop with an overall
    /// deadline instead of blocking forever. Used by the live integration
    /// test; the production [`run`] loop uses a plain blocking [`recv`]
    /// instead, since it has nothing better to do while idle.
    pub fn try_recv_timeout(&self, buf: &mut [u8], timeout: std::time::Duration) -> Option<usize> {
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        use std::os::fd::AsFd;

        let poll_timeout = PollTimeout::try_from(timeout).unwrap_or(PollTimeout::MAX);
        let mut fds = [PollFd::new(self.socket.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, poll_timeout) {
            Ok(n) if n > 0 => self.recv(buf).ok(),
            _ => None,
        }
    }
}

impl AsRawFd for NetlinkProcListener {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.socket.as_raw_fd()
    }
}

/// Enrich a decoded proc-connector event with `/proc/<pid>` metadata and
/// push it (best-effort; drop-on-backpressure) into the shared channel.
fn enrich_and_send(
    ev: ProcConnectorEvent,
    tx: &std::sync::mpsc::SyncSender<super::RawEvent>,
    stats: &super::KernelTelemetryStats,
) {
    let kind = match ev {
        ProcConnectorEvent::Exec { pid, .. } => {
            let info = crate::kernel_linux::procinfo::snapshot(pid);
            Some(KernelEventKind::ProcessExec {
                pid: pid as u32,
                ppid: info.ppid,
                uid: info.uid,
                exe: info.exe,
                args: info.args,
                cwd: info.cwd,
                container_id: info.container_id,
            })
        }
        ProcConnectorEvent::Exit { pid, exit_code, .. } => Some(KernelEventKind::ProcessExit {
            pid: pid as u32,
            exit_code,
        }),
        // `kernel_events::KernelEventKind` has no dedicated variant yet for
        // fork/uid-change/gid-change (unlike exec/exit), so forwarding one
        // of them as, say, a `ProcessExit` would misrepresent the event.
        // Rather than force a bad mapping, these are dropped here; only
        // exec and exit — which do have accurate normalized variants — are
        // forwarded today.
        ProcConnectorEvent::Fork { .. }
        | ProcConnectorEvent::UidChange { .. }
        | ProcConnectorEvent::GidChange { .. }
        | ProcConnectorEvent::Other { .. } => None,
    };

    if let Some(kind) = kind {
        super::send_or_drop(
            tx,
            stats,
            EventSource::NetlinkProcConnector,
            kind,
            &stats.process_events,
        );
    }
}

/// Backend loop: blocks on `recv`, parses, enriches, and forwards events
/// until the socket errors out (e.g. process shutdown closes the fd).
pub(crate) fn run(
    listener: NetlinkProcListener,
    tx: std::sync::mpsc::SyncSender<super::RawEvent>,
    stats: &super::KernelTelemetryStats,
) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match listener.recv(&mut buf) {
            Ok(n) if n > 0 => {
                for ev in parse_netlink_buffer(&buf[..n]) {
                    enrich_and_send(ev, &tx, stats);
                }
            }
            Ok(_) => continue,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                log::warn!("kernel_linux: CN_PROC listener stopped: {e}");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nlmsg(nlmsg_type: u16, cn_msg_and_payload: &[u8]) -> Vec<u8> {
        let total = NLMSG_HDR_LEN + cn_msg_and_payload.len();
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out.extend_from_slice(&nlmsg_type.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u32.to_le_bytes()); // seq
        out.extend_from_slice(&0u32.to_le_bytes()); // pid
        out.extend_from_slice(cn_msg_and_payload);
        out
    }

    fn cn_msg(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(CN_MSG_HDR_LEN + payload.len());
        out.extend_from_slice(&CN_IDX_PROC.to_le_bytes());
        out.extend_from_slice(&CN_VAL_PROC.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // seq
        out.extend_from_slice(&0u32.to_le_bytes()); // ack
        out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(payload);
        out
    }

    fn proc_event_exec(pid: i32, tgid: i32) -> Vec<u8> {
        let mut out = Vec::with_capacity(PROC_EVENT_HDR_LEN + 8);
        out.extend_from_slice(&what::EXEC.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // cpu
        out.extend_from_slice(&0u64.to_le_bytes()); // timestamp_ns
        out.extend_from_slice(&pid.to_le_bytes());
        out.extend_from_slice(&tgid.to_le_bytes());
        out
    }

    fn proc_event_fork(
        parent_pid: i32,
        parent_tgid: i32,
        child_pid: i32,
        child_tgid: i32,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(PROC_EVENT_HDR_LEN + 16);
        out.extend_from_slice(&what::FORK.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&parent_pid.to_le_bytes());
        out.extend_from_slice(&parent_tgid.to_le_bytes());
        out.extend_from_slice(&child_pid.to_le_bytes());
        out.extend_from_slice(&child_tgid.to_le_bytes());
        out
    }

    fn proc_event_exit(pid: i32, tgid: i32, code: i32) -> Vec<u8> {
        let mut out = Vec::with_capacity(PROC_EVENT_HDR_LEN + 16);
        out.extend_from_slice(&what::EXIT.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&pid.to_le_bytes());
        out.extend_from_slice(&tgid.to_le_bytes());
        out.extend_from_slice(&code.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes()); // exit_signal
        out
    }

    #[test]
    fn parses_single_exec_event() {
        let payload = proc_event_exec(1234, 1234);
        let msg = nlmsg(0, &cn_msg(&payload));
        let events = parse_netlink_buffer(&msg);
        assert_eq!(
            events,
            vec![ProcConnectorEvent::Exec {
                pid: 1234,
                tgid: 1234
            }]
        );
    }

    #[test]
    fn parses_fork_event() {
        let payload = proc_event_fork(10, 10, 20, 20);
        let msg = nlmsg(0, &cn_msg(&payload));
        let events = parse_netlink_buffer(&msg);
        assert_eq!(
            events,
            vec![ProcConnectorEvent::Fork {
                parent_pid: 10,
                parent_tgid: 10,
                child_pid: 20,
                child_tgid: 20,
            }]
        );
    }

    #[test]
    fn parses_exit_event() {
        let payload = proc_event_exit(555, 555, 0);
        let msg = nlmsg(0, &cn_msg(&payload));
        let events = parse_netlink_buffer(&msg);
        assert_eq!(
            events,
            vec![ProcConnectorEvent::Exit {
                pid: 555,
                tgid: 555,
                exit_code: 0
            }]
        );
    }

    #[test]
    fn parses_multiple_messages_in_one_buffer() {
        let mut buf = Vec::new();
        buf.extend(nlmsg(0, &cn_msg(&proc_event_exec(1, 1))));
        buf.extend(nlmsg(0, &cn_msg(&proc_event_exit(1, 1, 0))));
        let events = parse_netlink_buffer(&buf);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], ProcConnectorEvent::Exec { pid: 1, tgid: 1 });
        assert_eq!(
            events[1],
            ProcConnectorEvent::Exit {
                pid: 1,
                tgid: 1,
                exit_code: 0
            }
        );
    }

    #[test]
    fn ignores_non_proc_connector_ids() {
        let mut cn = cn_msg(&proc_event_exec(1, 1));
        // Corrupt the idx field so it no longer matches CN_IDX_PROC.
        cn[0..4].copy_from_slice(&99u32.to_le_bytes());
        let msg = nlmsg(0, &cn);
        assert!(parse_netlink_buffer(&msg).is_empty());
    }

    #[test]
    fn empty_nlmsg_done_frame_yields_no_events() {
        // A bare NLMSG_DONE with no cn_msg payload at all (too short to
        // contain one) must not be mistaken for an event.
        let mut buf = Vec::new();
        buf.extend(nlmsg(3, &[]));
        let events = parse_netlink_buffer(&buf);
        assert!(events.is_empty());
    }

    #[test]
    fn skips_nlmsg_error_frames() {
        // NLMSG_ERROR (type 2) is a `struct nlmsgerr`, never a `cn_msg`;
        // even if its bytes happened to look plausible, it must be
        // rejected.
        let payload = proc_event_exec(1, 1);
        let mut buf = Vec::new();
        buf.extend(nlmsg(2, &cn_msg(&payload)));
        let events = parse_netlink_buffer(&buf);
        assert!(events.is_empty());
    }

    #[test]
    fn parses_nlmsg_done_typed_events() {
        // Real `CN_PROC` events are sent by the kernel with
        // `nlmsg_type == NLMSG_DONE` (3) — this is the exact shape the
        // kernel actually sends (confirmed against a live socket), and
        // regressing this filter previously caused every real event to be
        // silently discarded (see the comment in `parse_netlink_buffer`).
        let payload = proc_event_exec(4242, 4242);
        let msg = nlmsg(3, &cn_msg(&payload));
        let events = parse_netlink_buffer(&msg);
        assert_eq!(
            events,
            vec![ProcConnectorEvent::Exec {
                pid: 4242,
                tgid: 4242
            }]
        );
    }

    #[test]
    fn truncated_buffer_does_not_panic() {
        let payload = proc_event_exec(1, 1);
        let mut msg = nlmsg(0, &cn_msg(&payload));
        msg.truncate(msg.len() - 3);
        // Must not panic; either yields nothing or is simply ignored.
        let _ = parse_netlink_buffer(&msg);
    }

    #[test]
    fn empty_buffer_yields_no_events() {
        assert!(parse_netlink_buffer(&[]).is_empty());
    }

    #[test]
    fn listen_control_message_has_expected_shape() {
        let msg = build_listen_control_message(true);
        assert_eq!(msg.len(), NLMSG_HDR_LEN + CN_MSG_HDR_LEN + 4);
        let nlmsg_len = u32::from_le_bytes(msg[0..4].try_into().unwrap());
        assert_eq!(nlmsg_len as usize, msg.len());
        let idx = u32::from_le_bytes(msg[16..20].try_into().unwrap());
        assert_eq!(idx, CN_IDX_PROC);
        let op = u32::from_le_bytes(msg[NLMSG_HDR_LEN + CN_MSG_HDR_LEN..].try_into().unwrap());
        assert_eq!(op, PROC_CN_MCAST_LISTEN);
    }

    #[test]
    fn unknown_what_becomes_other() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x0200u32.to_le_bytes()); // PROC_EVENT_COMM
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&0u64.to_le_bytes());
        let ev = parse_proc_event(&payload).unwrap();
        assert_eq!(ev, ProcConnectorEvent::Other { what: 0x0200 });
    }
}
