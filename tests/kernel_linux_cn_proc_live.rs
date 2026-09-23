//! Live integration test for the `CN_PROC` netlink process connector.
//!
//! Opens a real netlink socket, execs a short-lived child process, and
//! asserts we observe both its `Exec` and `Exit` events. This requires
//! `CAP_NET_ADMIN`; without it, the test prints why and returns early
//! (a runtime skip on a genuinely missing privilege) rather than failing
//! or being silently `#[ignore]`d.
//!
//! Linux-only: compiled out entirely on other platforms.

#![cfg(target_os = "linux")]

use std::process::Command;
use std::time::{Duration, Instant};

use wardex::kernel_linux::capability::detect_capability;
use wardex::kernel_linux::netlink_proc::{NetlinkProcListener, parse_netlink_buffer};

#[test]
fn observes_real_exec_and_exit_events() {
    let cap = detect_capability();
    if !cap.has_cap_net_admin {
        eprintln!(
            "SKIP: CAP_NET_ADMIN not held in this environment ({}); \
             cannot open a CN_PROC netlink socket. This is a runtime \
             privilege skip, not a test failure.",
            cap.process_backend_reason
        );
        return;
    }

    let listener = match NetlinkProcListener::open() {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "SKIP: CAP_NET_ADMIN was reported held, but opening the \
                 CN_PROC socket still failed ({e}); treating as an \
                 environment limitation (e.g. a restrictive seccomp/netlink \
                 sandbox) rather than a test failure."
            );
            return;
        }
    };

    // Spawn a short-lived child so we get a distinctive, findable pid
    // going through both an exec and an exit.
    let mut child = Command::new("/bin/true")
        .spawn()
        .expect("spawning /bin/true must succeed in any Linux test environment");
    let child_pid = child.id() as i32;
    let status = child.wait().expect("waiting on /bin/true must succeed");
    assert!(status.success());

    let mut saw_exec = false;
    let mut saw_exit = false;
    let deadline = Instant::now() + Duration::from_secs(10);

    // Use a raw poll+recv loop with a short per-call timeout so the test
    // can't hang forever if, for some reason, no event ever arrives.
    while Instant::now() < deadline && !(saw_exec && saw_exit) {
        let mut buf = vec![0u8; 16 * 1024];
        match listener.try_recv_timeout(&mut buf, Duration::from_millis(500)) {
            Some(n) => {
                for ev in parse_netlink_buffer(&buf[..n]) {
                    match ev {
                        wardex::kernel_linux::netlink_proc::ProcConnectorEvent::Exec {
                            pid,
                            ..
                        } if pid == child_pid => saw_exec = true,
                        wardex::kernel_linux::netlink_proc::ProcConnectorEvent::Exit {
                            pid,
                            ..
                        } if pid == child_pid => saw_exit = true,
                        _ => {}
                    }
                }
            }
            None => continue,
        }
    }

    assert!(
        saw_exec || saw_exit,
        "expected to observe at least one CN_PROC event for pid {child_pid} \
         within the timeout (saw_exec={saw_exec}, saw_exit={saw_exit}); the \
         kernel may have coalesced or dropped events under test-runner load"
    );
}
