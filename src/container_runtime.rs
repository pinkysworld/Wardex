//! Live container/orchestrator event sources.
//!
//! Connects to the local Docker (or Podman, via its Docker-compatible
//! socket) Engine API over a Unix domain socket, and to the in-cluster
//! Kubernetes API server when running inside a pod, translating both
//! into the [`crate::container`] event/detection model.
//!
//! Docker/Podman is reached with a minimal hand-rolled HTTP/1.1 client
//! over `std::os::unix::net::UnixStream` — the Docker Engine API is
//! plain HTTP over the socket, so no TLS stack or heavy client crate
//! (e.g. bollard) is required. `ureq` does not support Unix sockets in
//! the version this crate pins, so it is unused here.
//!
//! Kubernetes support is best-effort: the in-cluster API server serves
//! TLS with the cluster's own CA, which is not in the process's default
//! trust store. `ureq` (as configured in this crate, without a direct
//! `rustls` dependency for building a custom `RootCertStore`) cannot be
//! told to trust that CA, so [`KubeClient::watch_pods`] will fail TLS
//! verification against a real API server. The request/response types
//! and event-mapping logic are implemented and unit-tested against
//! fixtures so the feature is ready to enable once a custom trust
//! anchor can be wired through (tracked as a known limitation below).

use crate::container::{ContainerEvent, ContainerEventKind};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::time::Duration;
#[cfg(not(unix))]
use unsupported_transport::UnixStream;

// ── Configuration ───────────────────────────────────────────────────

/// Configuration for live container/Kubernetes event sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerRuntimeConfig {
    /// Enable the Docker/Podman Engine API event source.
    #[serde(default)]
    pub docker_enabled: bool,
    /// Path to the Docker (or Podman) Engine API Unix socket.
    #[serde(default = "default_docker_socket_path")]
    pub docker_socket_path: String,
    /// Read timeout applied to each socket operation.
    #[serde(default = "default_docker_timeout_secs")]
    pub docker_timeout_secs: u64,
    /// Base reconnect backoff, doubled on each consecutive failure up to
    /// `docker_max_backoff_secs`.
    #[serde(default = "default_docker_backoff_secs")]
    pub docker_backoff_secs: u64,
    /// Ceiling for the reconnect backoff.
    #[serde(default = "default_docker_max_backoff_secs")]
    pub docker_max_backoff_secs: u64,
    /// Enable the in-cluster Kubernetes Pod watch event source.
    #[serde(default)]
    pub kubernetes_enabled: bool,
    /// Namespaces to watch (empty = all namespaces).
    #[serde(default)]
    pub kubernetes_namespaces: Vec<String>,
}

fn default_docker_socket_path() -> String {
    "/var/run/docker.sock".into()
}
fn default_docker_timeout_secs() -> u64 {
    10
}
fn default_docker_backoff_secs() -> u64 {
    1
}
fn default_docker_max_backoff_secs() -> u64 {
    60
}

impl Default for ContainerRuntimeConfig {
    fn default() -> Self {
        Self {
            docker_enabled: false,
            docker_socket_path: default_docker_socket_path(),
            docker_timeout_secs: default_docker_timeout_secs(),
            docker_backoff_secs: default_docker_backoff_secs(),
            docker_max_backoff_secs: default_docker_max_backoff_secs(),
            kubernetes_enabled: false,
            kubernetes_namespaces: Vec::new(),
        }
    }
}

/// Podman's rootless Docker-compatible socket, for convenience when
/// building a config: `unix:///run/user/<uid>/podman/podman.sock`.
pub fn podman_socket_path_for_uid(uid: u32) -> String {
    format!("/run/user/{uid}/podman/podman.sock")
}

// ── Status (for doctor / status API) ────────────────────────────────

/// Reachability status of a container runtime event source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuntimeStatus {
    Disabled,
    Unreachable,
    Reachable,
}

/// Combined status of the Docker/Podman and Kubernetes sources, for
/// surfacing in `doctor` and the status API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerRuntimeStatusReport {
    pub docker_status: RuntimeStatus,
    pub docker_socket_path: String,
    pub docker_error: Option<String>,
    pub docker_server_version: Option<String>,
    pub kubernetes_status: RuntimeStatus,
    pub kubernetes_error: Option<String>,
}

/// Probe Docker/Podman and Kubernetes reachability for a status report.
/// Never panics; all failures are folded into `RuntimeStatus::Unreachable`
/// plus a human-readable error string.
pub fn probe_status(config: &ContainerRuntimeConfig) -> ContainerRuntimeStatusReport {
    let (docker_status, docker_error, docker_server_version) = if !config.docker_enabled {
        (RuntimeStatus::Disabled, None, None)
    } else {
        match DockerClient::connect(config) {
            Ok(client) => match client.version() {
                Ok(v) => (RuntimeStatus::Reachable, None, Some(v.version)),
                Err(e) => (RuntimeStatus::Unreachable, Some(e), None),
            },
            Err(e) => (RuntimeStatus::Unreachable, Some(e), None),
        }
    };

    let (kubernetes_status, kubernetes_error) = if !config.kubernetes_enabled {
        (RuntimeStatus::Disabled, None)
    } else {
        match KubeClient::in_cluster() {
            Ok(_) => (RuntimeStatus::Reachable, None),
            Err(e) => (RuntimeStatus::Unreachable, Some(e)),
        }
    };

    ContainerRuntimeStatusReport {
        docker_status,
        docker_socket_path: config.docker_socket_path.clone(),
        docker_error,
        docker_server_version,
        kubernetes_status,
        kubernetes_error,
    }
}

// ── Docker Engine API client ────────────────────────────────────────

/// Minimal HTTP/1.1 client for the Docker Engine API over a Unix socket.
pub struct DockerClient {
    socket_path: String,
    timeout: Duration,
}

/// `GET /version` response (subset).
#[derive(Debug, Clone, Deserialize)]
pub struct DockerVersion {
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "ApiVersion")]
    pub api_version: String,
}

/// One entry of `GET /containers/json`.
#[derive(Debug, Clone, Deserialize)]
pub struct DockerContainerSummary {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Image", default)]
    pub image: String,
    #[serde(rename = "Names", default)]
    pub names: Vec<String>,
}

/// `GET /containers/{id}/json` response (subset relevant to detection).
#[derive(Debug, Clone, Deserialize)]
pub struct DockerInspect {
    #[serde(rename = "Id", default)]
    pub id: String,
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "Config", default)]
    pub config: DockerInspectConfig,
    #[serde(rename = "HostConfig", default)]
    pub host_config: DockerHostConfig,
    #[serde(rename = "Mounts", default)]
    pub mounts: Vec<DockerMount>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DockerInspectConfig {
    #[serde(rename = "Image", default)]
    pub image: String,
    #[serde(rename = "User", default)]
    pub user: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DockerHostConfig {
    #[serde(rename = "Privileged", default)]
    pub privileged: bool,
    #[serde(rename = "CapAdd", default)]
    pub cap_add: Option<Vec<String>>,
    #[serde(rename = "PidMode", default)]
    pub pid_mode: String,
    #[serde(rename = "NetworkMode", default)]
    pub network_mode: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DockerMount {
    #[serde(rename = "Source", default)]
    pub source: String,
    #[serde(rename = "Destination", default)]
    pub destination: String,
}

/// One line of the `/events` stream.
#[derive(Debug, Clone, Deserialize)]
pub struct DockerEventMessage {
    #[serde(rename = "Type", default)]
    pub kind: String,
    #[serde(rename = "Action", default)]
    pub action: String,
    #[serde(rename = "Actor", default)]
    pub actor: DockerEventActor,
    #[serde(default)]
    pub time: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DockerEventActor {
    #[serde(rename = "ID", default)]
    pub id: String,
    #[serde(rename = "Attributes", default)]
    pub attributes: HashMap<String, String>,
}

impl DockerClient {
    /// Build a client bound to the configured socket path. This does not
    /// itself open a connection; each request dials fresh.
    pub fn connect(config: &ContainerRuntimeConfig) -> Result<Self, String> {
        Ok(Self {
            socket_path: config.docker_socket_path.clone(),
            timeout: Duration::from_secs(config.docker_timeout_secs.max(1)),
        })
    }

    fn dial(&self) -> Result<UnixStream, String> {
        let stream = UnixStream::connect(&self.socket_path)
            .map_err(|e| format!("connect {}: {e}", self.socket_path))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("set_read_timeout: {e}"))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("set_write_timeout: {e}"))?;
        Ok(stream)
    }

    /// Issue a simple (non-streaming) GET and return the parsed JSON body.
    fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, String> {
        let body = self.get_body(path)?;
        serde_json::from_slice(&body).map_err(|e| format!("decode {path}: {e}"))
    }

    fn get_body(&self, path: &str) -> Result<Vec<u8>, String> {
        let mut stream = self.dial()?;
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("write request: {e}"))?;
        let mut reader = BufReader::new(stream);
        let status = read_status_line(&mut reader)?;
        let headers = read_headers(&mut reader)?;
        if status.code < 200 || status.code >= 300 {
            return Err(format!(
                "HTTP {} from {path}: {}",
                status.code, status.reason
            ));
        }
        read_full_body(&mut reader, &headers)
    }

    /// `GET /_ping` — returns Ok(()) if the daemon answers.
    pub fn ping(&self) -> Result<(), String> {
        self.get_body("/_ping").map(|_| ())
    }

    /// `GET /version`.
    pub fn version(&self) -> Result<DockerVersion, String> {
        self.get_json("/version")
    }

    /// `GET /containers/json?all=1`.
    pub fn list_containers(&self) -> Result<Vec<DockerContainerSummary>, String> {
        self.get_json("/containers/json?all=1")
    }

    /// `GET /containers/{id}/json`.
    pub fn inspect_container(&self, id: &str) -> Result<DockerInspect, String> {
        self.get_json(&format!("/containers/{id}/json"))
    }

    /// Open the `/events` stream and return a reader that yields one
    /// decoded [`DockerEventMessage`] per call to `next_event`. `since`
    /// (Unix seconds) resumes from a prior cursor; pass `None` for "now".
    pub fn events_stream(&self, since: Option<i64>) -> Result<DockerEventStream, String> {
        let mut stream = self.dial()?;
        // The events stream has no natural end, so a finite read timeout
        // would spuriously abort it; the caller drives reconnects instead.
        stream
            .set_read_timeout(None)
            .map_err(|e| format!("set_read_timeout: {e}"))?;
        let path = match since {
            Some(s) => format!("/events?since={s}"),
            None => "/events".to_string(),
        };
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("write request: {e}"))?;
        let mut reader = BufReader::new(stream);
        let status = read_status_line(&mut reader)?;
        let headers = read_headers(&mut reader)?;
        if status.code < 200 || status.code >= 300 {
            return Err(format!(
                "HTTP {} from {path}: {}",
                status.code, status.reason
            ));
        }
        let chunked = headers
            .get("transfer-encoding")
            .map(|v| v.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false);
        Ok(DockerEventStream {
            reader,
            chunked,
            last_event_time: since.unwrap_or(0),
        })
    }
}

/// Iterator-like handle over a live `/events` HTTP response body.
pub struct DockerEventStream {
    reader: BufReader<UnixStream>,
    chunked: bool,
    last_event_time: i64,
}

impl DockerEventStream {
    /// Cursor to resume from (`since=`) on reconnect.
    pub fn resume_since(&self) -> i64 {
        self.last_event_time
    }

    /// Block for the next decoded event, or `Ok(None)` on clean EOF.
    pub fn next_event(&mut self) -> Result<Option<DockerEventMessage>, String> {
        loop {
            let chunk = if self.chunked {
                read_one_chunk(&mut self.reader)?
            } else {
                let mut line = String::new();
                let n = read_line_bounded(&mut self.reader, &mut line, MAX_EVENT_LINE_LEN)?;
                if n == 0 {
                    None
                } else {
                    Some(line.into_bytes())
                }
            };
            let Some(bytes) = chunk else {
                return Ok(None);
            };
            let text = std::str::from_utf8(&bytes).unwrap_or("").trim();
            if text.is_empty() {
                continue;
            }
            match serde_json::from_str::<DockerEventMessage>(text) {
                Ok(ev) => {
                    if ev.time > 0 {
                        self.last_event_time = ev.time;
                    }
                    return Ok(Some(ev));
                }
                Err(e) => return Err(format!("decode event {text:?}: {e}")),
            }
        }
    }
}

// ── Peer-controlled size limits ───────────────────────────────────────
//
// The Docker/Podman Engine API is reached over a local Unix socket, but
// the daemon on the other end is still an untrusted peer as far as this
// client's parsing is concerned (a compromised or misbehaving daemon, or
// a socket pointed at the wrong thing, could send an attacker-chosen
// response). None of these values were previously bounded, so a peer
// could make this client allocate an arbitrarily large buffer from a
// single length field, or stall it reading an unbounded header/status
// line. libcurl and most HTTP clients apply similar caps by default.

/// Maximum size of a single decoded HTTP body (Content-Length or the sum
/// of chunked-transfer chunks).
const MAX_BODY_LEN: usize = 16 * 1024 * 1024;
/// Maximum size of a single chunked-transfer-encoding chunk.
const MAX_CHUNK_LEN: usize = 8 * 1024 * 1024;
/// Maximum length of a single line (status line, header line, or
/// chunk-size line), including its terminator.
const MAX_LINE_LEN: usize = 8 * 1024;
/// Maximum number of headers accepted in one response.
const MAX_HEADER_COUNT: usize = 100;
/// Maximum length of one newline-delimited JSON event line from the
/// (non-chunked) Docker events stream. Generous compared to a real
/// Docker event, but still bounded so a misbehaving daemon cannot stall
/// this client on an unterminated line.
const MAX_EVENT_LINE_LEN: usize = 1024 * 1024;

/// Read one line via `BufRead::read_line`, but never more than `max_len`
/// bytes: `reader` is wrapped in a `Take` for the call so a peer that
/// never sends a newline cannot force an unbounded read/allocation.
/// Returns the number of bytes read, like `read_line` itself (`0` at
/// EOF), or an error if the line exceeds `max_len` without terminating.
fn read_line_bounded<R: BufRead>(
    reader: &mut R,
    buf: &mut String,
    max_len: usize,
) -> Result<usize, String> {
    let n = reader
        .by_ref()
        .take(max_len as u64)
        .read_line(buf)
        .map_err(|e| format!("read line: {e}"))?;
    if n as u64 >= max_len as u64 && !buf.ends_with('\n') {
        return Err(format!("line exceeds the {max_len}-byte limit"));
    }
    Ok(n)
}

fn read_one_chunk<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>, String> {
    let mut size_line = String::new();
    loop {
        size_line.clear();
        let n = read_line_bounded(reader, &mut size_line, MAX_LINE_LEN)?;
        if n == 0 {
            return Ok(None);
        }
        if !size_line.trim().is_empty() {
            break;
        }
    }
    let size_str = size_line.trim().split(';').next().unwrap_or("").trim();
    let size = usize::from_str_radix(size_str, 16)
        .map_err(|e| format!("bad chunk size {size_str:?}: {e}"))?;
    if size == 0 {
        return Ok(None);
    }
    if size > MAX_CHUNK_LEN {
        return Err(format!(
            "chunk size {size} exceeds the {MAX_CHUNK_LEN}-byte limit"
        ));
    }
    let mut buf = vec![0u8; size];
    reader
        .read_exact(&mut buf)
        .map_err(|e| format!("read chunk body: {e}"))?;
    let mut crlf = [0u8; 2];
    reader
        .read_exact(&mut crlf)
        .map_err(|e| format!("read chunk trailer: {e}"))?;
    Ok(Some(buf))
}

#[derive(Debug)]
struct StatusLine {
    code: u16,
    reason: String,
}

fn read_status_line<R: BufRead>(reader: &mut R) -> Result<StatusLine, String> {
    let mut line = String::new();
    read_line_bounded(reader, &mut line, MAX_LINE_LEN)?;
    let line = line.trim();
    let mut parts = line.splitn(3, ' ');
    let _http_version = parts.next().unwrap_or("");
    let code: u16 = parts
        .next()
        .unwrap_or("")
        .parse()
        .map_err(|_| format!("malformed status line {line:?}"))?;
    let reason = parts.next().unwrap_or("").to_string();
    Ok(StatusLine { code, reason })
}

fn read_headers<R: BufRead>(reader: &mut R) -> Result<HashMap<String, String>, String> {
    let mut headers = HashMap::new();
    loop {
        if headers.len() >= MAX_HEADER_COUNT {
            return Err(format!(
                "response has more than the {MAX_HEADER_COUNT}-header limit"
            ));
        }
        let mut line = String::new();
        read_line_bounded(reader, &mut line, MAX_LINE_LEN)?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    Ok(headers)
}

fn read_full_body<R: BufRead>(
    reader: &mut R,
    headers: &HashMap<String, String>,
) -> Result<Vec<u8>, String> {
    let chunked = headers
        .get("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);
    if chunked {
        let mut body = Vec::new();
        loop {
            let mut size_line = String::new();
            read_line_bounded(reader, &mut size_line, MAX_LINE_LEN)?;
            let size_str = size_line.trim().split(';').next().unwrap_or("").trim();
            if size_str.is_empty() {
                continue;
            }
            let size = usize::from_str_radix(size_str, 16)
                .map_err(|e| format!("bad chunk size {size_str:?}: {e}"))?;
            if size == 0 {
                // Drain trailing headers (if any) then the final CRLF.
                let mut trailer = String::new();
                let _ = read_line_bounded(reader, &mut trailer, MAX_LINE_LEN);
                break;
            }
            if size > MAX_CHUNK_LEN {
                return Err(format!(
                    "chunk size {size} exceeds the {MAX_CHUNK_LEN}-byte limit"
                ));
            }
            if body.len().saturating_add(size) > MAX_BODY_LEN {
                return Err(format!(
                    "chunked body exceeds the {MAX_BODY_LEN}-byte limit"
                ));
            }
            let mut buf = vec![0u8; size];
            reader
                .read_exact(&mut buf)
                .map_err(|e| format!("read chunk body: {e}"))?;
            body.extend_from_slice(&buf);
            let mut crlf = [0u8; 2];
            reader
                .read_exact(&mut crlf)
                .map_err(|e| format!("read chunk trailer: {e}"))?;
        }
        return Ok(body);
    }
    if let Some(len) = headers.get("content-length").and_then(|v| v.parse().ok()) {
        if len > MAX_BODY_LEN {
            return Err(format!(
                "content-length {len} exceeds the {MAX_BODY_LEN}-byte limit"
            ));
        }
        let mut buf = vec![0u8; len];
        reader
            .read_exact(&mut buf)
            .map_err(|e| format!("read body: {e}"))?;
        return Ok(buf);
    }
    let mut buf = Vec::new();
    reader
        .take(MAX_BODY_LEN as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read body to end: {e}"))?;
    if buf.len() > MAX_BODY_LEN {
        return Err(format!("body exceeds the {MAX_BODY_LEN}-byte limit"));
    }
    Ok(buf)
}

// ── Mapping Docker facts into the detection model ───────────────────

/// Convert a container inspect result into the container events that
/// would explain its current configuration, so the same
/// [`crate::container::ContainerDetector`] rules used for live events
/// also cover state observed via `/containers/{id}/json`.
pub fn inspect_to_events(
    inspect: &DockerInspect,
    hostname: &str,
    now_ms: u64,
) -> Vec<ContainerEvent> {
    let mut events = Vec::new();
    let name = inspect.name.trim_start_matches('/').to_string();
    let image = if inspect.config.image.is_empty() {
        inspect.id.clone()
    } else {
        inspect.config.image.clone()
    };
    let base = |kind: ContainerEventKind, details: HashMap<String, String>| ContainerEvent {
        timestamp_ms: now_ms,
        kind,
        container_id: inspect.id.clone(),
        container_name: name.clone(),
        image: image.clone(),
        hostname: hostname.to_string(),
        namespace: None,
        user: if inspect.config.user.is_empty() {
            None
        } else {
            Some(inspect.config.user.clone())
        },
        command: None,
        details,
        agent_id: None,
    };

    if inspect.host_config.privileged {
        events.push(base(ContainerEventKind::PrivilegedRun, HashMap::new()));
    }
    if inspect.host_config.pid_mode == "host" || inspect.host_config.network_mode == "host" {
        let mut details = HashMap::new();
        details.insert("pid_mode".into(), inspect.host_config.pid_mode.clone());
        details.insert(
            "network_mode".into(),
            inspect.host_config.network_mode.clone(),
        );
        events.push(base(ContainerEventKind::NamespaceEscape, details));
    }
    if let Some(caps) = &inspect.host_config.cap_add {
        for cap in caps {
            let mut details = HashMap::new();
            details.insert("capability".into(), cap.clone());
            events.push(base(ContainerEventKind::CapabilityAdded, details));
        }
    }
    for mount in &inspect.mounts {
        let mut details = HashMap::new();
        details.insert("mount_path".into(), mount.destination.clone());
        details.insert("source".into(), mount.source.clone());
        events.push(base(ContainerEventKind::VolumeMount, details));
    }
    events
}

/// Convert a `/events` stream message into a [`ContainerEvent`], when it
/// is one of the kinds this platform tracks. Returns `None` for event
/// types outside the documented scope (container start/die,
/// exec_create/exec_start, image pull, network connect).
pub fn docker_event_to_container_event(
    msg: &DockerEventMessage,
    hostname: &str,
) -> Option<ContainerEvent> {
    let kind = match (msg.kind.as_str(), msg.action.as_str()) {
        ("container", "start") => ContainerEventKind::ContainerStart,
        ("container", "die") => ContainerEventKind::ContainerStop,
        ("container", a) if a == "exec_create" || a.starts_with("exec_start") => {
            ContainerEventKind::ContainerExec
        }
        ("image", "pull") => ContainerEventKind::ImagePull,
        ("network", "connect") => ContainerEventKind::VolumeMount,
        _ => return None,
    };
    let name = msg
        .actor
        .attributes
        .get("name")
        .cloned()
        .unwrap_or_default();
    let image = msg
        .actor
        .attributes
        .get("image")
        .cloned()
        .unwrap_or_default();
    let command = msg.actor.attributes.get("execID").cloned().or_else(|| {
        msg.actor
            .attributes
            .get("com.docker.compose.command")
            .cloned()
    });
    Some(ContainerEvent {
        timestamp_ms: (msg.time.max(0) as u64).saturating_mul(1000),
        kind,
        container_id: msg.actor.id.clone(),
        container_name: name,
        image,
        hostname: hostname.to_string(),
        namespace: None,
        user: None,
        command,
        details: msg.actor.attributes.clone(),
        agent_id: None,
    })
}

// ── Kubernetes in-cluster client (best-effort; see module docs) ────

const KUBE_SA_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

/// In-cluster Kubernetes API client.
#[derive(Debug)]
pub struct KubeClient {
    api_server: String,
    token: String,
    #[allow(dead_code)]
    ca_path: String,
}

impl KubeClient {
    /// Detect whether the process is running inside a Kubernetes pod
    /// (`KUBERNETES_SERVICE_HOST` set and the serviceaccount token/CA
    /// present) and, if so, build a client from the mounted
    /// serviceaccount credentials.
    pub fn in_cluster() -> Result<Self, String> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST")
            .map_err(|_| "KUBERNETES_SERVICE_HOST not set".to_string())?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
        let token_path = format!("{KUBE_SA_DIR}/token");
        let ca_path = format!("{KUBE_SA_DIR}/ca.crt");
        let token = std::fs::read_to_string(&token_path)
            .map_err(|e| format!("read {token_path}: {e}"))?
            .trim()
            .to_string();
        if !std::path::Path::new(&ca_path).exists() {
            return Err(format!("missing serviceaccount CA at {ca_path}"));
        }
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        Ok(Self {
            api_server: format!("https://{host}:{port}"),
            token,
            ca_path,
        })
    }

    /// Watch Pods across the configured namespaces (or cluster-wide when
    /// empty), starting from `resource_version` (empty = "now").
    ///
    /// KNOWN LIMITATION: this crate's `ureq` is used without a direct
    /// `rustls` dependency to build a `RootCertStore` containing the
    /// cluster's serviceaccount CA, so the TLS handshake against a real
    /// in-cluster API server (which serves that CA, not one in the
    /// public trust store) will fail here with a certificate error. The
    /// request is still issued (and this failure mode is what callers
    /// should expect and log) so that wiring in a custom trust anchor
    /// later is a localized change to this one method.
    pub fn watch_pods(
        &self,
        namespace: Option<&str>,
        resource_version: &str,
    ) -> Result<String, String> {
        let path = match namespace {
            Some(ns) => format!("{}/api/v1/namespaces/{}/pods", self.api_server, ns),
            None => format!("{}/api/v1/pods", self.api_server),
        };
        let mut req = ureq::get(&path).query("watch", "1");
        if !resource_version.is_empty() {
            req = req.query("resourceVersion", resource_version);
        }
        let resp = req
            .set("Authorization", &format!("Bearer {}", self.token))
            .timeout(Duration::from_secs(30))
            .call()
            .map_err(|e| format!("kubernetes watch request failed: {e}"))?;
        resp.into_string()
            .map_err(|e| format!("read kubernetes watch response: {e}"))
    }
}

/// A Kubernetes `WatchEvent` envelope, generic enough for the Pod
/// fields this platform inspects.
#[derive(Debug, Clone, Deserialize)]
pub struct KubeWatchEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub object: KubePod,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct KubePod {
    #[serde(default)]
    pub metadata: KubeMetadata,
    #[serde(default)]
    pub spec: KubePodSpec,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct KubeMetadata {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(rename = "resourceVersion", default)]
    pub resource_version: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct KubePodSpec {
    #[serde(rename = "hostPID", default)]
    pub host_pid: bool,
    #[serde(rename = "hostNetwork", default)]
    pub host_network: bool,
    #[serde(default)]
    pub containers: Vec<KubeContainerSpec>,
    #[serde(default)]
    pub volumes: Vec<KubeVolume>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct KubeContainerSpec {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub image: String,
    #[serde(rename = "securityContext", default)]
    pub security_context: Option<KubeSecurityContext>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct KubeSecurityContext {
    #[serde(default)]
    pub privileged: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct KubeVolume {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "hostPath", default)]
    pub host_path: Option<KubeHostPath>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct KubeHostPath {
    #[serde(default)]
    pub path: String,
}

/// Parse one line of a Kubernetes watch stream (`ADDED`/`MODIFIED`/…)
/// into container events for the existing detection rules: privileged
/// containers, `hostPID`/`hostNetwork`, and `hostPath` mounts.
pub fn kube_watch_line_to_events(
    line: &str,
    hostname: &str,
    now_ms: u64,
) -> Result<Vec<ContainerEvent>, String> {
    let event: KubeWatchEvent =
        serde_json::from_str(line).map_err(|e| format!("decode kube watch event: {e}"))?;
    let pod = &event.object;
    let mut events = Vec::new();

    let container_id = format!("{}/{}", pod.metadata.namespace, pod.metadata.name);
    let image = pod
        .spec
        .containers
        .first()
        .map(|c| c.image.clone())
        .unwrap_or_default();

    let base = |kind: ContainerEventKind, details: HashMap<String, String>| ContainerEvent {
        timestamp_ms: now_ms,
        kind,
        container_id: container_id.clone(),
        container_name: pod.metadata.name.clone(),
        image: image.clone(),
        hostname: hostname.to_string(),
        namespace: Some(pod.metadata.namespace.clone()),
        user: None,
        command: None,
        details,
        agent_id: None,
    };

    if pod
        .spec
        .containers
        .iter()
        .any(|c| c.security_context.as_ref().and_then(|s| s.privileged) == Some(true))
    {
        events.push(base(ContainerEventKind::PrivilegedRun, HashMap::new()));
    }
    if pod.spec.host_pid || pod.spec.host_network {
        let mut details = HashMap::new();
        details.insert("hostPID".into(), pod.spec.host_pid.to_string());
        details.insert("hostNetwork".into(), pod.spec.host_network.to_string());
        events.push(base(ContainerEventKind::NamespaceEscape, details));
    }
    for vol in &pod.spec.volumes {
        if let Some(hp) = &vol.host_path {
            let mut details = HashMap::new();
            details.insert("mount_path".into(), hp.path.clone());
            details.insert("volume_name".into(), vol.name.clone());
            events.push(base(ContainerEventKind::VolumeMount, details));
        }
    }
    Ok(events)
}

// ── Tests ────────────────────────────────────────────────────────────

/// The Docker Engine API is reached over a Unix socket. Windows Docker
/// Desktop exposes it on a named pipe instead, which this client does not
/// implement yet, so on non-Unix targets every dial fails with a clear
/// error and the watch loop reports the runtime as unreachable.
#[cfg(not(unix))]
mod unsupported_transport {
    use std::io;
    use std::path::Path;
    use std::time::Duration;

    pub struct UnixStream(());

    impl UnixStream {
        pub fn connect<P: AsRef<Path>>(_path: P) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Docker Engine API over a Unix socket is not available on this platform \
                 (named-pipe transport not implemented)",
            ))
        }

        pub fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        pub fn set_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
    }

    impl io::Read for UnixStream {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl io::Write for UnixStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::thread;

    /// Spawn a tiny fake Docker daemon on a temp Unix socket that
    /// answers a fixed script of requests: `/_ping`, `/version`,
    /// `/containers/json`, `/containers/{id}/json`, and a chunked
    /// `/events` stream. Returns the socket path.
    /// Unix socket paths are limited to ~104 bytes (SUN_LEN) on macOS, and
    /// its per-user `temp_dir()` under /var/folders is long enough to exceed
    /// that once the socket name is appended, so keep test sockets in /tmp.
    fn fake_docker_socket_dir() -> std::path::PathBuf {
        std::path::PathBuf::from("/tmp").join(format!("wdx-docker-{}", std::process::id()))
    }

    fn spawn_fake_docker() -> String {
        let dir = fake_docker_socket_dir();
        let _ = std::fs::create_dir_all(&dir);
        let sock_path = dir.join(format!("docker-{}.sock", rand_suffix()));
        let sock_path_str = sock_path.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&sock_path);
        let listener = UnixListener::bind(&sock_path).expect("bind fake docker socket");

        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req
                    .lines()
                    .next()
                    .unwrap_or("")
                    .split(' ')
                    .nth(1)
                    .unwrap_or("");

                if path == "/_ping" {
                    write_simple_response(&mut stream, 200, "OK");
                } else if path == "/version" {
                    write_json_response(&mut stream, r#"{"Version":"24.0.0","ApiVersion":"1.43"}"#);
                } else if path.starts_with("/containers/json") {
                    write_json_response(
                        &mut stream,
                        r#"[{"Id":"abc123","Image":"nginx:latest","Names":["/web"]}]"#,
                    );
                } else if path.starts_with("/containers/") && path.ends_with("/json") {
                    write_json_response(
                        &mut stream,
                        r#"{"Id":"abc123","Name":"/web","Config":{"Image":"nginx:latest","User":""},
                           "HostConfig":{"Privileged":true,"CapAdd":["SYS_ADMIN"],"PidMode":"host","NetworkMode":"host"},
                           "Mounts":[{"Source":"/var/run/docker.sock","Destination":"/var/run/docker.sock"}]}"#,
                    );
                } else if path.starts_with("/events") {
                    write_chunked_events(&mut stream);
                } else {
                    write_simple_response(&mut stream, 404, "Not Found");
                }
            }
        });

        // Give the listener thread a moment to be ready to accept.
        thread::sleep(Duration::from_millis(30));
        sock_path_str
    }

    fn rand_suffix() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    fn write_simple_response(stream: &mut UnixStream, code: u16, reason: &str) {
        let body = "";
        let resp = format!(
            "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(resp.as_bytes());
    }

    fn write_json_response(stream: &mut UnixStream, body: &str) {
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(resp.as_bytes());
    }

    fn write_chunked_events(stream: &mut UnixStream) {
        let header = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(header.as_bytes());
        let events = [
            r#"{"Type":"container","Action":"start","Actor":{"ID":"abc123","Attributes":{"name":"web","image":"nginx"}},"time":1000}"#,
            r#"{"Type":"container","Action":"die","Actor":{"ID":"abc123","Attributes":{"name":"web","image":"nginx"}},"time":1001}"#,
        ];
        for ev in events {
            let chunk = format!("{ev}\n");
            let _ = write!(stream, "{:x}\r\n{}\r\n", chunk.len(), chunk);
        }
        // Terminating chunk.
        let _ = stream.write_all(b"0\r\n\r\n");
    }

    #[test]
    fn ping_and_version() {
        let sock = spawn_fake_docker();
        let cfg = ContainerRuntimeConfig {
            docker_socket_path: sock,
            docker_enabled: true,
            ..Default::default()
        };
        let client = DockerClient::connect(&cfg).expect("connect");
        client.ping().expect("ping");
        let v = client.version().expect("version");
        assert_eq!(v.version, "24.0.0");
    }

    #[test]
    fn list_and_inspect_maps_to_detection_events() {
        let sock = spawn_fake_docker();
        let cfg = ContainerRuntimeConfig {
            docker_socket_path: sock,
            docker_enabled: true,
            ..Default::default()
        };
        let client = DockerClient::connect(&cfg).expect("connect");
        let containers = client.list_containers().expect("list");
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].id, "abc123");

        let inspect = client.inspect_container("abc123").expect("inspect");
        assert!(inspect.host_config.privileged);
        let events = inspect_to_events(&inspect, "test-host", 1_700_000_000_000);
        assert!(
            events
                .iter()
                .any(|e| e.kind == ContainerEventKind::PrivilegedRun)
        );
        assert!(
            events
                .iter()
                .any(|e| e.kind == ContainerEventKind::NamespaceEscape)
        );
        assert!(
            events
                .iter()
                .any(|e| e.kind == ContainerEventKind::CapabilityAdded)
        );
        assert!(
            events
                .iter()
                .any(|e| e.kind == ContainerEventKind::VolumeMount)
        );

        // Feed into the real detector to prove end-to-end wiring.
        let mut detector = crate::container::ContainerDetector::new();
        for ev in events {
            detector.record_event(ev);
        }
        assert!(!detector.alerts().is_empty());
    }

    #[test]
    fn events_stream_parses_chunked_json_and_resumes() {
        let sock = spawn_fake_docker();
        let cfg = ContainerRuntimeConfig {
            docker_socket_path: sock,
            docker_enabled: true,
            ..Default::default()
        };
        let client = DockerClient::connect(&cfg).expect("connect");
        let mut stream = client.events_stream(None).expect("events stream");

        let first = stream.next_event().expect("read").expect("some event");
        assert_eq!(first.action, "start");
        let mapped = docker_event_to_container_event(&first, "host-1").expect("mapped");
        assert_eq!(mapped.kind, ContainerEventKind::ContainerStart);

        let second = stream.next_event().expect("read").expect("some event");
        assert_eq!(second.action, "die");
        assert_eq!(stream.resume_since(), 1001);

        let eof = stream.next_event().expect("read");
        assert!(eof.is_none());
    }

    #[test]
    fn probe_status_reports_disabled_when_not_enabled() {
        let cfg = ContainerRuntimeConfig::default();
        let status = probe_status(&cfg);
        assert_eq!(status.docker_status, RuntimeStatus::Disabled);
        assert_eq!(status.kubernetes_status, RuntimeStatus::Disabled);
    }

    #[test]
    fn probe_status_reports_unreachable_for_missing_socket() {
        let cfg = ContainerRuntimeConfig {
            docker_enabled: true,
            docker_socket_path: "/tmp/wardex-does-not-exist.sock".into(),
            ..Default::default()
        };
        let status = probe_status(&cfg);
        assert_eq!(status.docker_status, RuntimeStatus::Unreachable);
        assert!(status.docker_error.is_some());
    }

    #[test]
    fn kube_watch_line_parses_privileged_hostpath_pod() {
        let line = r#"{"type":"ADDED","object":{"metadata":{"name":"evil-pod","namespace":"default","resourceVersion":"123"},"spec":{"hostPID":true,"hostNetwork":false,"containers":[{"name":"c1","image":"alpine","securityContext":{"privileged":true}}],"volumes":[{"name":"root","hostPath":{"path":"/"}}]}}}"#;
        let events = kube_watch_line_to_events(line, "node-1", 1_700_000_000_000).expect("parse");
        assert!(
            events
                .iter()
                .any(|e| e.kind == ContainerEventKind::PrivilegedRun)
        );
        assert!(
            events
                .iter()
                .any(|e| e.kind == ContainerEventKind::NamespaceEscape)
        );
        assert!(
            events
                .iter()
                .any(|e| e.kind == ContainerEventKind::VolumeMount
                    && e.details.get("mount_path") == Some(&"/".to_string()))
        );
    }

    #[test]
    fn kube_watch_line_benign_pod_has_no_findings() {
        let line = r#"{"type":"ADDED","object":{"metadata":{"name":"nginx","namespace":"default","resourceVersion":"1"},"spec":{"hostPID":false,"hostNetwork":false,"containers":[{"name":"c1","image":"nginx"}],"volumes":[]}}}"#;
        let events = kube_watch_line_to_events(line, "node-1", 1_700_000_000_000).expect("parse");
        assert!(events.is_empty());
    }

    #[test]
    fn kube_watch_line_rejects_garbage() {
        let err = kube_watch_line_to_events("not json", "node-1", 0).unwrap_err();
        assert!(err.contains("decode kube watch event"));
    }

    #[test]
    fn in_cluster_detection_fails_cleanly_outside_a_pod() {
        // SAFETY-equivalent: this test only removes env vars for its own
        // process to exercise the "not in a pod" path; it does not touch
        // other tests' state persistently since each test process is
        // independent under `cargo test`.
        // Note: KUBERNETES_SERVICE_HOST is normally unset in CI/dev.
        if std::env::var("KUBERNETES_SERVICE_HOST").is_err() {
            let err = KubeClient::in_cluster().unwrap_err();
            assert!(err.contains("KUBERNETES_SERVICE_HOST"));
        }
    }

    #[test]
    fn podman_socket_path_uses_uid() {
        assert_eq!(
            podman_socket_path_for_uid(1000),
            "/run/user/1000/podman/podman.sock"
        );
    }

    // ── Peer size-limit regression tests ────────────────────────────
    //
    // These exercise `read_status_line`/`read_headers`/`read_full_body`/
    // `read_one_chunk` directly against an in-memory `Cursor`, standing in
    // for a misbehaving daemon that sends oversized values, rather than
    // spinning up a real fake-daemon thread for each case.

    #[test]
    fn read_full_body_rejects_oversized_content_length() {
        let mut headers = HashMap::new();
        headers.insert("content-length".to_string(), "999999999999".to_string());
        let mut reader = std::io::Cursor::new(Vec::<u8>::new());
        let err = read_full_body(&mut reader, &headers).unwrap_err();
        assert!(err.contains("exceeds"), "unexpected error: {err}");
    }

    #[test]
    fn read_full_body_rejects_oversized_chunk_size() {
        let mut headers = HashMap::new();
        headers.insert("transfer-encoding".to_string(), "chunked".to_string());
        // A chunk-size line claiming far more than MAX_CHUNK_LEN bytes.
        let mut reader = std::io::Cursor::new(b"ffffffff\r\n".to_vec());
        let err = read_full_body(&mut reader, &headers).unwrap_err();
        assert!(err.contains("exceeds"), "unexpected error: {err}");
    }

    #[test]
    fn read_full_body_caps_unbounded_body_without_content_length() {
        // No Content-Length and not chunked: the body is read to EOF, but
        // must still be capped rather than growing without limit for a
        // daemon that streams forever.
        let headers = HashMap::new();
        let oversized = vec![b'a'; MAX_BODY_LEN + 1024];
        let mut reader = std::io::Cursor::new(oversized);
        let err = read_full_body(&mut reader, &headers).unwrap_err();
        assert!(err.contains("exceeds"), "unexpected error: {err}");
    }

    #[test]
    fn read_one_chunk_rejects_oversized_chunk_size() {
        let mut reader = std::io::Cursor::new(b"ffffffff\r\n".to_vec());
        let err = read_one_chunk(&mut reader).unwrap_err();
        assert!(err.contains("exceeds"), "unexpected error: {err}");
    }

    #[test]
    fn read_headers_rejects_too_many_headers() {
        let mut buf = String::new();
        for i in 0..(MAX_HEADER_COUNT + 10) {
            buf.push_str(&format!("X-Header-{i}: v\r\n"));
        }
        buf.push_str("\r\n");
        let mut reader = std::io::Cursor::new(buf.into_bytes());
        let err = read_headers(&mut reader).unwrap_err();
        assert!(err.contains("header"), "unexpected error: {err}");
    }

    #[test]
    fn read_status_line_rejects_oversized_line() {
        // No CRLF terminator within MAX_LINE_LEN bytes.
        let long = "HTTP/1.1 200 ".to_string() + &"A".repeat(MAX_LINE_LEN * 2);
        let mut reader = std::io::Cursor::new(long.into_bytes());
        let err = read_status_line(&mut reader).unwrap_err();
        assert!(err.contains("exceeds"), "unexpected error: {err}");
    }

    #[test]
    fn read_headers_rejects_oversized_header_line() {
        let long = format!("X-Long: {}", "A".repeat(MAX_LINE_LEN * 2));
        let mut reader = std::io::Cursor::new(long.into_bytes());
        let err = read_headers(&mut reader).unwrap_err();
        assert!(err.contains("exceeds"), "unexpected error: {err}");
    }

    /// End-to-end: a fake daemon that sends a `Content-Length` far beyond
    /// the cap must make `get_json`/`get_body` fail cleanly rather than
    /// allocate gigabytes or hang.
    #[test]
    fn fake_daemon_oversized_content_length_is_rejected() {
        let dir = fake_docker_socket_dir();
        let _ = std::fs::create_dir_all(&dir);
        let sock_path = dir.join(format!("docker-oversize-{}.sock", rand_suffix()));
        let sock_path_str = sock_path.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&sock_path);
        let listener = UnixListener::bind(&sock_path).expect("bind fake docker socket");

        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                // Claim a body far larger than MAX_BODY_LEN, but never
                // actually send that many bytes — a well-behaved client
                // must reject this from the header alone.
                let resp =
                    "HTTP/1.1 200 OK\r\nContent-Length: 999999999999\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        thread::sleep(Duration::from_millis(30));

        let cfg = ContainerRuntimeConfig {
            docker_socket_path: sock_path_str,
            docker_enabled: true,
            ..Default::default()
        };
        let client = DockerClient::connect(&cfg).expect("connect");
        let err = client.ping().unwrap_err();
        assert!(err.contains("exceeds"), "unexpected error: {err}");
    }

    /// Live smoke test against a real Docker daemon, if one happens to be
    /// reachable on this machine. Skipped (not failed) otherwise, per the
    /// task's runtime-skip requirement.
    #[test]
    fn live_docker_socket_if_present() {
        let path = "/var/run/docker.sock";
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping live_docker_socket_if_present: {path} not present");
            return;
        }
        let cfg = ContainerRuntimeConfig {
            docker_enabled: true,
            docker_socket_path: path.into(),
            ..Default::default()
        };
        let Ok(client) = DockerClient::connect(&cfg) else {
            return;
        };
        // Best effort: a real daemon might reject us on permissions; that
        // is not a test failure, just an environment limitation.
        let _ = client.ping();
    }
}
