# Linux Agent Runbook

## Prerequisites

- Linux kernel 4.15+ (5.x+ recommended for eBPF)
- Root or sudo access for installation
- Network access to the SentinelEdge server (default port 9090)
- systemd (for service management)

## Deployment

### 1. Download Agent Binary

```bash
curl -o /tmp/sentineledge-agent \
  "https://<server>:9090/api/updates/download/sentineledge-agent-linux-amd64"
chmod +x /tmp/sentineledge-agent
```

### 2. Enroll Agent

```bash
sudo /tmp/sentineledge-agent enroll \
  --server https://<server>:9090 \
  --token <enrollment-token> \
  --hostname $(hostname) \
  --platform linux
```

### 3. Install as systemd Service

```bash
sudo cp /tmp/sentineledge-agent /usr/local/bin/
sudo mkdir -p /etc/sentineledge /var/lib/sentineledge

cat << 'EOF' | sudo tee /etc/systemd/system/sentineledge-agent.service
[Unit]
Description=SentinelEdge XDR Agent
After=network.target auditd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/sentineledge-agent --run --config /etc/sentineledge/config.toml
Restart=always
RestartSec=10
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now sentineledge-agent
```

## Telemetry Sources

| Source | Data Collected | Requirements |
|--------|---------------|-------------|
| /proc filesystem | Process list, network sockets, CPU/memory | Always available |
| auditd | Syscall auditing, file access, execve | `auditd` package |
| eBPF | Low-overhead tracing (process, network, file) | Kernel 5.x+, `bpftool` |
| fanotify | File access monitoring | Kernel 4.15+ |
| /proc/net/tcp,udp | Network socket enumeration | Always available |
| resolv.conf | DNS configuration monitoring | Always available |

### auditd Configuration

For comprehensive auditing, add these rules:

```bash
cat << 'EOF' | sudo tee /etc/audit/rules.d/sentineledge.rules
# Process execution
-a always,exit -F arch=b64 -S execve -k sentineledge_exec
# File modifications in sensitive paths
-w /etc/passwd -p wa -k sentineledge_identity
-w /etc/shadow -p wa -k sentineledge_identity
-w /etc/sudoers -p wa -k sentineledge_priv
-w /etc/crontab -p wa -k sentineledge_persist
-w /var/spool/cron/ -p wa -k sentineledge_persist
# Kernel module loading
-a always,exit -F arch=b64 -S init_module -S finit_module -k sentineledge_kernel
# Privilege escalation
-a always,exit -F arch=b64 -S setuid -S setgid -k sentineledge_priv_esc
EOF

sudo augenrules --load
sudo systemctl restart auditd
```

### eBPF Configuration (Kernel 5.x+)

Enable eBPF-based tracing for lower overhead:

```toml
[collectors]
ebpf_enabled = true
ebpf_programs = ["execsnoop", "tcpconnect", "filelife"]
```

Verify eBPF support:
```bash
# Check kernel support
bpftool feature probe kernel
# Check required capabilities
capsh --print | grep bpf
```

## Container Integration

### Docker

The agent detects Docker containers via cgroup paths:

```bash
# Verify Docker socket access
ls -la /var/run/docker.sock

# If running agent in a container, mount required paths:
docker run -d \
  --name sentineledge-agent \
  --privileged \
  --pid=host \
  --net=host \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  sentineledge/agent:latest
```

### Kubernetes

Deploy as a DaemonSet:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: sentineledge-agent
  namespace: security
spec:
  selector:
    matchLabels:
      app: sentineledge-agent
  template:
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: agent
        image: sentineledge/agent:latest
        securityContext:
          privileged: true
        volumeMounts:
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: sys
          mountPath: /host/sys
          readOnly: true
      volumes:
      - name: proc
        hostPath:
          path: /proc
      - name: sys
        hostPath:
          path: /sys
```

## Privilege Escalation Detection

The agent monitors:

- **SUID/SGID binaries**: Scans for unexpected SUID bit changes
- **Capabilities**: Monitors `CAP_SYS_ADMIN`, `CAP_NET_RAW`, etc.
- **sudo configuration**: Watches `/etc/sudoers` and `/etc/sudoers.d/`
- **cron jobs**: Monitors user and system crontabs

## Troubleshooting

### Agent Not Starting

```bash
# Check service status
sudo systemctl status sentineledge-agent
# View logs
sudo journalctl -u sentineledge-agent -f --no-pager | tail -50
```

### Permission Denied Errors

```bash
# Verify agent runs as root
ps aux | grep sentineledge
# Check SELinux (if applicable)
getenforce
# Temporarily set permissive for testing
sudo setenforce 0
```

### High Memory Usage

```toml
[limits]
max_events_in_memory = 5000
process_scan_interval_secs = 30
network_scan_interval_secs = 15
```

## Uninstallation

```bash
sudo systemctl stop sentineledge-agent
sudo systemctl disable sentineledge-agent
sudo rm /etc/systemd/system/sentineledge-agent.service
sudo systemctl daemon-reload
sudo rm /usr/local/bin/sentineledge-agent
sudo rm -rf /etc/sentineledge /var/lib/sentineledge
```
