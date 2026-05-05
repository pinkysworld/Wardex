import { useState, useMemo, useCallback, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useApi, useApiGroup, useInterval, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import { ConfirmDialog, JsonDetails, SummaryGrid, WorkspaceEmptyState } from './operator.jsx';
import EmptyState from './EmptyState.jsx';
import { formatDateTime, formatRelativeTime } from './operatorUtils.js';
import LocalConsoleInventory from './LocalConsoleInventory.jsx';

const AGENT_COLUMNS = ['id', 'hostname', 'os', 'version', 'status', 'last_seen'];
const PAGE_SIZE_OPTIONS = [10, 25, 50, 100];
const DEFAULT_PAGE_SIZE = 25;
const DEFAULT_INSTALL_TTL_SECS = 24 * 60 * 60;
const SSH_REMOTE_INSTALLABLE_PLATFORMS = new Set(['linux', 'macos']);
const WINRM_REMOTE_INSTALLABLE_PLATFORMS = new Set(['windows']);
const SAVED_VIEWS = [
  { id: 'all', label: 'All Agents', filters: { status: 'all', q: '', os: 'all' } },
  { id: 'offline', label: 'Offline Agents > 1h', filters: { status: 'offline', q: '', os: 'all' } },
  { id: 'linux', label: 'Linux Fleet', filters: { status: 'all', q: '', os: 'linux' } },
];

const INSTALL_ARTIFACTS = {
  linux: {
    fileName: 'wardex-agent-linux-amd64',
    installPath: '/usr/local/bin/wardex-agent',
  },
  macos: {
    fileName: 'wardex-agent-macos-universal',
    installPath: '/usr/local/bin/wardex-agent',
  },
  windows: {
    fileName: 'wardex-agent-windows.exe',
    installPath: 'C:\\Program Files\\Wardex\\wardex-agent.exe',
  },
};

const UPDATE_PANELS = [
  {
    id: 'rollout',
    label: 'Rollout History',
    description: 'Reopen recent deployment history, rollout notes, and policy-change context.',
  },
  {
    id: 'recovery',
    label: 'Recovery',
    description: 'Start with endpoints that need heartbeat or deployment recovery attention.',
  },
  {
    id: 'health',
    label: 'Deployment Health',
    description:
      'Review release drift, rollout targets, and deployment readiness before broad rollout.',
  },
];

const normalizePanelId = (value, panels, fallback) =>
  panels.some((panel) => panel.id === value) ? value : fallback;

function normalizeInstallPlatform(platform) {
  const value = String(platform || '')
    .trim()
    .toLowerCase();
  if (value.includes('darwin') || value.includes('mac')) return 'macos';
  if (value.includes('win')) return 'windows';
  return 'linux';
}

function defaultManagerUrl() {
  if (typeof window === 'undefined') return '';
  return window.location.origin;
}

function quoteShell(value) {
  return `'${String(value || '').replace(/'/g, `'"'"'`)}'`;
}

function quotePowerShell(value) {
  return `'${String(value || '').replace(/'/g, "''")}'`;
}

function quoteToml(value) {
  return `"${String(value || '')
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')}"`;
}

function buildInstallCommand({ hostname, address, managerUrl, platform, token, expiresAt }) {
  const targetPlatform = normalizeInstallPlatform(platform);
  const artifact = INSTALL_ARTIFACTS[targetPlatform] || INSTALL_ARTIFACTS.linux;
  const baseUrl = String(managerUrl || '').replace(/\/$/, '');
  const downloadUrl = `${baseUrl}/api/updates/download/${artifact.fileName}`;
  const metadata = [
    `# Host: ${hostname}`,
    address ? `# Address: ${address}` : null,
    expiresAt ? `# Token expires: ${expiresAt}` : null,
  ]
    .filter(Boolean)
    .join('\n');

  if (targetPlatform === 'windows') {
    return `${metadata}\nNew-Item -ItemType Directory -Force -Path 'C:\\Program Files\\Wardex', 'C:\\ProgramData\\Wardex' | Out-Null\nInvoke-WebRequest -Uri ${quotePowerShell(downloadUrl)} -OutFile '$env:TEMP\\wardex-agent.exe'\nCopy-Item '$env:TEMP\\wardex-agent.exe' ${quotePowerShell(artifact.installPath)} -Force\n@'\n[agent]\nserver_url = ${quoteToml(managerUrl)}\nenrollment_token = ${quoteToml(token)}\n'@ | Set-Content -Path 'C:\\ProgramData\\Wardex\\agent.toml' -Encoding UTF8\nif (Get-Service -Name 'WardexAgent' -ErrorAction SilentlyContinue) {\n  Stop-Service -Name 'WardexAgent' -Force -ErrorAction SilentlyContinue\n  sc.exe delete WardexAgent | Out-Null\n  Start-Sleep -Seconds 2\n}\nNew-Service -Name 'WardexAgent' -BinaryPathName ${quotePowerShell(`${artifact.installPath} agent --config C:\\ProgramData\\Wardex\\agent.toml`)} -DisplayName ${quotePowerShell('Wardex XDR Agent')} -StartupType Automatic\nStart-Service -Name 'WardexAgent'`;
  }

  if (targetPlatform === 'macos') {
    return `${metadata}\ncurl -fsSL -o /tmp/wardex-agent ${quoteShell(downloadUrl)}\nchmod +x /tmp/wardex-agent\nsudo install -m 755 /tmp/wardex-agent ${quoteShell(artifact.installPath)}\nsudo mkdir -p /Library/Application\\ Support/Wardex /Library/Logs/Wardex\ncat <<'EOF' | sudo tee '/Library/Application Support/Wardex/agent.toml' >/dev/null\n[agent]\nserver_url = ${quoteToml(managerUrl)}\nenrollment_token = ${quoteToml(token)}\nEOF\ncat <<'EOF' | sudo tee /Library/LaunchDaemons/com.wardex.agent.plist >/dev/null\n<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n  <key>Label</key>\n  <string>com.wardex.agent</string>\n  <key>ProgramArguments</key>\n  <array>\n    <string>${artifact.installPath}</string>\n    <string>agent</string>\n  </array>\n  <key>EnvironmentVariables</key>\n  <dict>\n    <key>WARDEX_CONFIG_PATH</key>\n    <string>/Library/Application Support/Wardex/agent.toml</string>\n  </dict>\n  <key>RunAtLoad</key>\n  <true/>\n  <key>KeepAlive</key>\n  <true/>\n  <key>StandardOutPath</key>\n  <string>/Library/Logs/Wardex/agent.log</string>\n  <key>StandardErrorPath</key>\n  <string>/Library/Logs/Wardex/agent-error.log</string>\n</dict>\n</plist>\nEOF\nsudo launchctl unload /Library/LaunchDaemons/com.wardex.agent.plist >/dev/null 2>&1 || true\nsudo launchctl load /Library/LaunchDaemons/com.wardex.agent.plist`;
  }

  return `${metadata}\ncurl -fsSL -o /tmp/wardex-agent ${quoteShell(downloadUrl)}\nchmod +x /tmp/wardex-agent\nsudo install -m 755 /tmp/wardex-agent ${quoteShell(artifact.installPath)}\nsudo mkdir -p /etc/wardex /var/lib/wardex\ncat <<'EOF' | sudo tee /etc/wardex/agent.toml >/dev/null\n[agent]\nserver_url = ${quoteToml(managerUrl)}\nenrollment_token = ${quoteToml(token)}\nEOF\ncat <<'EOF' | sudo tee /etc/systemd/system/wardex-agent.service >/dev/null\n[Unit]\nDescription=Wardex XDR Agent\nAfter=network.target auditd.service\n\n[Service]\nType=simple\nEnvironment=WARDEX_CONFIG_PATH=/etc/wardex/agent.toml\nExecStart=${artifact.installPath} agent\nRestart=always\nRestartSec=10\nUser=root\nLimitNOFILE=65536\n\n[Install]\nWantedBy=multi-user.target\nEOF\nsudo systemctl daemon-reload\nsudo systemctl enable --now wardex-agent`;
}

function parseApiErrorPayload(error) {
  if (typeof error?.body !== 'string' || !error.body) return null;
  try {
    return JSON.parse(error.body);
  } catch {
    return null;
  }
}

function MobileAgentCard({ agent, active, onOpen, onCopy }) {
  return (
    <article
      className={`mobile-stack-card ${active ? 'active' : ''}`}
      role="button"
      tabIndex={0}
      onClick={() => onOpen(agent)}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          onOpen(agent);
        }
      }}
    >
      <div className="mobile-card-header">
        <div>
          <div className="mobile-card-title">{agent.hostname}</div>
          <div className="row-secondary">{agent.id}</div>
        </div>
        <span
          className={`badge ${agent.status === 'online' ? 'badge-ok' : agent.status === 'offline' ? 'badge-err' : 'badge-warn'}`}
        >
          {agent.status}
        </span>
      </div>
      <div className="mobile-card-meta">
        <span>{agent.os}</span>
        <span>{agent.version}</span>
        <span>{formatRelativeTime(agent.lastSeen)}</span>
      </div>
      <div className="mobile-card-actions">
        <button
          className="btn btn-sm btn-primary"
          onClick={(event) => {
            event.stopPropagation();
            onOpen(agent);
          }}
        >
          Inspect
        </button>
        <button
          className="btn btn-sm"
          onClick={(event) => {
            event.stopPropagation();
            onCopy(agent);
          }}
        >
          Copy
        </button>
      </div>
    </article>
  );
}

function normalizeAgent(agent, index) {
  const source = agent.agent || agent;
  const id = source.id || source.agent_id || `agent-${index}`;
  return {
    id,
    hostname: source.hostname || source.host || id,
    os: source.os || source.platform || 'unknown',
    version: source.version || '—',
    status: agent.computed_status || source.status || 'unknown',
    lastSeen: source.last_seen || agent.last_seen || agent.last_heartbeat || null,
    isLocalConsole: Boolean(agent.local_console || source.labels?.local_console === 'true'),
    raw: agent,
  };
}

export default function FleetAgents() {
  const toast = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const [tab, setTab] = useState(() => searchParams.get('fleetTab') || 'fleet');
  const updatesPanel = normalizePanelId(searchParams.get('updatesPanel'), UPDATE_PANELS, 'rollout');
  const [query, setQuery] = useState(() => searchParams.get('q') || '');
  const [statusFilter, setStatusFilter] = useState(() => searchParams.get('status') || 'all');
  const [osFilter, setOsFilter] = useState(() => searchParams.get('os') || 'all');
  const [nowMs, setNowMs] = useState(() => Date.now());
  const { data: fleetSurfaceData, reload: reloadFleetSurface } = useApiGroup({
    fleetSt: api.fleetStatus,
    dash: api.fleetDashboard,
    health: api.fleetHealth,
    agentList: api.agents,
    wsStats: api.wsStats,
  });
  const { fleetSt, dash, health: fleetHealthData, agentList, wsStats } = fleetSurfaceData;
  const { data: swarm } = useApi(api.swarmPosture);
  const { data: swarmIntelData } = useApi(api.swarmIntel);
  const { data: plat } = useApi(api.platform);
  const { data: evts, reload: rEvents } = useApi(api.events);
  const { data: evtSum } = useApi(api.eventsSummary);
  const { data: policyHist } = useApi(api.policyHistory);
  const { data: releases } = useApi(api.updatesReleases);
  const { data: rollout } = useApi(api.rolloutConfig);
  const { data: installHistory, reload: reloadInstallHistory } = useApi(api.fleetInstalls);
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [hoveredAgent, setHoveredAgent] = useState(null);
  const [agentDetail, setAgentDetail] = useState(null);
  const [selected, setSelected] = useState(new Set());
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE);
  const [confirmState, setConfirmState] = useState(null);
  const [pendingDelete, setPendingDelete] = useState(null);
  const [focusedRowIndex, setFocusedRowIndex] = useState(0);
  const [installForm, setInstallForm] = useState(() => ({
    hostname: '',
    address: '',
    platform: 'linux',
    managerUrl: defaultManagerUrl(),
    sshUser: 'root',
    sshPort: '22',
    sshIdentityFile: '',
    sshAcceptNewHostKey: true,
    useSudo: true,
    winrmUsername: 'Administrator',
    winrmPassword: '',
    winrmPort: '5985',
    winrmUseTls: false,
    winrmSkipCertCheck: false,
  }));
  const [installBundle, setInstallBundle] = useState(null);
  const [isGeneratingInstallBundle, setIsGeneratingInstallBundle] = useState(false);
  const [latestRemoteInstall, setLatestRemoteInstall] = useState(null);
  const [isRemoteInstalling, setIsRemoteInstalling] = useState(false);
  const [isAssigningRelease, setIsAssigningRelease] = useState(false);
  const [visibleColumns, setVisibleColumns] = useState(() => {
    try {
      const parsed = JSON.parse(localStorage.getItem('wardex_fleet_columns') || 'null');
      if (Array.isArray(parsed) && parsed.length > 0) {
        return AGENT_COLUMNS.filter((column) => parsed.includes(column));
      }
    } catch {
      // Ignore malformed stored values and fall back to defaults.
    }
    return AGENT_COLUMNS;
  });

  useEffect(() => {
    localStorage.setItem('wardex_fleet_columns', JSON.stringify(visibleColumns));
  }, [visibleColumns]);

  const setFleetQueryState = useCallback(
    (updates) => {
      const next = new URLSearchParams(searchParams);
      Object.entries(updates).forEach(([key, value]) => {
        if (!value || value === 'all') next.delete(key);
        else next.set(key, value);
      });
      setSearchParams(next, { replace: true });
    },
    [searchParams, setSearchParams],
  );

  const handleTabChange = useCallback(
    (nextTab) => {
      setTab(nextTab);
      setFleetQueryState({ fleetTab: nextTab });
    },
    [setFleetQueryState],
  );

  useInterval(() => {
    reloadFleetSurface();
    setNowMs(Date.now());
  }, 15000);

  const agentArr = useMemo(
    () => (Array.isArray(agentList) ? agentList : agentList?.agents || []).map(normalizeAgent),
    [agentList],
  );
  const eventArr = Array.isArray(evts) ? evts : evts?.events || [];
  const statusOptions = ['all', ...new Set(agentArr.map((agent) => agent.status))];
  const osOptions = ['all', ...new Set(agentArr.map((agent) => String(agent.os).toLowerCase()))];

  const filteredAgents = useMemo(() => {
    return agentArr.filter((agent) => {
      const matchesQuery =
        !query || JSON.stringify(agent.raw).toLowerCase().includes(query.toLowerCase());
      const matchesStatus = statusFilter === 'all' || agent.status === statusFilter;
      const matchesOs =
        osFilter === 'all' || String(agent.os).toLowerCase().includes(osFilter.toLowerCase());
      if (statusFilter === 'offline' && SAVED_VIEWS[1].filters.status === 'offline') {
        const lastSeenMs = agent.lastSeen ? new Date(agent.lastSeen).getTime() : 0;
        const olderThanHour = !lastSeenMs || nowMs - lastSeenMs > 60 * 60 * 1000;
        return matchesQuery && matchesStatus && matchesOs && olderThanHour;
      }
      return matchesQuery && matchesStatus && matchesOs;
    });
  }, [agentArr, nowMs, osFilter, query, statusFilter]);

  const pagedAgents = useMemo(
    () => filteredAgents.slice(page * pageSize, (page + 1) * pageSize),
    [filteredAgents, page, pageSize],
  );
  const activeRowIndex = Math.min(focusedRowIndex, Math.max(0, pagedAgents.length - 1));
  const totalPages = Math.max(1, Math.ceil(filteredAgents.length / pageSize));
  const hasFleetFilters = statusFilter !== 'all' || osFilter !== 'all' || Boolean(query);

  const currentPreview =
    agentDetail && selectedAgent
      ? { ...normalizeAgent(agentDetail, 0), raw: agentDetail }
      : hoveredAgent;
  const currentPreviewIndex = currentPreview
    ? filteredAgents.findIndex((agent) => agent.id === currentPreview.id)
    : -1;

  const queueHealth = useMemo(
    () => ({
      offline: agentArr.filter((agent) => agent.status === 'offline').length,
      stale: agentArr.filter(
        (agent) => agent.lastSeen && nowMs - new Date(agent.lastSeen).getTime() > 30 * 60 * 1000,
      ).length,
      linux: agentArr.filter((agent) => String(agent.os).toLowerCase().includes('linux')).length,
    }),
    [agentArr, nowMs],
  );
  const offlineAgents = useMemo(
    () => agentArr.filter((agent) => agent.status === 'offline'),
    [agentArr],
  );
  const staleAgents = useMemo(
    () =>
      agentArr.filter(
        (agent) => agent.lastSeen && nowMs - new Date(agent.lastSeen).getTime() > 30 * 60 * 1000,
      ),
    [agentArr, nowMs],
  );
  const recoveryWatchlistAgents = useMemo(() => {
    const offlinePreview = offlineAgents.slice(0, 3);
    const seen = new Set(offlinePreview.map((agent) => agent.id || agent.hostname));
    const stalePreview = staleAgents
      .filter((agent) => {
        const key = agent.id || agent.hostname;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      })
      .slice(0, 3);
    return [...offlinePreview, ...stalePreview];
  }, [offlineAgents, staleAgents]);
  const rolloutHistory = useMemo(
    () =>
      Array.isArray(rollout?.recent_history)
        ? rollout.recent_history
        : Array.isArray(rollout?.history)
          ? rollout.history
          : [],
    [rollout],
  );
  const policyHistoryEntries = useMemo(
    () =>
      Array.isArray(policyHist?.recent_history)
        ? policyHist.recent_history
        : Array.isArray(policyHist)
          ? policyHist
          : [],
    [policyHist],
  );
  const releaseItems = useMemo(
    () =>
      Array.isArray(releases?.items)
        ? releases.items
        : Array.isArray(releases?.releases)
          ? releases.releases
          : Array.isArray(releases)
            ? releases
            : [],
    [releases],
  );
  const latestRelease = useMemo(
    () =>
      releaseItems[0] ||
      (releases?.latest_version
        ? {
            version: releases.latest_version,
            notes: releases?.notes,
            channel: releases?.channel,
          }
        : null),
    [releaseItems, releases],
  );
  const driftAgents = useMemo(() => {
    if (!latestRelease?.version) return [];
    return agentArr.filter((agent) => agent.version && agent.version !== latestRelease.version);
  }, [agentArr, latestRelease]);
  const remoteInstallHistory = useMemo(
    () =>
      Array.isArray(installHistory?.attempts)
        ? installHistory.attempts
        : Array.isArray(installHistory)
          ? installHistory
          : [],
    [installHistory],
  );
  const installPlatform = normalizeInstallPlatform(installForm.platform);
  const isSshRemoteInstall = SSH_REMOTE_INSTALLABLE_PLATFORMS.has(installPlatform);
  const isWinRmRemoteInstall = WINRM_REMOTE_INSTALLABLE_PLATFORMS.has(installPlatform);
  const canRemoteInstall = isSshRemoteInstall || isWinRmRemoteInstall;
  const visibleRemoteInstallHistory = useMemo(() => {
    if (!latestRemoteInstall) return remoteInstallHistory;
    return [
      latestRemoteInstall,
      ...remoteInstallHistory.filter((attempt) => attempt.id !== latestRemoteInstall.id),
    ];
  }, [latestRemoteInstall, remoteInstallHistory]);
  const activeUpdatesPanel = UPDATE_PANELS.find((panel) => panel.id === updatesPanel);
  const selectedDeployableAgent =
    currentPreview && !currentPreview.isLocalConsole ? currentPreview : null;
  const selectedAgentNeedsUpgrade = Boolean(
    selectedDeployableAgent &&
    latestRelease?.version &&
    selectedDeployableAgent.version !== latestRelease.version,
  );

  const clearFleetFilters = useCallback(() => {
    setQuery('');
    setStatusFilter('all');
    setOsFilter('all');
    setPage(0);
    setFleetQueryState({ q: '', status: 'all', os: 'all' });
  }, [setFleetQueryState]);

  const hasColumn = useCallback((column) => visibleColumns.includes(column), [visibleColumns]);

  const toggleColumn = useCallback((column) => {
    setVisibleColumns((current) => {
      if (current.includes(column)) {
        if (current.length === 1) return current;
        return current.filter((candidate) => candidate !== column);
      }
      return [...current, column];
    });
  }, []);

  const openAgent = async (agent) => {
    setSelectedAgent(agent.id);
    setHoveredAgent(agent);
    try {
      const detail = await api.agentDetails(agent.id);
      setAgentDetail(detail);
    } catch {
      setAgentDetail(agent.raw);
    }
  };

  const copyRow = useCallback(
    (agent) => {
      const text = AGENT_COLUMNS.map(
        (column) =>
          `${column}: ${agent.raw[column] || agent.raw[column === 'id' ? 'agent_id' : column] || '—'}`,
      ).join(', ');
      navigator.clipboard.writeText(text).then(() => toast('Copied', 'success'));
    },
    [toast],
  );

  const copyInstallBundle = useCallback(() => {
    if (!installBundle) return;
    navigator.clipboard.writeText(installBundle.command).then(() => {
      toast('Install command copied', 'success');
    });
  }, [installBundle, toast]);

  const handleInstallFormChange = useCallback((field, value) => {
    setInstallForm((current) => ({ ...current, [field]: value }));
  }, []);

  const generateInstallBundle = useCallback(
    async (event) => {
      event.preventDefault();
      const hostname = installForm.hostname.trim();
      const managerUrl = installForm.managerUrl.trim() || defaultManagerUrl();
      if (!hostname) {
        toast('Host name is required before generating an install bundle.', 'warning');
        return;
      }
      if (!managerUrl) {
        toast('Manager URL is required before generating an install bundle.', 'warning');
        return;
      }

      setIsGeneratingInstallBundle(true);
      try {
        const enrollmentToken = await api.agentsToken({
          max_uses: 1,
          ttl_secs: DEFAULT_INSTALL_TTL_SECS,
        });
        const platform = normalizeInstallPlatform(installForm.platform);
        const address = installForm.address.trim();
        const expiresAt = enrollmentToken.expires_at || null;
        setInstallBundle({
          hostname,
          address,
          platform,
          managerUrl,
          token: enrollmentToken.token,
          expiresAt,
          command: buildInstallCommand({
            hostname,
            address,
            managerUrl,
            platform,
            token: enrollmentToken.token,
            expiresAt,
          }),
        });
        toast(`Install bundle ready for ${hostname}.`, 'success');
      } catch {
        toast('Failed to create an install bundle.', 'error');
      } finally {
        setIsGeneratingInstallBundle(false);
      }
    },
    [installForm, toast],
  );

  const runRemoteInstall = useCallback(async () => {
    const hostname = installForm.hostname.trim();
    const address = installForm.address.trim();
    const managerUrl = installForm.managerUrl.trim() || defaultManagerUrl();
    const platform = normalizeInstallPlatform(installForm.platform);

    if (!canRemoteInstall) {
      toast('Remote install is not available for the selected platform.', 'warning');
      return;
    }
    if (!hostname) {
      toast('Host name is required before running a remote install.', 'warning');
      return;
    }
    if (!address) {
      toast('Address or DNS name is required before running a remote install.', 'warning');
      return;
    }
    if (!managerUrl) {
      toast('Manager URL is required before running a remote install.', 'warning');
      return;
    }
    setIsRemoteInstalling(true);
    try {
      let result;
      if (isSshRemoteInstall) {
        const sshUser = installForm.sshUser.trim();
        const sshPort = Number.parseInt(String(installForm.sshPort || '').trim(), 10);
        if (!sshUser) {
          toast('SSH user is required before running a remote install.', 'warning');
          return;
        }
        if (!Number.isInteger(sshPort) || sshPort <= 0) {
          toast('SSH port must be a positive integer.', 'warning');
          return;
        }
        result = await api.fleetInstallSsh({
          hostname,
          address,
          platform,
          manager_url: managerUrl,
          ssh_user: sshUser,
          ssh_port: sshPort,
          ssh_identity_file: installForm.sshIdentityFile.trim() || undefined,
          ssh_accept_new_host_key: Boolean(installForm.sshAcceptNewHostKey),
          use_sudo: Boolean(installForm.useSudo),
          ttl_secs: DEFAULT_INSTALL_TTL_SECS,
        });
      } else {
        const winrmUsername = installForm.winrmUsername.trim();
        const winrmPassword = installForm.winrmPassword;
        const winrmPort = Number.parseInt(String(installForm.winrmPort || '').trim(), 10);
        if (!winrmUsername) {
          toast('WinRM username is required before running a remote install.', 'warning');
          return;
        }
        if (!winrmPassword) {
          toast('WinRM password is required before running a remote install.', 'warning');
          return;
        }
        if (!Number.isInteger(winrmPort) || winrmPort <= 0) {
          toast('WinRM port must be a positive integer.', 'warning');
          return;
        }
        result = await api.fleetInstallWinrm({
          hostname,
          address,
          platform,
          manager_url: managerUrl,
          winrm_username: winrmUsername,
          winrm_password: winrmPassword,
          winrm_port: winrmPort,
          winrm_use_tls: Boolean(installForm.winrmUseTls),
          winrm_skip_cert_check: Boolean(installForm.winrmSkipCertCheck),
          ttl_secs: DEFAULT_INSTALL_TTL_SECS,
        });
      }
      setLatestRemoteInstall(result);
      await reloadInstallHistory();
      toast(
        `Remote ${isWinRmRemoteInstall ? 'WinRM' : 'SSH'} install dispatched to ${hostname}; awaiting first heartbeat.`,
        'success',
      );
    } catch (error) {
      const payload = parseApiErrorPayload(error);
      if (payload?.record) {
        setLatestRemoteInstall(payload.record);
      }
      toast(
        payload?.error || payload?.message || payload?.record?.error || 'Remote install failed.',
        'error',
      );
    } finally {
      if (isWinRmRemoteInstall) {
        setInstallForm((current) => ({ ...current, winrmPassword: '' }));
      }
      setIsRemoteInstalling(false);
    }
  }, [
    canRemoteInstall,
    installForm,
    isSshRemoteInstall,
    isWinRmRemoteInstall,
    reloadInstallHistory,
    toast,
  ]);

  const assignLatestRelease = useCallback(async () => {
    if (!selectedDeployableAgent || !latestRelease?.version) {
      return;
    }
    setIsAssigningRelease(true);
    try {
      await api.updatesDeploy({
        agent_id: selectedDeployableAgent.id,
        version: latestRelease.version,
        platform: normalizeInstallPlatform(selectedDeployableAgent.os),
      });
      toast(
        selectedDeployableAgent.status === 'offline'
          ? `Assigned ${latestRelease.version}; the agent will upgrade after the next heartbeat.`
          : `Assigned ${latestRelease.version} to ${selectedDeployableAgent.hostname}.`,
        'success',
      );
      reloadFleetSurface();
    } catch {
      toast('Failed to assign the selected release.', 'error');
    } finally {
      setIsAssigningRelease(false);
    }
  }, [latestRelease, reloadFleetSurface, selectedDeployableAgent, toast]);

  const toggleSelect = useCallback((agent) => {
    if (agent.isLocalConsole) {
      return;
    }
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(agent.id) ? next.delete(agent.id) : next.add(agent.id);
      return next;
    });
  }, []);

  const removablePagedAgents = pagedAgents.filter((agent) => !agent.isLocalConsole);
  const allSelected =
    removablePagedAgents.length > 0 &&
    removablePagedAgents.every((agent) => selected.has(agent.id));
  const toggleAll = useCallback(() => {
    setSelected((prev) => {
      const next = new Set(prev);
      removablePagedAgents.forEach((agent) => {
        if (allSelected) next.delete(agent.id);
        else next.add(agent.id);
      });
      return next;
    });
  }, [allSelected, removablePagedAgents]);

  const executeDelete = async (ids) => {
    const protectedIds = new Set(
      agentArr.filter((agent) => agent.isLocalConsole).map((agent) => agent.id),
    );
    const removableIds = ids.filter((id) => !protectedIds.has(id));
    if (removableIds.length === 0) {
      setConfirmState(null);
      toast('The local console host cannot be removed.', 'warning');
      return;
    }
    const timer = setTimeout(async () => {
      const results = await Promise.allSettled(removableIds.map((id) => api.deleteAgent(id)));
      const ok = results.filter((result) => result.status === 'fulfilled').length;
      toast(
        `Removed ${ok}/${removableIds.length} agents`,
        ok === removableIds.length ? 'success' : 'warning',
      );
      setSelected(new Set());
      if (selectedAgent && removableIds.includes(selectedAgent)) {
        setSelectedAgent(null);
        setAgentDetail(null);
      }
      setPendingDelete(null);
      reloadFleetSurface();
    }, 5000);
    setPendingDelete({ ids: removableIds, timer });
    toast('Delete queued. Undo within 5 seconds.', 'warning');
    setConfirmState(null);
  };

  const undoPendingDelete = useCallback(() => {
    if (!pendingDelete?.timer) return;
    clearTimeout(pendingDelete.timer);
    setPendingDelete(null);
    toast('Delete canceled.', 'success');
  }, [pendingDelete, toast]);

  useEffect(
    () => () => {
      if (pendingDelete?.timer) clearTimeout(pendingDelete.timer);
    },
    [pendingDelete],
  );

  const activeViewId = SAVED_VIEWS.find(
    (view) =>
      view.filters.status === statusFilter &&
      view.filters.os === osFilter &&
      view.filters.q === query,
  )?.id;

  const openRecoveryScope = useCallback(
    ({ nextStatus = 'all', nextOs = 'all', nextQuery = '' } = {}) => {
      setTab('agents');
      setQuery(nextQuery);
      setStatusFilter(nextStatus);
      setOsFilter(nextOs);
      setPage(0);
      setFleetQueryState({
        fleetTab: 'agents',
        status: nextStatus,
        os: nextOs,
        q: nextQuery,
      });
    },
    [setFleetQueryState],
  );

  return (
    <div>
      <div className="tabs">
        {['fleet', 'agents', 'events', 'updates', 'swarm'].map((item) => (
          <button
            key={item}
            className={`tab ${tab === item ? 'active' : ''}`}
            onClick={() => handleTabChange(item)}
          >
            {item.charAt(0).toUpperCase() + item.slice(1)}
          </button>
        ))}
      </div>

      {tab === 'fleet' && (
        <>
          <div className="card-grid">
            <div className="card metric">
              <div className="metric-label">Total Agents</div>
              <div className="metric-value">{dash?.total_agents ?? dash?.agents ?? '—'}</div>
              <div className="metric-sub">Coverage across the current workspace</div>
            </div>
            <div className="card metric">
              <div className="metric-label">Offline Now</div>
              <div className="metric-value">{queueHealth.offline}</div>
              <div className="metric-sub">Endpoints that need recovery attention</div>
            </div>
            <div className="card metric">
              <div className="metric-label">Stale Heartbeats</div>
              <div className="metric-value">{queueHealth.stale}</div>
              <div className="metric-sub">Agents quiet for more than 30 minutes</div>
            </div>
            <div className="card metric">
              <div className="metric-label">Platform</div>
              <div className="metric-value">{plat?.os ?? plat?.platform ?? '—'}</div>
              <div className="metric-sub">Primary host environment</div>
            </div>
          </div>
          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>
              Fleet Health
            </div>
            <div className="summary-grid">
              <div className="summary-card">
                <div className="summary-label">Agent Count</div>
                <div className="summary-value">{fleetHealthData?.total_agents ?? '—'}</div>
                <div className="summary-meta">Including local console host</div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Online</div>
                <div className="summary-value">{fleetHealthData?.online ?? '—'}</div>
                <div className="summary-meta">Agents with live heartbeat</div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Stale</div>
                <div className="summary-value">{fleetHealthData?.stale ?? '—'}</div>
                <div className="summary-meta">Missed heartbeat window</div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Log Streams</div>
                <div className="summary-value">{fleetHealthData?.logs_tracked ?? '—'}</div>
                <div className="summary-meta">Agent log buffers tracked</div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Inventories</div>
                <div className="summary-value">{fleetHealthData?.inventories_tracked ?? '—'}</div>
                <div className="summary-meta">Inventory snapshots available</div>
              </div>
            </div>
          </div>
          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>
              System Status
            </div>
            <SummaryGrid data={fleetSt} limit={12} />
          </div>
          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>
              Fleet Dashboard
            </div>
            <SummaryGrid data={dash} limit={12} />
            <JsonDetails data={dash} label="Fleet metrics breakdown" />
          </div>
        </>
      )}

      {tab === 'agents' && (
        <div className="triage-layout">
          <section className="triage-list card">
            <div className="card-header">
              <span className="card-title">Registered Agents ({filteredAgents.length})</span>
              <div className="btn-group">
                <span
                  className={`badge ${(wsStats?.connected_subscribers || 0) > 0 ? 'badge-ok' : 'badge-warn'}`}
                >
                  {(wsStats?.connected_subscribers || 0) > 0
                    ? `Live (${wsStats.connected_subscribers})`
                    : 'Live idle'}
                </span>
                <button className="btn btn-sm" onClick={reloadFleetSurface}>
                  Refresh
                </button>
                <button
                  className="btn btn-sm btn-danger"
                  disabled={selected.size === 0}
                  onClick={() => setConfirmState({ type: 'bulk-delete' })}
                >
                  Delete {selected.size || ''} selected
                </button>
              </div>
            </div>

            <div className="triage-toolbar">
              <div className="triage-toolbar-group">
                {SAVED_VIEWS.map((view) => (
                  <button
                    key={view.id}
                    type="button"
                    className={`btn btn-sm ${activeViewId === view.id ? 'btn-primary' : ''}`}
                    onClick={() => {
                      setQuery(view.filters.q);
                      setStatusFilter(view.filters.status);
                      setOsFilter(view.filters.os);
                      setPage(0);
                      setFleetQueryState({
                        q: view.filters.q,
                        status: view.filters.status,
                        os: view.filters.os,
                      });
                    }}
                  >
                    {view.label}
                  </button>
                ))}
              </div>
              <div className="triage-toolbar-group triage-toolbar-group-right">
                <label className="sr-only" htmlFor="fleet-agent-query">
                  Search agents
                </label>
                <input
                  id="fleet-agent-query"
                  className="form-input triage-search"
                  placeholder="Search hostname, ID, OS, or version…"
                  value={query}
                  onChange={(event) => {
                    const value = event.target.value;
                    setQuery(value);
                    setPage(0);
                    setFleetQueryState({ q: value });
                  }}
                />
                <label className="sr-only" htmlFor="fleet-status-filter">
                  Filter by status
                </label>
                <select
                  id="fleet-status-filter"
                  className="form-select"
                  value={statusFilter}
                  onChange={(event) => {
                    const value = event.target.value;
                    setStatusFilter(value);
                    setPage(0);
                    setFleetQueryState({ status: value });
                  }}
                >
                  {statusOptions.map((status) => (
                    <option key={status} value={status}>
                      {status === 'all' ? 'All statuses' : status}
                    </option>
                  ))}
                </select>
                <label className="sr-only" htmlFor="fleet-os-filter">
                  Filter by OS
                </label>
                <select
                  id="fleet-os-filter"
                  className="form-select"
                  value={osFilter}
                  onChange={(event) => {
                    const value = event.target.value;
                    setOsFilter(value);
                    setPage(0);
                    setFleetQueryState({ os: value });
                  }}
                >
                  {osOptions.map((os) => (
                    <option key={os} value={os}>
                      {os === 'all' ? 'All platforms' : os}
                    </option>
                  ))}
                </select>
                <div className="btn-group" style={{ marginLeft: 8 }}>
                  {AGENT_COLUMNS.map((column) => (
                    <button
                      key={column}
                      className={`btn btn-sm ${hasColumn(column) ? 'btn-primary' : ''}`}
                      onClick={() => toggleColumn(column)}
                      title={`Toggle ${column.replace('_', ' ')} column`}
                    >
                      {column.replace('_', ' ')}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <div className="summary-grid triage-summary-grid">
              <div className="summary-card">
                <div className="summary-label">Filtered Fleet</div>
                <div className="summary-value">{filteredAgents.length}</div>
                <div className="summary-meta">Endpoints still in the current operator scope</div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Offline Over 1h</div>
                <div className="summary-value">{queueHealth.offline}</div>
                <div className="summary-meta">Saved views keep lagging endpoints visible</div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Stale Heartbeats</div>
                <div className="summary-value">{queueHealth.stale}</div>
                <div className="summary-meta">Likely needs recovery or rollout validation</div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Selected</div>
                <div className="summary-value">{selected.size}</div>
                <div className="summary-meta">Endpoint records pinned for bulk actions</div>
              </div>
            </div>

            <div className="active-filter-chips">
              {statusFilter !== 'all' && <span className="scope-chip">Status: {statusFilter}</span>}
              {osFilter !== 'all' && <span className="scope-chip">OS: {osFilter}</span>}
              {query && <span className="scope-chip">Query: {query}</span>}
              {hasFleetFilters && (
                <button className="filter-chip-button" onClick={clearFleetFilters}>
                  Reset filters
                </button>
              )}
            </div>
            <div className="triage-meta-bar">
              <div className="hint">
                Showing {pagedAgents.length} agent{pagedAgents.length === 1 ? '' : 's'} on page{' '}
                {page + 1} of {totalPages}. {queueHealth.offline} endpoints are currently offline.
              </div>
              {hasFleetFilters && (
                <button className="btn btn-sm" onClick={clearFleetFilters}>
                  Clear Scope
                </button>
              )}
            </div>

            {pendingDelete && (
              <div className="sticky-bulk-bar" style={{ marginBottom: 12 }}>
                <span className="hint">
                  Delete scheduled for {pendingDelete.ids.length} agent
                  {pendingDelete.ids.length === 1 ? '' : 's'}.
                </span>
                <button className="btn btn-sm" onClick={undoPendingDelete}>
                  Undo
                </button>
              </div>
            )}

            {filteredAgents.length === 0 ? (
              <EmptyState
                title="No agents match the current view"
                message="The fleet is available, but the current search and platform filters narrowed this view to zero endpoints. Clear the scope or switch a saved view to continue operating."
                primaryCta={
                  hasFleetFilters
                    ? { label: 'Clear Filters', onClick: clearFleetFilters }
                    : undefined
                }
              />
            ) : (
              <>
                <div
                  className="split-list-table"
                  tabIndex={0}
                  onKeyDown={(event) => {
                    if (event.key === 'j') {
                      event.preventDefault();
                      setFocusedRowIndex(
                        Math.min(activeRowIndex + 1, Math.max(0, pagedAgents.length - 1)),
                      );
                    }
                    if (event.key === 'k') {
                      event.preventDefault();
                      setFocusedRowIndex(Math.max(activeRowIndex - 1, 0));
                    }
                    if (event.key === 'Enter' && pagedAgents[activeRowIndex]) {
                      event.preventDefault();
                      openAgent(pagedAgents[activeRowIndex]);
                    }
                    if (event.key === 'Escape') {
                      event.preventDefault();
                      setSelectedAgent(null);
                      setAgentDetail(null);
                    }
                  }}
                >
                  <div className="desktop-table-only">
                    <table>
                      <thead>
                        <tr>
                          <th style={{ width: 32 }}>
                            <input
                              type="checkbox"
                              checked={allSelected}
                              onChange={toggleAll}
                              aria-label="Select all visible agents"
                            />
                          </th>
                          {hasColumn('hostname') && <th>Host</th>}
                          {hasColumn('id') && <th>Agent ID</th>}
                          {hasColumn('status') && <th>Status</th>}
                          {hasColumn('os') && <th>OS</th>}
                          {hasColumn('version') && <th>Version</th>}
                          {hasColumn('last_seen') && <th>Last Seen</th>}
                        </tr>
                      </thead>
                      <tbody>
                        {pagedAgents.map((agent) => {
                          const isActive =
                            (selectedAgent && selectedAgent === agent.id) ||
                            hoveredAgent?.id === agent.id;
                          return (
                            <tr
                              key={agent.id}
                              className={
                                isActive || pagedAgents[activeRowIndex]?.id === agent.id
                                  ? 'row-active'
                                  : ''
                              }
                              onMouseEnter={() => setHoveredAgent(agent)}
                              onFocus={() => setHoveredAgent(agent)}
                              onClick={() => openAgent(agent)}
                              tabIndex={0}
                            >
                              <td onClick={(event) => event.stopPropagation()}>
                                <input
                                  type="checkbox"
                                  disabled={agent.isLocalConsole}
                                  checked={selected.has(agent.id)}
                                  onChange={() => toggleSelect(agent)}
                                  aria-label={
                                    agent.isLocalConsole
                                      ? `${agent.hostname} is managed by the local console`
                                      : `Select ${agent.hostname}`
                                  }
                                />
                              </td>
                              {hasColumn('hostname') && (
                                <td>
                                  <div className="row-primary">{agent.hostname}</div>
                                  <div className="row-secondary">
                                    {agent.isLocalConsole ? ' · Local Console Host' : ''}
                                  </div>
                                </td>
                              )}
                              {hasColumn('id') && <td>{agent.id}</td>}
                              {hasColumn('status') && (
                                <td>
                                  <span
                                    className={`badge ${agent.status === 'online' ? 'badge-ok' : agent.status === 'offline' ? 'badge-err' : 'badge-warn'}`}
                                  >
                                    {agent.status}
                                  </span>
                                </td>
                              )}
                              {hasColumn('os') && <td>{agent.os}</td>}
                              {hasColumn('version') && <td>{agent.version}</td>}
                              {hasColumn('last_seen') && (
                                <td>
                                  <div className="row-primary">
                                    {formatRelativeTime(agent.lastSeen)}
                                  </div>
                                  <div className="row-secondary">
                                    {formatDateTime(agent.lastSeen)}
                                  </div>
                                </td>
                              )}
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                  <div className="mobile-stack">
                    {pagedAgents.map((agent) => {
                      const isActive =
                        (selectedAgent && selectedAgent === agent.id) ||
                        hoveredAgent?.id === agent.id;
                      return (
                        <MobileAgentCard
                          key={agent.id}
                          agent={agent}
                          active={isActive}
                          onOpen={openAgent}
                          onCopy={copyRow}
                        />
                      );
                    })}
                  </div>
                </div>
                {totalPages > 1 && (
                  <div className="triage-pagination">
                    <div className="triage-pagination-meta">
                      Showing {page * pageSize + 1}–
                      {Math.min((page + 1) * pageSize, filteredAgents.length)} of{' '}
                      {filteredAgents.length} agents
                    </div>
                    <div className="triage-pagination-controls">
                      <label className="sr-only" htmlFor="fleet-page-size">
                        Rows per page
                      </label>
                      <select
                        id="fleet-page-size"
                        className="form-select"
                        value={pageSize}
                        onChange={(event) => {
                          setPageSize(Number(event.target.value));
                          setPage(0);
                        }}
                      >
                        {PAGE_SIZE_OPTIONS.map((size) => (
                          <option key={size} value={size}>
                            {size} / page
                          </option>
                        ))}
                      </select>
                      <button
                        className="btn btn-sm"
                        disabled={page === 0}
                        onClick={() => setPage((current) => current - 1)}
                      >
                        Previous
                      </button>
                      <span>
                        {page + 1} / {totalPages}
                      </span>
                      <button
                        className="btn btn-sm"
                        disabled={page >= totalPages - 1}
                        onClick={() => setPage((current) => current + 1)}
                      >
                        Next
                      </button>
                    </div>
                  </div>
                )}
              </>
            )}
          </section>

          <aside className="triage-detail card">
            <div className="card-header">
              <span className="card-title">
                {currentPreview ? currentPreview.hostname : 'Agent Preview'}
              </span>
              {currentPreview && (
                <div className="btn-group">
                  {!currentPreview.isLocalConsole && latestRelease?.version && (
                    <button
                      className="btn btn-sm btn-primary"
                      disabled={isAssigningRelease || !selectedAgentNeedsUpgrade}
                      onClick={assignLatestRelease}
                    >
                      {selectedAgentNeedsUpgrade
                        ? isAssigningRelease
                          ? 'Assigning…'
                          : `Assign ${latestRelease.version}`
                        : 'Current release'}
                    </button>
                  )}
                  <button className="btn btn-sm" onClick={() => copyRow(currentPreview)}>
                    Copy
                  </button>
                  {!currentPreview.isLocalConsole && (
                    <button
                      className="btn btn-sm btn-danger"
                      onClick={() =>
                        setConfirmState({
                          type: 'single-delete',
                          id: currentPreview.id,
                          hostname: currentPreview.hostname,
                        })
                      }
                    >
                      Remove
                    </button>
                  )}
                </div>
              )}
            </div>
            {currentPreview ? (
              <>
                <div className="triage-detail-nav">
                  <span className="scope-chip">
                    {currentPreviewIndex + 1} of {filteredAgents.length}
                  </span>
                  <div className="btn-group">
                    <button
                      className="btn btn-sm"
                      onClick={() =>
                        currentPreviewIndex > 0 &&
                        openAgent(filteredAgents[currentPreviewIndex - 1])
                      }
                      disabled={currentPreviewIndex <= 0}
                    >
                      Previous
                    </button>
                    <button
                      className="btn btn-sm"
                      onClick={() =>
                        currentPreviewIndex < filteredAgents.length - 1 &&
                        openAgent(filteredAgents[currentPreviewIndex + 1])
                      }
                      disabled={currentPreviewIndex >= filteredAgents.length - 1}
                    >
                      Next
                    </button>
                    {!selectedAgent && (
                      <button
                        className="btn btn-sm btn-primary"
                        onClick={() => openAgent(currentPreview)}
                      >
                        Pin Preview
                      </button>
                    )}
                  </div>
                </div>
                <div className="detail-hero">
                  <div>
                    <div className="detail-hero-title">{currentPreview.hostname}</div>
                    <div className="detail-hero-copy">
                      {currentPreview.isLocalConsole
                        ? 'Local Wardex console host with direct process and telemetry access'
                        : currentPreview.status === 'offline'
                          ? 'Needs operator attention'
                          : 'Healthy endpoint context available'}
                    </div>
                  </div>
                  <span
                    className={`badge ${currentPreview.status === 'online' ? 'badge-ok' : currentPreview.status === 'offline' ? 'badge-err' : 'badge-warn'}`}
                  >
                    {currentPreview.status}
                  </span>
                </div>
                <div className="summary-grid" style={{ marginTop: 16 }}>
                  <div className="summary-card">
                    <div className="summary-label">Agent ID</div>
                    <div className="summary-value">{currentPreview.id}</div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Operating System</div>
                    <div className="summary-value">{currentPreview.os}</div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Version</div>
                    <div className="summary-value">{currentPreview.version}</div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Last Seen</div>
                    <div className="summary-value">
                      {formatRelativeTime(currentPreview.lastSeen)}
                    </div>
                    <div className="summary-meta">
                      <div>{formatDateTime(currentPreview.lastSeen)}</div>
                    </div>
                  </div>
                </div>
                <div className="detail-callout" style={{ marginTop: 16 }}>
                  {currentPreview.isLocalConsole
                    ? 'This host is running the Wardex control plane locally. Use the live monitor and process views to inspect this machine directly without deregistration workflows.'
                    : currentPreview.status === 'offline'
                      ? 'This endpoint is offline. Review recent heartbeat time and recovery readiness before rolling out changes.'
                      : 'This endpoint is healthy. Use this panel to verify version, platform, and detailed inventory quickly.'}
                </div>
                {!currentPreview.isLocalConsole && latestRelease?.version && (
                  <div className="detail-callout" style={{ marginTop: 12 }}>
                    <strong>Remote upgrade</strong>
                    <div style={{ marginTop: 6 }}>
                      {selectedAgentNeedsUpgrade
                        ? `This agent is behind the latest release reference (${latestRelease.version}). Assigning it queues the upgrade for the next agent update check.`
                        : `This agent already matches the latest release reference (${latestRelease.version}).`}
                    </div>
                  </div>
                )}
                {currentPreview.isLocalConsole && <LocalConsoleInventory />}
                <JsonDetails
                  data={agentDetail || currentPreview.raw}
                  label="Detailed endpoint context"
                />
              </>
            ) : (
              <EmptyState
                title="No agent preview yet"
                message="Hover a row on desktop or tap a card on mobile to inspect endpoint details without losing list position."
              />
            )}
          </aside>
        </div>
      )}

      {tab === 'events' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Events ({eventArr.length})</span>
            <div className="btn-group">
              <button className="btn btn-sm" onClick={rEvents}>
                Refresh
              </button>
              <button
                className="btn btn-sm"
                onClick={async () => {
                  try {
                    const data = await api.eventsExport();
                    const blob = new Blob(
                      [typeof data === 'string' ? data : JSON.stringify(data)],
                      { type: 'application/json' },
                    );
                    const url = URL.createObjectURL(blob);
                    const link = document.createElement('a');
                    link.href = url;
                    link.download = 'events.json';
                    link.click();
                    setTimeout(() => URL.revokeObjectURL(url), 1000);
                    toast('Events exported', 'success');
                  } catch {
                    toast('Export failed', 'error');
                  }
                }}
              >
                Export
              </button>
            </div>
          </div>
          {evtSum && (
            <div style={{ marginBottom: 16 }}>
              <SummaryGrid data={evtSum} limit={10} />
              <JsonDetails data={evtSum} />
            </div>
          )}
          {eventArr.length === 0 ? (
            <WorkspaceEmptyState compact description="No events" />
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Type</th>
                    <th>Source</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {eventArr.slice(0, 100).map((event, index) => (
                    <tr key={index}>
                      <td
                        style={{
                          whiteSpace: 'nowrap',
                          fontSize: 12,
                          fontFamily: 'var(--font-mono)',
                        }}
                      >
                        {event.timestamp || event.time || '—'}
                      </td>
                      <td>{event.event_type || event.type || '—'}</td>
                      <td>{event.source || '—'}</td>
                      <td>
                        {event.message || event.description || JSON.stringify(event).slice(0, 100)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === 'updates' && (
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>
              Rollout & Recovery Workspace
            </div>
            <div className="summary-grid">
              <div className="summary-card">
                <div className="summary-label">Recent Rollouts</div>
                <div className="summary-value">{rolloutHistory.length}</div>
                <div className="summary-meta">
                  {rollout?.last_rollout_at
                    ? `Last rollout ${formatRelativeTime(rollout.last_rollout_at)}`
                    : 'No recent rollout timestamp recorded.'}
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Rollback Events</div>
                <div className="summary-value">{rollout?.rollback_events ?? 0}</div>
                <div className="summary-meta">
                  Recovery history that still needs operator follow-up.
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Offline Or Stale</div>
                <div className="summary-value">{offlineAgents.length + staleAgents.length}</div>
                <div className="summary-meta">
                  {offlineAgents.length} offline • {staleAgents.length} stale heartbeat
                  {staleAgents.length === 1 ? '' : 's'}
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Version Drift</div>
                <div className="summary-value">{driftAgents.length}</div>
                <div className="summary-meta">
                  {latestRelease?.version
                    ? `${latestRelease.version} is the current release reference.`
                    : 'No latest release reference is currently available.'}
                </div>
              </div>
            </div>
            <div style={{ marginTop: 16 }}>
              <div className="row-primary" style={{ marginBottom: 8 }}>
                Updates focus
              </div>
              <div className="chip-row" style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {UPDATE_PANELS.map((panel) => (
                  <button
                    key={panel.id}
                    className={`filter-chip-button ${updatesPanel === panel.id ? 'active' : ''}`}
                    onClick={() =>
                      setFleetQueryState({ fleetTab: 'updates', updatesPanel: panel.id })
                    }
                  >
                    {panel.label}
                  </button>
                ))}
              </div>
            </div>
            <div className="detail-callout" style={{ marginTop: 16 }}>
              <strong>URL-backed updates focus</strong>
              <div style={{ marginTop: 6 }}>{activeUpdatesPanel?.description}</div>
            </div>
          </div>

          <div className="card-grid" style={{ marginBottom: 16 }}>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                Enroll New Host
              </div>
              <div className="detail-callout" style={{ marginBottom: 16 }}>
                Linux and macOS hosts can now be bootstrapped over SSH from this console. Wardex
                still keeps the manual bundle below for RMM, MDM, Windows, or any environment where
                you do not want the manager host to open an SSH session directly.
              </div>
              <form onSubmit={generateInstallBundle}>
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                    gap: 12,
                  }}
                >
                  <label style={{ display: 'grid', gap: 6 }}>
                    <span className="row-primary">Host or agent name</span>
                    <input
                      aria-label="Host or agent name"
                      className="form-input"
                      value={installForm.hostname}
                      onChange={(event) => handleInstallFormChange('hostname', event.target.value)}
                      placeholder="edge-02"
                    />
                  </label>
                  <label style={{ display: 'grid', gap: 6 }}>
                    <span className="row-primary">Address or DNS name</span>
                    <input
                      aria-label="Address or DNS name"
                      className="form-input"
                      value={installForm.address}
                      onChange={(event) => handleInstallFormChange('address', event.target.value)}
                      placeholder="10.0.4.12"
                    />
                  </label>
                  <label style={{ display: 'grid', gap: 6 }}>
                    <span className="row-primary">Platform</span>
                    <select
                      aria-label="Platform"
                      className="form-select"
                      value={installForm.platform}
                      onChange={(event) => handleInstallFormChange('platform', event.target.value)}
                    >
                      <option value="linux">Linux</option>
                      <option value="macos">macOS</option>
                      <option value="windows">Windows</option>
                    </select>
                  </label>
                  <label style={{ display: 'grid', gap: 6 }}>
                    <span className="row-primary">Manager URL</span>
                    <input
                      aria-label="Manager URL"
                      className="form-input"
                      value={installForm.managerUrl}
                      onChange={(event) =>
                        handleInstallFormChange('managerUrl', event.target.value)
                      }
                      placeholder="https://manager.example.com:9090"
                    />
                  </label>
                  {isSshRemoteInstall && (
                    <>
                      <label style={{ display: 'grid', gap: 6 }}>
                        <span className="row-primary">SSH user</span>
                        <input
                          aria-label="SSH user"
                          className="form-input"
                          value={installForm.sshUser}
                          onChange={(event) =>
                            handleInstallFormChange('sshUser', event.target.value)
                          }
                          placeholder="root"
                        />
                      </label>
                      <label style={{ display: 'grid', gap: 6 }}>
                        <span className="row-primary">SSH port</span>
                        <input
                          aria-label="SSH port"
                          className="form-input"
                          inputMode="numeric"
                          value={installForm.sshPort}
                          onChange={(event) =>
                            handleInstallFormChange('sshPort', event.target.value)
                          }
                          placeholder="22"
                        />
                      </label>
                      <label style={{ display: 'grid', gap: 6 }}>
                        <span className="row-primary">Identity file</span>
                        <input
                          aria-label="Identity file"
                          className="form-input"
                          value={installForm.sshIdentityFile}
                          onChange={(event) =>
                            handleInstallFormChange('sshIdentityFile', event.target.value)
                          }
                          placeholder="~/.ssh/wardex-fleet"
                        />
                      </label>
                    </>
                  )}
                  {isWinRmRemoteInstall && (
                    <>
                      <label style={{ display: 'grid', gap: 6 }}>
                        <span className="row-primary">WinRM username</span>
                        <input
                          aria-label="WinRM username"
                          className="form-input"
                          value={installForm.winrmUsername}
                          onChange={(event) =>
                            handleInstallFormChange('winrmUsername', event.target.value)
                          }
                          placeholder="Administrator"
                        />
                      </label>
                      <label style={{ display: 'grid', gap: 6 }}>
                        <span className="row-primary">WinRM password</span>
                        <input
                          aria-label="WinRM password"
                          className="form-input"
                          type="password"
                          value={installForm.winrmPassword}
                          onChange={(event) =>
                            handleInstallFormChange('winrmPassword', event.target.value)
                          }
                          placeholder="Enter the remote administrator password"
                        />
                      </label>
                      <label style={{ display: 'grid', gap: 6 }}>
                        <span className="row-primary">WinRM port</span>
                        <input
                          aria-label="WinRM port"
                          className="form-input"
                          inputMode="numeric"
                          value={installForm.winrmPort}
                          onChange={(event) =>
                            handleInstallFormChange('winrmPort', event.target.value)
                          }
                          placeholder={installForm.winrmUseTls ? '5986' : '5985'}
                        />
                      </label>
                    </>
                  )}
                </div>
                {isSshRemoteInstall ? (
                  <div className="detail-callout" style={{ marginTop: 16 }}>
                    Remote SSH install uses the manager host&apos;s local `ssh` client with batch
                    mode enabled. Use a reachable SSH target, a valid key in your SSH agent or
                    identity file, and either `root` or passwordless `sudo`.
                    <div style={{ marginTop: 10, display: 'flex', gap: 16, flexWrap: 'wrap' }}>
                      <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                        <input
                          type="checkbox"
                          checked={Boolean(installForm.useSudo)}
                          onChange={(event) =>
                            handleInstallFormChange('useSudo', event.target.checked)
                          }
                        />
                        Use `sudo -n` for service install
                      </label>
                      <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                        <input
                          type="checkbox"
                          checked={Boolean(installForm.sshAcceptNewHostKey)}
                          onChange={(event) =>
                            handleInstallFormChange('sshAcceptNewHostKey', event.target.checked)
                          }
                        />
                        Accept new host key on first contact
                      </label>
                    </div>
                  </div>
                ) : isWinRmRemoteInstall ? (
                  <div className="detail-callout" style={{ marginTop: 16 }}>
                    Remote WinRM install uses the manager host&apos;s local `pwsh` runtime. On macOS
                    or Linux managers, install PowerShell 7 plus the `PSWSMan` module before using
                    this path, then provide a Windows account that is allowed to connect over WinRM.
                    <div style={{ marginTop: 10, display: 'flex', gap: 16, flexWrap: 'wrap' }}>
                      <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                        <input
                          type="checkbox"
                          checked={Boolean(installForm.winrmUseTls)}
                          onChange={(event) =>
                            handleInstallFormChange('winrmUseTls', event.target.checked)
                          }
                        />
                        Use WinRM over HTTPS
                      </label>
                      <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                        <input
                          type="checkbox"
                          checked={Boolean(installForm.winrmSkipCertCheck)}
                          disabled={!installForm.winrmUseTls}
                          onChange={(event) =>
                            handleInstallFormChange('winrmSkipCertCheck', event.target.checked)
                          }
                        />
                        Allow self-signed WinRM TLS certificates
                      </label>
                    </div>
                  </div>
                ) : (
                  <div className="detail-callout" style={{ marginTop: 16 }}>
                    Generate the manual install bundle for environments where you do not want the
                    manager host to open a remote session directly.
                  </div>
                )}
                <div className="btn-group" style={{ marginTop: 16 }}>
                  <button className="btn btn-sm btn-primary" disabled={isGeneratingInstallBundle}>
                    {isGeneratingInstallBundle ? 'Generating…' : 'Generate Install Bundle'}
                  </button>
                  {canRemoteInstall && (
                    <button
                      className="btn btn-sm btn-primary"
                      disabled={isRemoteInstalling}
                      onClick={runRemoteInstall}
                      type="button"
                    >
                      {isRemoteInstalling ? 'Installing…' : 'Install Remotely'}
                    </button>
                  )}
                  {installBundle && (
                    <button className="btn btn-sm" onClick={copyInstallBundle} type="button">
                      Copy Command
                    </button>
                  )}
                </div>
              </form>
              {visibleRemoteInstallHistory.length > 0 && (
                <div style={{ marginTop: 16 }}>
                  <div className="row-primary" style={{ marginBottom: 8 }}>
                    Recent Remote Install Attempts
                  </div>
                  {visibleRemoteInstallHistory.slice(0, 4).map((attempt) => (
                    <div
                      key={attempt.id || `${attempt.hostname}-${attempt.started_at}`}
                      style={{ padding: '10px 0', borderBottom: '1px solid var(--border)' }}
                    >
                      <div className="row-primary">
                        {attempt.hostname || 'Unknown host'}
                        {' • '}
                        {attempt.transport || 'ssh'}
                        {' • '}
                        {attempt.status || 'unknown'}
                      </div>
                      <div className="row-secondary">
                        {attempt.transport === 'winrm'
                          ? `${attempt.winrm_username || 'winrm'}@${attempt.address || '—'}:${attempt.winrm_port || (attempt.winrm_use_tls ? '5986' : '5985')}`
                          : `${attempt.ssh_user || 'ssh'}@${attempt.address || '—'}:${attempt.ssh_port || '22'}`}
                        {' • '}
                        {formatDateTime(attempt.completed_at || attempt.started_at)}
                      </div>
                      {(attempt.agent_id || attempt.first_heartbeat_at) && (
                        <div className="hint" style={{ marginTop: 6 }}>
                          {attempt.agent_id
                            ? `Agent ${attempt.agent_id}`
                            : 'First heartbeat received'}
                          {attempt.first_heartbeat_at
                            ? ` • first heartbeat ${formatDateTime(attempt.first_heartbeat_at)}`
                            : ''}
                        </div>
                      )}
                      {(attempt.error || attempt.output_excerpt) && (
                        <div className="hint" style={{ marginTop: 6, whiteSpace: 'pre-wrap' }}>
                          {attempt.error || attempt.output_excerpt}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
              {installBundle && (
                <div style={{ marginTop: 16 }}>
                  <SummaryGrid
                    data={{
                      target_host: installBundle.hostname,
                      target_address: installBundle.address || '—',
                      platform: installBundle.platform,
                      manager_url: installBundle.managerUrl,
                      token_expires: installBundle.expiresAt || 'single use',
                    }}
                    limit={10}
                  />
                  <label
                    htmlFor="fleet-generated-install-command"
                    className="row-primary"
                    style={{ display: 'block', margin: '16px 0 8px' }}
                  >
                    Generated install command
                  </label>
                  <textarea
                    id="fleet-generated-install-command"
                    aria-label="Generated install command"
                    className="form-input"
                    readOnly
                    rows={16}
                    value={installBundle.command}
                    style={{ fontFamily: 'var(--font-mono)', whiteSpace: 'pre' }}
                  />
                </div>
              )}
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                Upgrade Selected Agent
              </div>
              {selectedDeployableAgent ? (
                <>
                  <SummaryGrid
                    data={{
                      hostname: selectedDeployableAgent.hostname,
                      agent_id: selectedDeployableAgent.id,
                      status: selectedDeployableAgent.status,
                      current_version: selectedDeployableAgent.version,
                      target_version: latestRelease?.version || '—',
                    }}
                    limit={10}
                  />
                  <div className="detail-callout" style={{ marginTop: 16 }}>
                    {latestRelease?.version
                      ? selectedAgentNeedsUpgrade
                        ? 'Use the deploy action to assign the latest release to this agent. Offline agents will apply it after they reconnect and send a heartbeat.'
                        : 'This agent already matches the latest release reference.'
                      : 'Publish or sync a release before assigning upgrades from the console.'}
                  </div>
                  <div className="btn-group" style={{ marginTop: 16 }}>
                    <button
                      className="btn btn-sm btn-primary"
                      disabled={!selectedAgentNeedsUpgrade || isAssigningRelease}
                      onClick={assignLatestRelease}
                    >
                      {isAssigningRelease
                        ? 'Assigning…'
                        : latestRelease?.version
                          ? `Assign ${latestRelease.version}`
                          : 'No release available'}
                    </button>
                    <button className="btn btn-sm" onClick={() => handleTabChange('agents')}>
                      Open Agent Details
                    </button>
                  </div>
                </>
              ) : (
                <EmptyState
                  title="No agent selected"
                  message="Pick an endpoint in the Agents workspace, then return here to queue a remote upgrade assignment."
                  primaryCta={{ label: 'Open Agents', onClick: () => handleTabChange('agents') }}
                />
              )}
            </div>
          </div>

          {updatesPanel === 'rollout' && (
            <div className="card-grid">
              <div className="card">
                <div className="card-title" style={{ marginBottom: 12 }}>
                  Recent Rollout History
                </div>
                {rolloutHistory.length === 0 ? (
                  <div className="hint">
                    No rollout history is recorded yet. As deployment history lands, this view will
                    keep the most recent changes visible for recovery review.
                  </div>
                ) : (
                  rolloutHistory.slice(0, 6).map((event, index) => (
                    <div
                      key={event.id || `${event.agent_id || event.target || 'rollout'}-${index}`}
                      style={{ padding: '10px 0', borderBottom: '1px solid var(--border)' }}
                    >
                      <div className="row-primary">
                        {event.agent_id || event.target || event.platform || 'Shared rollout'}
                      </div>
                      <div className="row-secondary">
                        {event.status || 'unknown'} •{' '}
                        {event.rollout_group || event.group || 'default'}
                      </div>
                      <div className="hint" style={{ marginTop: 4 }}>
                        {event.notes || event.summary || 'No rollout notes captured.'}
                        {event.started_at || event.timestamp
                          ? ` • ${formatDateTime(event.started_at || event.timestamp)}`
                          : ''}
                      </div>
                    </div>
                  ))
                )}
              </div>
              <div className="card">
                <div className="card-title" style={{ marginBottom: 12 }}>
                  Config & Policy Context
                </div>
                <SummaryGrid
                  data={{
                    rollout_targets: rollout?.rollout_targets ?? rollout?.targets ?? 0,
                    canary_percentage: rollout?.canary_percentage ?? rollout?.canary ?? '—',
                    rollback_events: rollout?.rollback_events ?? 0,
                    policy_history: policyHistoryEntries.length,
                    latest_release: latestRelease?.version || '—',
                  }}
                  limit={10}
                />
                <JsonDetails data={rollout} label="Rollout config details" />
              </div>
            </div>
          )}

          {updatesPanel === 'recovery' && (
            <div className="card-grid">
              <div className="card">
                <div className="card-title" style={{ marginBottom: 12 }}>
                  Recovery Watchlist
                </div>
                {offlineAgents.length === 0 && staleAgents.length === 0 ? (
                  <div className="hint">
                    No endpoints currently need rollout recovery attention.
                  </div>
                ) : (
                  recoveryWatchlistAgents.map((agent) => (
                    <div
                      key={`${agent.id}-${agent.status}`}
                      style={{ padding: '10px 0', borderBottom: '1px solid var(--border)' }}
                    >
                      <div className="row-primary">{agent.hostname}</div>
                      <div className="row-secondary">
                        {agent.status} • {agent.version} • {agent.os}
                      </div>
                      <div className="hint" style={{ marginTop: 4 }}>
                        Last seen {formatRelativeTime(agent.lastSeen)} •{' '}
                        {formatDateTime(agent.lastSeen)}
                      </div>
                    </div>
                  ))
                )}
                <div className="btn-group" style={{ marginTop: 16 }}>
                  <button
                    className="btn btn-sm btn-primary"
                    onClick={() => openRecoveryScope({ nextStatus: 'offline' })}
                  >
                    Open Offline Agents
                  </button>
                  <button className="btn btn-sm" onClick={() => openRecoveryScope()}>
                    Open Agent Inventory
                  </button>
                </div>
              </div>
              <div className="card">
                <div className="card-title" style={{ marginBottom: 12 }}>
                  Recovery Guidance
                </div>
                <div className="detail-callout">
                  Prioritize offline endpoints first, then validate whether stale heartbeat agents
                  are waiting on rollout completion, transport recovery, or local host drift.
                </div>
                <div style={{ marginTop: 12 }}>
                  {(policyHistoryEntries.length > 0
                    ? policyHistoryEntries
                    : [{ summary: 'No policy-change history captured yet.' }]
                  )
                    .slice(0, 4)
                    .map((entry, index) => (
                      <div
                        key={entry.id || `${entry.timestamp || 'policy'}-${index}`}
                        style={{ padding: '10px 0', borderBottom: '1px solid var(--border)' }}
                      >
                        <div className="row-primary">
                          {entry.actor || entry.user || entry.summary || 'Policy activity'}
                        </div>
                        <div className="row-secondary">
                          {entry.action || entry.status || 'Change recorded'}
                        </div>
                        <div className="hint" style={{ marginTop: 4 }}>
                          {entry.timestamp
                            ? formatDateTime(entry.timestamp)
                            : 'Timestamp unavailable'}
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            </div>
          )}

          {updatesPanel === 'health' && (
            <div className="card-grid">
              <div className="card">
                <div className="card-title" style={{ marginBottom: 12 }}>
                  Deployment Health
                </div>
                <SummaryGrid
                  data={{
                    latest_release: latestRelease?.version || '—',
                    agents_on_latest: latestRelease?.version
                      ? agentArr.length - driftAgents.length
                      : '—',
                    version_drift: driftAgents.length,
                    rollout_targets: rollout?.rollout_targets ?? rollout?.targets ?? 0,
                    rollback_events: rollout?.rollback_events ?? 0,
                  }}
                  limit={10}
                />
                <div className="detail-callout" style={{ marginTop: 16 }}>
                  {driftAgents.length > 0
                    ? `${driftAgents.length} agent${driftAgents.length === 1 ? '' : 's'} are still behind the latest release reference. Review rollout history before widening deployment scope.`
                    : 'No version drift is currently visible against the latest release reference.'}
                </div>
              </div>
              <div className="card">
                <div className="card-title" style={{ marginBottom: 12 }}>
                  Release Reference
                </div>
                {latestRelease ? (
                  <>
                    <SummaryGrid data={latestRelease} limit={10} />
                    <JsonDetails data={releases} label="Release metadata" />
                  </>
                ) : (
                  <div className="hint">Release metadata is not available yet.</div>
                )}
              </div>
            </div>
          )}

          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>
              Policy History
            </div>
            <SummaryGrid data={policyHist} limit={10} />
            <JsonDetails data={policyHist} />
          </div>
        </>
      )}

      {tab === 'swarm' && (
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>
              Swarm Posture
            </div>
            <SummaryGrid data={swarm} limit={12} />
            <JsonDetails data={swarm} />
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Swarm Intel
            </div>
            <SummaryGrid data={swarmIntelData} limit={12} />
            <JsonDetails data={swarmIntelData} />
          </div>
        </>
      )}

      <ConfirmDialog
        open={Boolean(confirmState)}
        title={
          confirmState?.type === 'bulk-delete' ? 'Delete selected agents?' : 'Remove this agent?'
        }
        message={
          confirmState?.type === 'bulk-delete'
            ? `This will remove ${selected.size} agent records from the console. Use this only when the endpoints have been decommissioned.`
            : `This will remove ${confirmState?.hostname || 'the selected agent'} from the console and can disrupt operator context if used accidentally.`
        }
        confirmLabel={confirmState?.type === 'bulk-delete' ? 'Delete Agents' : 'Remove Agent'}
        onCancel={() => setConfirmState(null)}
        onConfirm={() =>
          executeDelete(confirmState?.type === 'bulk-delete' ? [...selected] : [confirmState.id])
        }
      />
    </div>
  );
}
