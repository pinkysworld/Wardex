import { useEffect, useMemo, useState } from 'react';
import { useToast } from '../hooks.jsx';
import * as api from '../api.js';
import { JsonDetails, SideDrawer, SummaryGrid } from './operator.jsx';
import { downloadData, formatDateTime, formatLabel } from './operatorUtils.js';
import { freshnessStatusBadge } from './operatorTrustUtils.js';
import AlertNarrative from './AlertNarrative.jsx';

/* ── MITRE + investigation helpers ──────────────────────────── */

const CATEGORY_TO_MITRE = {
  brute_force: { tactic: 'Credential Access', technique: 'T1110', name: 'Brute Force' },
  credential_access: {
    tactic: 'Credential Access',
    technique: 'T1555',
    name: 'Credentials from Password Stores',
  },
  lateral_movement: { tactic: 'Lateral Movement', technique: 'T1021', name: 'Remote Services' },
  privilege_escalation: {
    tactic: 'Privilege Escalation',
    technique: 'T1548',
    name: 'Abuse Elevation Control',
  },
  exfiltration: {
    tactic: 'Exfiltration',
    technique: 'T1041',
    name: 'Exfiltration Over C2 Channel',
  },
  malware: { tactic: 'Execution', technique: 'T1204', name: 'User Execution' },
  ransomware: { tactic: 'Impact', technique: 'T1486', name: 'Data Encrypted for Impact' },
  reconnaissance: { tactic: 'Reconnaissance', technique: 'T1595', name: 'Active Scanning' },
  command_and_control: {
    tactic: 'Command and Control',
    technique: 'T1071',
    name: 'Application Layer Protocol',
  },
  persistence: { tactic: 'Persistence', technique: 'T1053', name: 'Scheduled Task/Job' },
};

function inferMitre(alert) {
  const cat = (alert.category || alert.type || '').toLowerCase().replace(/[\s-]/g, '_');
  return CATEGORY_TO_MITRE[cat] || null;
}

function buildExplanation(alert, mitre, reasons) {
  const score = alert.score ?? alert.severity_score ?? null;
  const lines = [];
  if (score !== null && score >= 8) {
    lines.push('This is a critical-severity alert that warrants immediate investigation.');
  } else if (score !== null && score >= 5) {
    lines.push('This is a medium-severity alert. Validate the activity and escalate if confirmed.');
  } else {
    lines.push(
      'This is a lower-severity alert. Review context to determine if further action is needed.',
    );
  }
  if (mitre) {
    lines.push(`Mapped to MITRE ATT&CK ${mitre.tactic} / ${mitre.technique} (${mitre.name}).`);
  }
  if (alert.ml_triage) {
    const label = alert.ml_triage.label || alert.ml_triage.prediction;
    const conf = alert.ml_triage.confidence;
    if (label)
      lines.push(
        `ML triage classified this as "${label}"${conf ? ` with ${(conf * 100).toFixed(0)}% confidence` : ''}.`,
      );
  }
  if (reasons.length > 0) {
    lines.push(`Detection triggered by: ${reasons.join('; ')}.`);
  }
  return lines;
}

function suggestNextSteps(alert, mitre) {
  const steps = ['Verify the source host and user account are legitimate.'];
  if (mitre?.tactic === 'Credential Access') {
    steps.push('Check for concurrent login anomalies across the fleet.');
    steps.push('Reset credentials for the affected account.');
  }
  if (mitre?.tactic === 'Lateral Movement') {
    steps.push('Isolate the source and destination hosts.');
    steps.push('Review SMB/RDP/SSH session logs for the time window.');
  }
  if (mitre?.tactic === 'Impact' || (alert.category || '').toLowerCase().includes('ransom')) {
    steps.push('Quarantine affected endpoints immediately.');
    steps.push('Check for shadow-copy deletion or encryption activity.');
  }
  steps.push('Correlate with adjacent telemetry in the timeline view.');
  steps.push('If benign, mark as false-positive to improve future scoring.');
  return steps;
}

const HASH_VALUE_PATTERN = /\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{32})\b/g;
const IPV4_VALUE_PATTERN = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const FILE_PATH_PATTERN =
  /(?:[A-Za-z]:\\[^\s'"<>]+|\/(?:Applications|Library|System|Users|bin|etc|opt|private|tmp|usr|var|home|dev|run)\/[^\s'"<>]+)/g;

function extractAlertHashes(alert, reasons) {
  if (!alert) return [];

  const directCandidates = [
    alert.sha256,
    alert.md5,
    alert.hash,
    alert.file_hash,
    alert.artifact_hash,
    alert.indicator_hash,
  ];
  const textCandidates = [alert.message, alert.description, ...reasons]
    .filter(Boolean)
    .flatMap((value) => String(value).match(HASH_VALUE_PATTERN) || []);

  return [...new Set([...directCandidates, ...textCandidates])]
    .map((value) =>
      String(value || '')
        .trim()
        .toLowerCase(),
    )
    .filter((value) => /^[a-f0-9]{32}$|^[a-f0-9]{64}$/.test(value));
}

function isBlockableIpv4(value) {
  const parts = String(value || '').split('.');
  if (parts.length !== 4) return false;
  const nums = parts.map((part) => Number(part));
  if (nums.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  if (nums[0] === 0 || nums[0] === 127) return false;
  if (nums[0] === 169 && nums[1] === 254) return false;
  return value !== '255.255.255.255';
}

function extractAlertSourceIps(alert, reasons) {
  if (!alert) return [];
  const directCandidates = [
    alert.source_ip,
    alert.src_ip,
    alert.remote_ip,
    alert.client_ip,
    alert.attacker_ip,
    alert.origin_ip,
    alert.ip,
    alert.identity_event?.source_ip,
    alert.auth_event?.source_ip,
    alert.event?.source_ip,
    alert.context?.source_ip,
    alert.details?.source_ip,
    alert.data?.source_ip,
    alert.raw?.source_ip,
    alert.source?.ip,
  ];
  const textCandidates = [alert.message, alert.description, ...reasons]
    .filter(Boolean)
    .flatMap((value) => String(value).match(IPV4_VALUE_PATTERN) || []);

  return [...new Set([...directCandidates, ...textCandidates])]
    .map((value) => String(value || '').trim())
    .filter(isBlockableIpv4);
}

function extractAlertFilePaths(alert, reasons) {
  if (!alert) return [];
  const directCandidates = [
    alert.path,
    alert.file,
    alert.file_path,
    alert.artifact_path,
    alert.quarantine_path,
    alert.exe_path,
    alert.process?.exe_path,
    alert.process_detail?.exe_path,
    alert.sample?.file_path,
    alert.context?.file_path,
    alert.details?.file_path,
    alert.data?.file_path,
  ];
  const textCandidates = [alert.message, alert.description, alert.action, ...reasons]
    .filter(Boolean)
    .flatMap((value) => String(value).match(FILE_PATH_PATTERN) || []);

  return [...new Set([...directCandidates, ...textCandidates])]
    .map((value) =>
      String(value || '')
        .trim()
        .replace(/[),.;]+$/g, ''),
    )
    .filter((value) => value.length > 1);
}

function extractAlertUsernames(alert, reasons) {
  if (!alert) return [];
  const directCandidates = [
    alert.username,
    alert.user,
    alert.account,
    alert.identity,
    alert.identity_event?.username,
    alert.auth_event?.username,
    alert.event?.username,
    alert.context?.username,
    alert.details?.username,
  ];
  const textCandidates = [alert.message, alert.description, ...reasons]
    .filter(Boolean)
    .flatMap((value) => {
      const matches =
        String(value).match(/\b(?:user|username|account)=([A-Za-z0-9._@\\-]+)/gi) || [];
      return matches.map((match) => match.split('=').pop());
    });
  return [...new Set([...directCandidates, ...textCandidates])]
    .map((value) => String(value || '').trim())
    .filter(Boolean);
}

function isAuthenticationAlert(alert, reasons) {
  if (!alert) return false;
  const haystack = [alert.category, alert.type, alert.message, alert.description, ...reasons]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
  return [
    'auth failures surge',
    'auth_failures',
    'authentication',
    'brute',
    'credential',
    'login failure',
    'failed login',
    'credential stuffing',
  ].some((needle) => haystack.includes(needle));
}

function alertText(alert, reasons) {
  return [
    alert?.category,
    alert?.type,
    alert?.message,
    alert?.description,
    alert?.action,
    ...reasons,
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
}

function alertPlatform(alert) {
  const normalized = String(alert?.platform || '').toLowerCase();
  if (normalized.includes('mac') || normalized.includes('darwin')) return 'macos';
  if (normalized.includes('win')) return 'windows';
  return 'linux';
}

function normalizeAlertProcessCandidate(source, alert) {
  if (!source && !alert) return null;

  const process =
    source?.process || source?.process_detail || source?.process_snapshot || source || {};
  const pidCandidate = [
    source?.pid,
    source?.process_pid,
    process?.pid,
    alert?.pid,
    alert?.process_pid,
    alert?.process?.pid,
    alert?.process_detail?.pid,
    alert?.process_snapshot?.pid,
    alert?.sample?.pid,
  ]
    .map((value) => Number(value))
    .find((value) => Number.isFinite(value) && value > 0);

  if (!pidCandidate) return null;

  const name =
    source?.name ||
    process?.name ||
    source?.process_name ||
    alert?.process_name ||
    source?.display_name ||
    process?.display_name ||
    source?.exe_path ||
    process?.exe_path ||
    source?.cmd_line ||
    process?.cmd_line ||
    `PID ${pidCandidate}`;

  return {
    pid: pidCandidate,
    ppid: Number(source?.ppid ?? process?.ppid ?? alert?.ppid ?? process?.parent_pid) || null,
    name,
    display_name:
      source?.display_name ||
      process?.display_name ||
      String(name).split('/').pop() ||
      `PID ${pidCandidate}`,
    user: source?.user || process?.user || alert?.user || null,
    group: source?.group || process?.group || alert?.group || null,
    hostname: source?.hostname || process?.hostname || alert?.hostname || null,
    platform: source?.platform || process?.platform || alert?.platform || null,
    cmd_line: source?.cmd_line || process?.cmd_line || alert?.cmd_line || null,
    exe_path: source?.exe_path || process?.exe_path || alert?.exe_path || null,
    cwd: source?.cwd || process?.cwd || alert?.cwd || null,
    start_time: source?.start_time || process?.start_time || null,
    reason: source?.reason || alert?.reasons?.[0] || alert?.message || alert?.description || null,
  };
}

function extractAlertProcessCandidate(alert) {
  return normalizeAlertProcessCandidate(alert, alert);
}

function extractAlertProcessCandidates(alert) {
  if (!alert) return [];

  const items = [extractAlertProcessCandidate(alert)];
  if (Array.isArray(alert.process_candidates)) {
    items.push(
      ...alert.process_candidates.map((candidate) =>
        normalizeAlertProcessCandidate(candidate, alert),
      ),
    );
  }

  const seen = new Set();
  return items.filter((candidate) => {
    if (!candidate || seen.has(candidate.pid)) return false;
    seen.add(candidate.pid);
    return true;
  });
}

function responseBody(alert, body) {
  return {
    hostname: alert?.hostname || alert?.target_hostname || 'local-host',
    severity: alert?.severity || 'high',
    ...body,
  };
}

function buildResponseActions(alert, reasons, sourceIps, filePaths, usernames, processCandidates) {
  if (!alert) return [];

  const text = alertText(alert, reasons);
  const hostname = alert.hostname || alert.target_hostname || 'local-host';
  const primaryIp = sourceIps[0];
  const primaryFile = filePaths[0];
  const primaryUser = usernames[0];
  const primaryProcess = processCandidates[0];
  const isAuth = isAuthenticationAlert(alert, reasons);
  const isNetwork = [
    'network',
    'beacon',
    'c2',
    'command_and_control',
    'dns',
    'exfil',
    'lateral',
    'recon',
    'port scan',
  ].some((needle) => text.includes(needle));
  const isMalware = [
    'malware',
    'virus',
    'ransom',
    'rootkit',
    'hash reputation',
    'yara',
    'packed',
    'defense evasion',
    'persistence',
    'credential_dump',
  ].some((needle) => text.includes(needle));
  const isIntegrity = ['integrity drift', 'config drift', 'tamper', 'rollback'].some((needle) =>
    text.includes(needle),
  );
  const isResource = [
    'process count',
    'process_count',
    'memory pressure',
    'disk pressure',
    'thermal',
    'cpu',
    'crypto',
  ].some((needle) => text.includes(needle));

  const actions = [];
  const add = (action) => actions.push(action);

  if (primaryIp && (isAuth || isNetwork)) {
    add({
      id: `block-ip-${primaryIp}`,
      action: 'block_ip',
      label: 'Request IP Block',
      badge: isAuth ? 'Auth surge' : 'Network',
      target: primaryIp,
      description: 'Approval-gated traffic block for the suspicious source or destination IP.',
      primary: true,
      body: responseBody(alert, {
        action: 'block_ip',
        ip: primaryIp,
        dry_run: false,
        asset_tags: [isAuth ? 'auth-surge' : 'network-detection', 'containment'],
        reason: `${isAuth ? 'Authentication failure surge' : 'Network alarm'} on ${hostname}; request traffic block for ${primaryIp}.`,
      }),
    });
  }

  if (isAuth) {
    add({
      id: 'auth-throttle',
      action: 'throttle',
      label: 'Stage Auth Rate Limit',
      badge: 'Auth surge',
      target: hostname,
      description:
        'Dry-run rate-limit request for aggregate auth-failure surges without reliable IP attribution.',
      body: responseBody(alert, {
        action: 'throttle',
        rate_limit_kbps: 512,
        dry_run: true,
        asset_tags: ['auth-surge', 'rate-limit'],
        reason:
          'Authentication failure surge detected; stage an approval-safe auth ingress rate-limit dry run.',
      }),
    });
  }

  if (primaryUser && isAuth) {
    add({
      id: `disable-account-${primaryUser}`,
      action: 'disable_account',
      label: 'Request Account Disable',
      badge: 'Identity',
      target: primaryUser,
      description: 'Dual-approval account disable for confirmed credential compromise.',
      body: responseBody(alert, {
        action: 'disable_account',
        username: primaryUser,
        dry_run: false,
        asset_tags: ['identity', 'credential-access'],
        reason: `Authentication alarm on ${hostname}; request account disable for ${primaryUser} if compromise is confirmed.`,
      }),
    });
  }

  if (primaryFile && (isMalware || isIntegrity || text.includes('disk pressure'))) {
    add({
      id: `quarantine-file-${primaryFile}`,
      action: 'quarantine_file',
      label: 'Request File Quarantine',
      badge: 'Artifact',
      target: primaryFile,
      description: 'Approval-gated file quarantine with reversible release path.',
      primary: isMalware,
      body: responseBody(alert, {
        action: 'quarantine_file',
        path: primaryFile,
        dry_run: false,
        asset_tags: ['malware', 'artifact'],
        reason: `Malware or integrity alarm on ${hostname}; request quarantine for ${primaryFile}.`,
      }),
    });
  }

  if (primaryProcess && (isMalware || isResource)) {
    add({
      id: `kill-process-${primaryProcess.pid}`,
      action: 'kill_process',
      label: 'Request Process Kill',
      badge: 'Process',
      target: `${primaryProcess.display_name || primaryProcess.name} (${primaryProcess.pid})`,
      description: 'Single-approval kill request for the suspicious process tree root.',
      body: responseBody(alert, {
        action: 'kill_process',
        pid: primaryProcess.pid,
        process_name:
          primaryProcess.display_name || primaryProcess.name || `pid-${primaryProcess.pid}`,
        dry_run: false,
        asset_tags: ['process', isMalware ? 'malware' : 'resource-abuse'],
        reason: `Alarm on ${hostname}; request termination of suspicious process PID ${primaryProcess.pid}.`,
      }),
    });
  }

  if (
    isNetwork ||
    isMalware ||
    isIntegrity ||
    text.includes('ransom') ||
    text.includes('rootkit')
  ) {
    add({
      id: 'isolate-host',
      action: 'isolate',
      label: 'Request Host Isolation',
      badge: 'Host',
      target: hostname,
      description: 'Approval-gated network isolation for confirmed high-impact activity.',
      body: responseBody(alert, {
        action: 'isolate',
        dry_run: false,
        asset_tags: ['host-containment'],
        reason: `High-risk alarm on ${hostname}; request host isolation while evidence is preserved.`,
      }),
    });
  }

  if (isNetwork || (isResource && !isAuth)) {
    add({
      id: 'traffic-throttle',
      action: 'throttle',
      label: 'Stage Traffic Throttle',
      badge: 'Traffic',
      target: hostname,
      description: 'Dry-run traffic shaping request for noisy network or resource-abuse alarms.',
      body: responseBody(alert, {
        action: 'throttle',
        rate_limit_kbps: 1024,
        dry_run: true,
        asset_tags: ['traffic-control'],
        reason: `Network or resource alarm on ${hostname}; stage traffic throttle dry run.`,
      }),
    });
  }

  if (isIntegrity) {
    add({
      id: 'rollback-config',
      action: 'rollback_config',
      label: 'Request Config Rollback',
      badge: 'Integrity',
      target: primaryFile || alert.category || 'configuration baseline',
      description: 'Single-approval rollback request for drifted or tampered configuration.',
      body: responseBody(alert, {
        action: 'rollback_config',
        config_name: primaryFile || alert.category || 'configuration baseline',
        dry_run: false,
        asset_tags: ['integrity', 'rollback'],
        reason: `Integrity drift alarm on ${hostname}; request rollback to the last trusted baseline.`,
      }),
    });
  }

  if (actions.length === 0) {
    add({
      id: 'notify-soc',
      action: 'alert',
      label: 'Create Response Notice',
      badge: 'Triage',
      target: hostname,
      description:
        'Notification-only response record for alarms that need analyst validation first.',
      body: responseBody(alert, {
        action: 'alert',
        dry_run: true,
        asset_tags: ['triage'],
        reason: `Alarm on ${hostname}; create a response notice for analyst validation.`,
      }),
    });
  }

  const seen = new Set();
  return actions.filter((action) => {
    const key = `${action.action}:${action.target}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function normalizeContributingSignal(signal, index) {
  if (typeof signal === 'string') {
    return {
      id: `signal-${index}`,
      kind: 'signal',
      severity: 'info',
      detail: signal,
    };
  }
  if (!signal || typeof signal !== 'object') return null;
  return {
    id: `${signal.kind || signal.type || 'signal'}-${signal.thread_id || signal.id || index}`,
    kind: signal.kind || signal.type || signal.source || 'signal',
    severity: signal.severity || signal.level || 'info',
    detail: signal.detail || signal.message || signal.description || signal.reason || '',
    evidence: signal.evidence || signal,
  };
}

function signalBadgeClass(severity) {
  const normalized = String(severity || '').toLowerCase();
  if (['critical', 'high', 'severe'].includes(normalized)) return 'badge-err';
  if (['medium', 'elevated', 'warning'].includes(normalized)) return 'badge-warn';
  return 'badge-info';
}

function extractContributingSignals(alert, explainData) {
  const directSignals = [
    alert?.thread_anomalies,
    alert?.thread_signals,
    alert?.contributing_signals,
    explainData?.thread_anomalies,
    explainData?.thread_signals,
    explainData?.contributing_signals,
  ]
    .filter(Array.isArray)
    .flat();

  const normalized = directSignals
    .map(normalizeContributingSignal)
    .filter((signal) => signal?.detail || String(signal?.kind || '').includes('thread'));

  if (normalized.length === 0 && Number(alert?.thread_anomaly_count || 0) > 0) {
    normalized.push({
      id: 'thread-anomaly-count',
      kind: 'thread_anomaly',
      severity: alert.thread_anomaly_level || 'info',
      detail: `${alert.thread_anomaly_count} thread anomaly signal${Number(alert.thread_anomaly_count) === 1 ? '' : 's'} attached to this alert.`,
    });
  }

  return normalized.slice(0, 6);
}

/* ── AlertDrawer component ──────────────────────────────────── */

export default function AlertDrawer({
  alert,
  onClose,
  onUpdated,
  onSelectProcess,
  onPrevious,
  onNext,
  canPrevious = false,
  canNext = false,
  positionLabel = null,
}) {
  const toast = useToast();
  const [explainOpen, setExplainOpen] = useState(false);
  const [explainData, setExplainData] = useState(null);
  const [explainLoading, setExplainLoading] = useState(false);
  const [artifactContext, setArtifactContext] = useState({
    hashMatch: null,
    recentDetections: [],
    sightings: [],
  });
  const [artifactContextLoading, setArtifactContextLoading] = useState(false);
  const [responseSubmitting, setResponseSubmitting] = useState(null);
  const [responseResult, setResponseResult] = useState(null);

  const summary = useMemo(() => {
    if (!alert) return null;
    return {
      severity: alert.severity,
      score: alert.score,
      source: alert.source,
      category: alert.category || alert.type,
      hostname: alert.hostname,
      origin: alert.alert_origin,
      agent_id: alert.origin_agent_id || alert.agent_id,
      timestamp: alert.timestamp || alert.time,
    };
  }, [alert]);
  const reasons = useMemo(() => {
    if (!alert) return [];
    return Array.isArray(alert.reasons) ? alert.reasons : alert.reasons ? [alert.reasons] : [];
  }, [alert]);
  const alertHashes = useMemo(() => extractAlertHashes(alert, reasons), [alert, reasons]);
  const sourceIps = useMemo(() => extractAlertSourceIps(alert, reasons), [alert, reasons]);
  const filePaths = useMemo(() => extractAlertFilePaths(alert, reasons), [alert, reasons]);
  const usernames = useMemo(() => extractAlertUsernames(alert, reasons), [alert, reasons]);
  const isAuthAlert = useMemo(() => isAuthenticationAlert(alert, reasons), [alert, reasons]);
  const processCandidates = useMemo(() => extractAlertProcessCandidates(alert), [alert]);
  const responseActions = useMemo(
    () => buildResponseActions(alert, reasons, sourceIps, filePaths, usernames, processCandidates),
    [alert, reasons, sourceIps, filePaths, usernames, processCandidates],
  );
  const processNames = useMemo(
    () => (Array.isArray(alert?.process_names) ? alert.process_names.filter(Boolean) : []),
    [alert],
  );
  const processResolution = useMemo(() => {
    const value = alert?.process_resolution;
    if (typeof value !== 'string' || value.length === 0) return null;
    const labels = {
      unique: { label: '1 live match', tone: 'success' },
      multiple: { label: `${processCandidates.length} candidates`, tone: 'warning' },
      remote_host: { label: 'Remote host — switch agent', tone: 'info' },
      unresolved: { label: 'No live match', tone: 'muted' },
      none: { label: 'No process names', tone: 'muted' },
    };
    return { code: value, ...(labels[value] || { label: value, tone: 'muted' }) };
  }, [alert, processCandidates]);

  useEffect(() => {
    let cancelled = false;
    if (!alert) {
      setExplainData(null);
      setExplainLoading(false);
      return undefined;
    }
    setExplainLoading(true);
    api
      .detectionExplain({
        event_id: alert.id || alert.alert_id,
        alert_id: alert.alert_id || alert.id,
      })
      .then((data) => {
        if (!cancelled) setExplainData(data);
      })
      .catch(() => {
        if (!cancelled) setExplainData(null);
      })
      .finally(() => {
        if (!cancelled) setExplainLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [alert]);

  useEffect(() => {
    let cancelled = false;

    if (!alert || alertHashes.length === 0) {
      setArtifactContext({ hashMatch: null, recentDetections: [], sightings: [] });
      setArtifactContextLoading(false);
      return undefined;
    }

    setArtifactContextLoading(true);
    Promise.allSettled([
      api.scanHash({ hash: alertHashes[0] }),
      api.malwareRecent(),
      api.threatIntelSightings(25),
    ])
      .then(([hashMatchResult, recentDetectionsResult, sightingsResult]) => {
        if (cancelled) return;

        const recentDetections = Array.isArray(recentDetectionsResult.value)
          ? recentDetectionsResult.value.filter((item) =>
              alertHashes.includes(String(item.sha256 || '').toLowerCase()),
            )
          : [];
        const sightingsItems = Array.isArray(sightingsResult.value?.items)
          ? sightingsResult.value.items
          : [];
        const sightings = sightingsItems.filter((item) =>
          alertHashes.includes(String(item.value || '').toLowerCase()),
        );

        setArtifactContext({
          hashMatch: hashMatchResult.status === 'fulfilled' ? hashMatchResult.value : null,
          recentDetections,
          sightings,
        });
      })
      .catch(() => {
        if (!cancelled) {
          setArtifactContext({ hashMatch: null, recentDetections: [], sightings: [] });
        }
      })
      .finally(() => {
        if (!cancelled) setArtifactContextLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [alert, alertHashes]);

  if (!alert) return null;

  const mitre = inferMitre(alert);
  const fallbackExplanation = buildExplanation(alert, mitre, reasons);
  const fallbackNextSteps = suggestNextSteps(alert, mitre);

  const explanation = explainData?.why_fired?.length
    ? [...(explainData.summary || []), ...explainData.why_fired]
    : fallbackExplanation;
  const whySafeOrNoisy = explainData?.why_safe_or_noisy || [];
  const nextSteps = explainData?.next_steps?.length ? explainData.next_steps : fallbackNextSteps;
  const analystFeedback = Array.isArray(explainData?.feedback) ? explainData.feedback : [];
  const normalizedFeedbackStates = [
    'valid',
    'false_positive',
    'benign_true_positive',
    'needs_more_data',
    'duplicate',
  ];
  const entityScores = Array.isArray(explainData?.entity_scores) ? explainData.entity_scores : [];
  const contributingSignals = extractContributingSignals(alert, explainData);
  const evidenceChain = Array.isArray(explainData?.evidence_chain)
    ? explainData.evidence_chain
    : [];
  const matchedRules = Array.isArray(explainData?.matched_rules) ? explainData.matched_rules : [];
  const similarPastAlerts = Array.isArray(explainData?.similar_past_alerts)
    ? explainData.similar_past_alerts
    : [];
  const alertSource = explainData?.source && typeof explainData.source === 'object'
    ? explainData.source
    : null;
  const freshnessRows =
    explainData?.freshness_badges && typeof explainData.freshness_badges === 'object'
      ? Object.entries(explainData.freshness_badges).map(([key, status]) => ({
          key,
          label: formatLabel(key),
          tone: freshnessStatusBadge(status),
        }))
      : [];
  const exportPreviewItems = Array.isArray(explainData?.export_preview?.items)
    ? explainData.export_preview.items
    : [];
  const processLinkState = processCandidates.length
    ? 'Process-linked'
    : processNames.length
      ? 'Process-attributed'
      : 'PID-free';

  const submitFeedback = async (verdict) => {
    try {
      await api.recordDetectionFeedback({
        event_id: alert.id || alert.alert_id,
        alert_id: String(alert.alert_id || alert.id || ''),
        analyst: 'console_analyst',
        verdict,
        reason_pattern:
          reasons.length > 0 ? reasons.join(', ') : alert.category || alert.type || 'unknown',
        notes:
          verdict === 'false_positive'
            ? 'Submitted from alert drawer as benign or noisy.'
            : 'Submitted from alert drawer as analyst-confirmed malicious activity.',
        evidence: (explainData?.evidence || []).slice(0, 8),
      });
      const refreshed = await api.detectionExplain({
        event_id: alert.id || alert.alert_id,
        alert_id: alert.alert_id || alert.id,
      });
      setExplainData(refreshed);
      toast('Analyst feedback saved', 'success');
      onUpdated?.();
    } catch {
      toast('Analyst feedback failed', 'error');
    }
  };

  const markFalsePositive = async () => {
    const pattern =
      reasons.length > 0 ? reasons.join(', ') : alert.category || alert.type || 'unknown';
    try {
      await api.fpFeedback({
        alert_id: alert.id || alert.alert_id,
        pattern,
        is_false_positive: true,
      });
      await api.recordDetectionFeedback({
        event_id: alert.id || alert.alert_id,
        alert_id: String(alert.alert_id || alert.id || ''),
        analyst: 'console_analyst',
        verdict: 'false_positive',
        reason_pattern: pattern,
        notes: 'Marked as false positive from the alert drawer.',
        evidence: (explainData?.evidence || []).slice(0, 8),
      });
      toast('Marked as false positive', 'success');
      onUpdated?.();
    } catch {
      toast('False-positive feedback failed', 'error');
    }
  };

  const createIncidentFromAlert = async () => {
    try {
      await api.createIncident({
        title: `${alert.category || alert.type || 'Alert'} on ${alert.hostname || 'host'}`,
        severity: alert.severity || 'medium',
        event_ids: [alert.id || alert.alert_id].filter(Boolean),
        summary: alert.message || alert.description || 'Created from live alert stream',
      });
      toast('Incident created', 'success');
      onUpdated?.();
    } catch {
      toast('Incident creation failed', 'error');
    }
  };

  const submitResponseAction = async (actionConfig) => {
    if (!alert) return;
    setResponseSubmitting(actionConfig.id);
    setResponseResult(null);
    try {
      let plan = null;
      if (actionConfig.action === 'block_ip' && actionConfig.body?.ip) {
        try {
          plan = await api.remediationPlan({
            platform: alertPlatform(alert),
            action: 'block_ip',
            addr: actionConfig.body.ip,
          });
        } catch {
          plan = null;
        }
      }

      const result = await api.responseRequest(actionConfig.body);
      setResponseResult({ action: actionConfig, result, plan });
      toast(`${actionConfig.label} submitted`, 'success');
      onUpdated?.();
    } catch {
      toast(`${actionConfig.label} failed`, 'error');
    } finally {
      setResponseSubmitting(null);
    }
  };

  return (
    <SideDrawer
      open={!!alert}
      onClose={onClose}
      title={alert.message || alert.description || alert.category || 'Alert detail'}
      subtitle={`${processLinkState} alert context · ${(alert.severity || 'unknown').toUpperCase()}`}
      actions={
        <>
          {(onPrevious || onNext || positionLabel) && (
            <div className="drawer-nav">
              {positionLabel && <span className="scope-chip">{positionLabel}</span>}
              {onPrevious && (
                <button className="btn btn-sm" onClick={onPrevious} disabled={!canPrevious}>
                  Previous
                </button>
              )}
              {onNext && (
                <button className="btn btn-sm" onClick={onNext} disabled={!canNext}>
                  Next
                </button>
              )}
            </div>
          )}
          <button
            className="btn btn-sm"
            onClick={() =>
              downloadData(alert, `alert-${alert.id || alert.alert_id || 'detail'}.json`)
            }
          >
            Export
          </button>
          <button className="btn btn-sm" onClick={markFalsePositive}>
            Mark FP
          </button>
          <button className="btn btn-sm" onClick={() => submitFeedback('true_positive')}>
            Confirm TP
          </button>
          <button className="btn btn-sm btn-primary" onClick={createIncidentFromAlert}>
            Create Incident
          </button>
        </>
      }
    >
      <SummaryGrid data={summary} limit={8} />

      {(processCandidates.length > 0 || processNames.length > 0) && (
        <div className="card" style={{ marginTop: 16 }}>
          <div
            className="card-title"
            style={{
              marginBottom: 8,
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              flexWrap: 'wrap',
            }}
          >
            <span>Process Pivot</span>
            {processResolution && (
              <span
                data-testid="alert-process-resolution"
                data-resolution={processResolution.code}
                className={`badge badge-${processResolution.tone}`}
                style={{ fontSize: 11, fontWeight: 500 }}
              >
                {processResolution.label}
              </span>
            )}
          </div>
          {processNames.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <div className="metric-label" style={{ marginBottom: 6 }}>
                Extracted Process Names
              </div>
              <div className="chip-row">
                {processNames.map((name) => (
                  <span key={name} className="scope-chip">
                    {name}
                  </span>
                ))}
              </div>
            </div>
          )}
          {processCandidates.length > 0 ? (
            <div style={{ display: 'grid', gap: 12 }}>
              {processCandidates.map((candidate) => (
                <div key={candidate.pid} className="drawer-copy-grid">
                  <div>
                    <div className="metric-label">Process</div>
                    <div className="row-primary">
                      {candidate.display_name} (PID {candidate.pid})
                    </div>
                    <div className="row-secondary">
                      {candidate.hostname || 'Local host'}
                      {candidate.user ? ` · ${candidate.user}` : ''}
                    </div>
                  </div>
                  <div>
                    <div className="metric-label">Command</div>
                    <div
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 12,
                        wordBreak: 'break-all',
                      }}
                    >
                      {candidate.cmd_line || candidate.exe_path || candidate.name}
                    </div>
                  </div>
                  {onSelectProcess && (
                    <div className="btn-group" style={{ marginTop: 4 }}>
                      <button className="btn btn-sm" onClick={() => onSelectProcess(candidate)}>
                        {processCandidates.length === 1
                          ? 'Investigate Process'
                          : `Inspect ${candidate.display_name}`}
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="hint">
              {alert.process_resolution === 'remote_host'
                ? 'Wardex extracted process names, but this alert originated on a different host so no local PID was resolved.'
                : 'Wardex extracted process names for this alert, but no live process matched them at collection time.'}
            </div>
          )}
        </div>
      )}

      <AlertNarrative narrative={alert.narrative} />

      {responseActions.length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="card-header">
            <div>
              <div className="card-title">Containment Actions</div>
              <div className="hint" style={{ marginTop: 6 }}>
                Stage guarded responses for this alarm. Destructive or high-impact actions stay in
                the approval workflow; throttles and notices run as dry-runs first.
              </div>
            </div>
            <span className="badge badge-warn">
              {isAuthAlert
                ? 'Auth surge'
                : `${responseActions.length} action${responseActions.length === 1 ? '' : 's'}`}
            </span>
          </div>
          <div className="drawer-copy-grid">
            <div>
              <div className="metric-label">Source IP</div>
              <div className="row-primary">{sourceIps[0] || 'Not present in alert'}</div>
              <div className="row-secondary">
                {sourceIps.length > 0
                  ? 'Use an approval-gated block if this source is confirmed hostile.'
                  : 'This alert stream only reported failure counts, so blocking a remote address is not available yet.'}
              </div>
            </div>
            <div>
              <div className="metric-label">Primary Artifact</div>
              <div className="row-primary">
                {filePaths[0] ||
                  (processCandidates[0]
                    ? `${processCandidates[0].display_name} (${processCandidates[0].pid})`
                    : usernames[0] || 'Host-level response')}
              </div>
              <div className="row-secondary">
                Actions are selected from the alert category, source context, process pivots, and
                extracted artifact fields.
              </div>
            </div>
          </div>
          <div style={{ display: 'grid', gap: 10, marginTop: 12 }}>
            {responseActions.slice(0, 6).map((actionConfig) => (
              <div key={actionConfig.id} className="detail-callout" style={{ margin: 0 }}>
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    gap: 12,
                    alignItems: 'flex-start',
                    flexWrap: 'wrap',
                  }}
                >
                  <div>
                    <span className="badge badge-info" style={{ marginBottom: 6 }}>
                      {actionConfig.badge}
                    </span>
                    <div className="row-primary">{actionConfig.target}</div>
                    <div className="row-secondary">{actionConfig.description}</div>
                  </div>
                  <button
                    className={`btn btn-sm ${actionConfig.primary ? 'btn-primary' : ''}`}
                    onClick={() => submitResponseAction(actionConfig)}
                    disabled={responseSubmitting != null}
                  >
                    {responseSubmitting === actionConfig.id ? 'Submitting…' : actionConfig.label}
                  </button>
                </div>
              </div>
            ))}
          </div>
          {responseActions.length > 6 && (
            <div className="hint" style={{ marginTop: 10 }}>
              Showing the six safest high-signal actions for this alarm.
            </div>
          )}
          {responseResult?.result?.request && (
            <div className="alert-banner success" style={{ marginTop: 12 }}>
              <div className="row-primary">
                {responseResult.result.request.action_label || 'Response request'} ·{' '}
                {responseResult.result.request.status || 'submitted'}
              </div>
              <div className="row-secondary">
                Tier {responseResult.result.request.tier || 'review'} · reversal:{' '}
                {responseResult.result.request.reversal_path || 'tracked in response workflow'}
              </div>
              {responseResult.plan?.commands?.length > 0 && (
                <div className="row-secondary">
                  Planned adapter command: {responseResult.plan.commands[0].program}{' '}
                  {(responseResult.plan.commands[0].args || []).join(' ')}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Explain Alert ───────────────────────────── */}
      <div className="card" style={{ marginTop: 16 }}>
        <button
          onClick={() => setExplainOpen((v) => !v)}
          style={{
            background: 'none',
            border: 'none',
            color: 'var(--primary)',
            cursor: 'pointer',
            fontWeight: 600,
            fontSize: 14,
            padding: 0,
            display: 'flex',
            alignItems: 'center',
            gap: 6,
          }}
        >
          {explainOpen ? '▾' : '▸'} Explain this Alert
        </button>
        {explainOpen && (
          <div style={{ marginTop: 12 }}>
            {explainLoading && (
              <div style={{ marginBottom: 10, fontSize: 13, color: 'var(--text-secondary)' }}>
                Loading server-backed explainability…
              </div>
            )}
            {mitre && (
              <div style={{ marginBottom: 10 }}>
                <span className="badge badge-info" style={{ marginRight: 6 }}>
                  {mitre.technique}
                </span>
                <span style={{ fontSize: 13 }}>
                  {mitre.tactic} — {mitre.name}
                </span>
              </div>
            )}
            <ul
              style={{
                margin: '0 0 12px',
                paddingLeft: 18,
                fontSize: 13,
                lineHeight: 1.7,
                color: 'var(--text)',
              }}
            >
              {explanation.map((line, i) => (
                <li key={i}>{line}</li>
              ))}
            </ul>
            {whySafeOrNoisy.length > 0 && (
              <>
                <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>
                  Why this may be safe or noisy
                </div>
                <ul
                  style={{
                    margin: '0 0 12px',
                    paddingLeft: 18,
                    fontSize: 13,
                    lineHeight: 1.7,
                    color: 'var(--text-secondary)',
                  }}
                >
                  {whySafeOrNoisy.map((line, i) => (
                    <li key={`noise-${i}`}>{line}</li>
                  ))}
                </ul>
              </>
            )}
            {entityScores.length > 0 && (
              <div style={{ margin: '12px 0' }}>
                <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>
                  Entity risk scoring
                </div>
                <div style={{ display: 'grid', gap: 10 }}>
                  {entityScores.slice(0, 4).map((entity) => {
                    const components = Array.isArray(entity.score_components)
                      ? entity.score_components
                      : [];
                    const sequenceSignals = Array.isArray(entity.sequence_signals)
                      ? entity.sequence_signals
                      : [];
                    const graphContext = Array.isArray(entity.graph_context)
                      ? entity.graph_context
                      : [];
                    const pivots = Array.isArray(entity.recommended_pivots)
                      ? entity.recommended_pivots
                      : [];
                    return (
                      <div
                        key={`${entity.entity_kind}-${entity.entity_id}`}
                        className="card"
                        style={{ margin: 0, padding: 12, background: 'var(--surface-muted)' }}
                      >
                        <div
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            gap: 12,
                            alignItems: 'flex-start',
                            marginBottom: 6,
                          }}
                        >
                          <div>
                            <div style={{ fontSize: 13, fontWeight: 700 }}>
                              {entity.entity_kind?.replace(/_/g, ' ') || 'entity'} ·{' '}
                              {entity.entity_id || 'unknown'}
                            </div>
                            {entity.peer_group && (
                              <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                                Peer group: {entity.peer_group}
                              </div>
                            )}
                          </div>
                          <span className="badge badge-info">
                            {Number(entity.score ?? 0).toFixed(1)} / 10
                          </span>
                        </div>
                        {components.length > 0 && (
                          <div className="chip-row" style={{ marginBottom: 6 }}>
                            {components.slice(0, 4).map((component) => (
                              <span key={component.name} className="scope-chip">
                                {String(component.name || 'component').replace(/_/g, ' ')}:{' '}
                                {Number(component.score ?? 0).toFixed(1)}
                              </span>
                            ))}
                          </div>
                        )}
                        {[...sequenceSignals.slice(0, 2), ...graphContext.slice(0, 2)].length >
                          0 && (
                          <ul
                            style={{
                              margin: '6px 0',
                              paddingLeft: 18,
                              fontSize: 12,
                              lineHeight: 1.6,
                              color: 'var(--text-secondary)',
                            }}
                          >
                            {[...sequenceSignals.slice(0, 2), ...graphContext.slice(0, 2)].map(
                              (line, i) => (
                                <li key={`${entity.entity_kind}-context-${i}`}>{line}</li>
                              ),
                            )}
                          </ul>
                        )}
                        {pivots.length > 0 && (
                          <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                            Next pivot: {pivots[0]}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
            {contributingSignals.length > 0 && (
              <div style={{ margin: '12px 0' }}>
                <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>
                  Contributing signals
                </div>
                <div style={{ display: 'grid', gap: 8 }}>
                  {contributingSignals.map((signal) => (
                    <div key={signal.id} className="detail-callout" style={{ margin: 0 }}>
                      <span className={`badge ${signalBadgeClass(signal.severity)}`}>
                        {String(signal.severity || 'info').replace(/_/g, ' ')}
                      </span>{' '}
                      <strong>{String(signal.kind || 'signal').replace(/_/g, ' ')}</strong>
                      <div className="hint" style={{ marginTop: 4 }}>
                        {signal.detail}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {(freshnessRows.length > 0 ||
              alertSource ||
              explainData?.recommended_next_action ||
              exportPreviewItems.length > 0) && (
              <div style={{ margin: '12px 0' }}>
                <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>
                  Provenance and freshness
                </div>
                {alertSource && (
                  <div className="detail-callout" style={{ margin: 0 }}>
                    <strong>{formatLabel(alertSource.source_type || 'source')}</strong>
                    <div className="hint" style={{ marginTop: 4 }}>
                      {[
                        alertSource.hostname || alert.hostname,
                        alertSource.platform || alert.platform,
                        formatDateTime(alertSource.timestamp || summary?.timestamp),
                      ]
                        .filter((value) => value && value !== '—')
                        .join(' • ') || 'Source metadata pending'}
                    </div>
                  </div>
                )}
                {freshnessRows.length > 0 && (
                  <div className="chip-row" style={{ marginTop: 8 }}>
                    {freshnessRows.map((row) => (
                      <span key={row.key} className={`badge ${row.tone.className}`}>
                        {row.label}: {row.tone.label}
                      </span>
                    ))}
                  </div>
                )}
                {explainData?.recommended_next_action && (
                  <div className="hint" style={{ marginTop: 8 }}>
                    Decision path: {explainData.recommended_next_action}
                  </div>
                )}
                {exportPreviewItems.length > 0 && (
                  <div className="hint" style={{ marginTop: 8 }}>
                    Evidence export preview:{' '}
                    {exportPreviewItems
                      .slice(0, 4)
                      .map((item) => formatLabel(item))
                      .join(' • ')}
                  </div>
                )}
              </div>
            )}
            {(evidenceChain.length > 0 ||
              matchedRules.length > 0 ||
              similarPastAlerts.length > 0) && (
              <div style={{ margin: '12px 0' }}>
                <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>Evidence chain</div>
                <div style={{ display: 'grid', gap: 8 }}>
                  {evidenceChain.slice(0, 4).map((item, index) => (
                    <div
                      key={`evidence-chain-${index}`}
                      className="detail-callout"
                      style={{ margin: 0 }}
                    >
                      <span className="badge badge-info">
                        {String(item.signal_type || 'signal').replace(/_/g, ' ')}
                      </span>{' '}
                      <strong>{item.label || `Signal ${index + 1}`}</strong>
                      <div className="hint" style={{ marginTop: 4 }}>
                        {item.value || 'Evidence captured'}
                        {item.confidence_score != null
                          ? ` • confidence ${Number(item.confidence_score).toFixed(2)}`
                          : ''}
                      </div>
                    </div>
                  ))}
                </div>
                {matchedRules.length > 0 && (
                  <div className="chip-row" style={{ marginTop: 8 }}>
                    {matchedRules.slice(0, 4).map((rule) => (
                      <span key={rule.rule_id || rule.rule_name} className="scope-chip">
                        {rule.rule_name || rule.rule_id} · {rule.lifecycle_stage || 'active'}
                      </span>
                    ))}
                  </div>
                )}
                {similarPastAlerts.length > 0 && (
                  <div className="hint" style={{ marginTop: 8 }}>
                    {similarPastAlerts.length} similar past alert
                    {similarPastAlerts.length === 1 ? '' : 's'} available for pivot.
                  </div>
                )}
              </div>
            )}
            <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>
              Recommended next steps
            </div>
            <ol
              style={{
                margin: 0,
                paddingLeft: 18,
                fontSize: 13,
                lineHeight: 1.7,
                color: 'var(--text-secondary)',
              }}
            >
              {nextSteps.map((s, i) => (
                <li key={i}>{s}</li>
              ))}
            </ol>
            {analystFeedback.length > 0 && (
              <div style={{ marginTop: 12, fontSize: 13, color: 'var(--text-secondary)' }}>
                Latest analyst feedback: {analystFeedback[0].analyst} marked this as{' '}
                {String(analystFeedback[0].verdict || '').replace(/_/g, ' ')}.
              </div>
            )}
            <div className="detail-callout" style={{ marginTop: 12 }}>
              <strong>Detection trust impact</strong>
              <div style={{ marginTop: 6 }}>
                Feedback uses normalized outcomes and feeds the rule trust score, draft-only
                suppression suggestions, threshold reviews, and promotion blockers. Wardex does not
                auto-weaken production detections from this drawer.
              </div>
              <div className="chip-row" style={{ marginTop: 10 }}>
                {normalizedFeedbackStates.map((state) => (
                  <span key={state} className="badge badge-info">
                    {state.replace(/_/g, ' ')}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {(alert.message || alert.description) && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="card-title" style={{ marginBottom: 8 }}>
            Narrative
          </div>
          <div style={{ lineHeight: 1.6, fontSize: 14 }}>{alert.message || alert.description}</div>
        </div>
      )}
      {reasons.length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="card-title" style={{ marginBottom: 8 }}>
            Detection Reasons
          </div>
          <div className="chip-row">
            {reasons.map((reason) => (
              <span key={reason} className="badge badge-info">
                {reason}
              </span>
            ))}
          </div>
        </div>
      )}
      {alertHashes.length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="card-title" style={{ marginBottom: 8 }}>
            Malware &amp; Threat Intel
          </div>
          <div className="chip-row" style={{ marginBottom: 12 }}>
            {alertHashes.slice(0, 2).map((hash) => (
              <span key={hash} className="scope-chip">
                {hash}
              </span>
            ))}
          </div>
          {artifactContextLoading ? (
            <div className="hint">Loading hash reputation and recent sightings.</div>
          ) : (
            <div style={{ display: 'grid', gap: 12 }}>
              <div
                className="card"
                style={{ margin: 0, padding: 12, background: 'var(--surface-muted)' }}
              >
                <div className="metric-label">Hash Reputation</div>
                {artifactContext.hashMatch ? (
                  <>
                    <div className="row-primary" style={{ marginTop: 6 }}>
                      {artifactContext.hashMatch.rule_name}
                    </div>
                    <div className="row-secondary">{artifactContext.hashMatch.detail}</div>
                    <div style={{ marginTop: 8 }}>
                      <span
                        className={`badge ${artifactContext.hashMatch.severity === 'high' || artifactContext.hashMatch.severity === 'critical' ? 'badge-err' : 'badge-info'}`}
                      >
                        {artifactContext.hashMatch.severity || 'unknown'}
                      </span>
                    </div>
                  </>
                ) : (
                  <div className="hint">
                    No direct malware hash match was returned for this artifact.
                  </div>
                )}
              </div>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                  gap: 12,
                }}
              >
                <div
                  className="card"
                  style={{ margin: 0, padding: 12, background: 'var(--surface-muted)' }}
                >
                  <div className="metric-label">Recent Hash Detections</div>
                  {artifactContext.recentDetections.length > 0 ? (
                    artifactContext.recentDetections.slice(0, 2).map((detection) => (
                      <div
                        key={`${detection.sha256}-${detection.detected_at}`}
                        style={{ marginTop: 8 }}
                      >
                        <div className="row-primary">
                          {detection.name || detection.family || detection.sha256}
                        </div>
                        <div className="row-secondary">
                          {detection.family || 'unknown family'} ·{' '}
                          {detection.source || 'unknown source'}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="hint">
                      No matching detections were found in the recent malware history.
                    </div>
                  )}
                </div>
                <div
                  className="card"
                  style={{ margin: 0, padding: 12, background: 'var(--surface-muted)' }}
                >
                  <div className="metric-label">Recent Threat Intel Sightings</div>
                  {artifactContext.sightings.length > 0 ? (
                    artifactContext.sightings.slice(0, 2).map((sighting, index) => (
                      <div
                        key={`${sighting.timestamp || 'sighting'}-${index}`}
                        style={{ marginTop: 8 }}
                      >
                        <div className="row-primary">{sighting.context || sighting.value}</div>
                        <div className="row-secondary">
                          {sighting.source || 'unknown source'} · {sighting.severity || 'unknown'}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="hint">
                      No recent threat-intel sighting matches were found for this artifact.
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
      <JsonDetails data={alert} label="Full alert context" />
    </SideDrawer>
  );
}
