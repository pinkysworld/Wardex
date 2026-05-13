import { useCallback, useEffect, useMemo, useState } from 'react';
import * as api from '../api.js';
import { copyTextToClipboard } from './clipboard.js';
import { safeStorageGet, safeStorageRemove, safeStorageSet } from '../safeStorage.js';

const ROLES = ['viewer', 'analyst', 'admin'];
const FEEDS = ['Abuse.ch MalwareBazaar', 'CIRCL MISP (TAXII)', 'Custom URL feed'];
const AGENT_PLATFORMS = [
  { id: 'macos', label: 'macOS', hostname: '$(hostname -s)' },
  { id: 'linux', label: 'Linux', hostname: '$(hostname)' },
  { id: 'windows', label: 'Windows', hostname: '$env:COMPUTERNAME' },
];
const DEFAULT_AGENT_TTL_SECS = 24 * 60 * 60;

function defaultManagerUrl() {
  if (typeof window === 'undefined') return 'http://localhost:8080';
  return window.location.origin || 'http://localhost:8080';
}

function quoteShell(value) {
  return `'${String(value).replace(/'/g, `'"'"'`)}'`;
}

function quotePowerShell(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
}

function buildAgentInstallCommand({ platform, managerUrl, token }) {
  const enrollmentToken = token || '<enrollment-token>';
  const downloadBase = `${managerUrl.replace(/\/$/, '')}/api/updates/download`;

  if (platform === 'windows') {
    return [
      `Invoke-WebRequest -Uri ${quotePowerShell(`${downloadBase}/wardex-agent-windows.exe`)} -OutFile "$env:TEMP\\wardex-agent.exe"`,
      `.\\wardex-agent.exe enroll \``,
      `  --server ${quotePowerShell(managerUrl)} \``,
      `  --token ${quotePowerShell(enrollmentToken)} \``,
      `  --hostname $env:COMPUTERNAME \``,
      `  --platform windows`,
    ].join('\n');
  }

  const artifact =
    platform === 'macos' ? 'wardex-agent-macos-universal' : 'wardex-agent-linux-amd64';
  const hostname = AGENT_PLATFORMS.find((item) => item.id === platform)?.hostname || '$(hostname)';
  return [
    `curl -fsSL -o /tmp/wardex-agent ${quoteShell(`${downloadBase}/${artifact}`)}`,
    'chmod +x /tmp/wardex-agent',
    'sudo /tmp/wardex-agent enroll \\',
    `  --server ${quoteShell(managerUrl)} \\`,
    `  --token ${quoteShell(enrollmentToken)} \\`,
    `  --hostname ${hostname} \\`,
    `  --platform ${platform}`,
  ].join('\n');
}

function ChecklistItem({ label, complete, helper, actionLabel, onAction, busy, actionDisabled }) {
  return (
    <div className={`onboarding-checklist-item ${complete ? 'complete' : ''}`}>
      <div className="onboarding-checklist-mark" aria-hidden="true">
        {complete ? '✓' : '○'}
      </div>
      <div className="onboarding-checklist-copy">
        <div className="onboarding-checklist-label">{label}</div>
        {helper && <div className="onboarding-checklist-helper">{helper}</div>}
      </div>
      {onAction && (
        <button
          type="button"
          className="btn btn-sm"
          onClick={onAction}
          disabled={busy || actionDisabled}
        >
          {busy ? 'Checking…' : actionLabel}
        </button>
      )}
    </div>
  );
}

export default function OnboardingWizard({ onComplete }) {
  const [token, setToken] = useState('');
  const [role, setRole] = useState(safeStorageGet('wardex_role', 'analyst'));
  const [selectedFeeds, setSelectedFeeds] = useState([FEEDS[0]]);
  const [managerUrl, setManagerUrl] = useState(defaultManagerUrl);
  const [agentPlatform, setAgentPlatform] = useState('macos');
  const [enrollment, setEnrollment] = useState({
    token: '',
    expiresAt: '',
    busy: false,
    copied: false,
    message: 'Create a one-use enrollment token when you are ready to connect the first agent.',
  });
  const [readiness, setReadiness] = useState(null);
  const [readinessCheck, setReadinessCheck] = useState({
    busy: false,
    message: 'Refresh operator readiness once the backend is reachable.',
  });
  const [tokenCheck, setTokenCheck] = useState({
    busy: false,
    ok: false,
    message: 'Validate the API token before finishing setup.',
  });

  const refreshReadiness = useCallback(async () => {
    setReadinessCheck({
      busy: true,
      message: 'Checking operator readiness across agents, telemetry, malware, and response…',
    });
    try {
      const next = await api.onboardingReadiness();
      setReadiness(next);
      setReadinessCheck({
        busy: false,
        message: next?.ready
          ? 'Operator readiness checks are passing.'
          : 'Some readiness checks still need attention.',
      });
    } catch {
      setReadinessCheck({
        busy: false,
        message:
          'Readiness checks could not be loaded right now. You can still finish setup and retry once the backend is authenticated.',
      });
    }
  }, []);

  useEffect(() => {
    refreshReadiness();
  }, [refreshReadiness]);

  const readinessChecks = useMemo(() => {
    const items = Array.isArray(readiness?.checks) ? readiness.checks : [];
    return items.reduce((acc, item) => {
      acc[item.key] = item;
      return acc;
    }, {});
  }, [readiness]);

  const readinessItem = useCallback(
    (key, fallbackLabel) => readinessChecks[key] || { label: fallbackLabel },
    [readinessChecks],
  );

  const checklist = useMemo(
    () => [
      {
        key: 'token-present',
        label: 'Console session',
        complete: true,
        helper: token
          ? 'Admin token entered for verification and enrollment-token creation.'
          : 'The console is connected. Paste the admin token only when you want this dialog to verify or issue agent tokens.',
      },
      {
        key: 'token-verified',
        label: 'Verify token',
        complete: tokenCheck.ok || !token.trim(),
        helper: tokenCheck.message,
        actionLabel: 'Verify Token',
        onAction: async () => {
          const previous = api.getToken();
          setTokenCheck({ busy: true, ok: false, message: 'Checking token against the backend…' });
          try {
            api.setToken(token.trim());
            await api.authCheck();
            await api.createAuthSession();
            await refreshReadiness();
            api.setToken('');
            safeStorageRemove('wardex_token');
            setTokenCheck({ busy: false, ok: true, message: 'Backend accepted the token.' });
          } catch {
            setTokenCheck({
              busy: false,
              ok: false,
              message: 'Token verification failed. Check the token and try again.',
            });
          } finally {
            api.setToken(previous);
          }
        },
        busy: tokenCheck.busy,
        actionDisabled: !token.trim(),
      },
      {
        key: 'role-selected',
        label: 'Select role',
        complete: Boolean(role),
        helper: role
          ? `Workspace optimized for ${role}.`
          : 'Choose the workspace that matches your daily responsibilities.',
      },
      {
        key: 'agent-token-ready',
        label: 'Agent enrollment command',
        complete: Boolean(enrollment.token),
        helper: enrollment.message,
      },
      {
        key: 'first-agent-online',
        label: readinessItem('first_agent_online', 'First agent online').label,
        complete: Boolean(readinessItem('first_agent_online').ready),
        helper:
          readinessItem('first_agent_online').detail ||
          'Enroll an agent and confirm the first healthy heartbeat.',
        actionLabel: 'Refresh',
        onAction: refreshReadiness,
        busy: readinessCheck.busy,
      },
      {
        key: 'telemetry-flowing',
        label: readinessItem('telemetry_flowing', 'Telemetry flowing').label,
        complete: Boolean(readinessItem('telemetry_flowing').ready),
        helper:
          readinessItem('telemetry_flowing').detail ||
          'Confirm the backend is receiving live telemetry.',
        actionLabel: 'Refresh',
        onAction: refreshReadiness,
        busy: readinessCheck.busy,
      },
      {
        key: 'first-alert-visible',
        label: readinessItem('first_alert_visible', 'First alert visible').label,
        complete: Boolean(readinessItem('first_alert_visible').ready),
        helper:
          readinessItem('first_alert_visible').detail ||
          'Trigger or ingest one alert so the queue can be validated.',
        actionLabel: 'Refresh',
        onAction: refreshReadiness,
        busy: readinessCheck.busy,
      },
      {
        key: 'intel-source-healthy',
        label: readinessItem('intel_source_healthy', 'Intel source healthy').label,
        complete: Boolean(readinessItem('intel_source_healthy').ready),
        helper:
          readinessItem('intel_source_healthy').detail ||
          'Validate at least one active enrichment feed or imported indicator source.',
        actionLabel: 'Refresh',
        onAction: refreshReadiness,
        busy: readinessCheck.busy,
      },
      {
        key: 'malware-scan-run',
        label: readinessItem('malware_scan_run', 'Malware scan run').label,
        complete: Boolean(readinessItem('malware_scan_run').ready),
        helper:
          readinessItem('malware_scan_run').detail ||
          'Run one malware scan to verify verdict and provenance paths.',
        actionLabel: 'Refresh',
        onAction: refreshReadiness,
        busy: readinessCheck.busy,
      },
      {
        key: 'response-dry-run',
        label: readinessItem(
          'response_approval_dry_run_completed',
          'Response approval dry-run completed',
        ).label,
        complete: Boolean(readinessItem('response_approval_dry_run_completed').ready),
        helper:
          readinessItem('response_approval_dry_run_completed').detail ||
          'Submit a dry-run response request to validate approvals and rollback flow.',
        actionLabel: 'Refresh',
        onAction: refreshReadiness,
        busy: readinessCheck.busy,
      },
    ],
    [
      enrollment.message,
      enrollment.token,
      readinessCheck.busy,
      readinessItem,
      refreshReadiness,
      role,
      token,
      tokenCheck,
    ],
  );

  const completedCount = checklist.filter((item) => item.complete).length;
  const canFinish = checklist[2].complete;
  const installCommand = useMemo(
    () =>
      buildAgentInstallCommand({
        platform: agentPlatform,
        managerUrl: managerUrl.trim() || defaultManagerUrl(),
        token: enrollment.token,
      }),
    [agentPlatform, enrollment.token, managerUrl],
  );

  const toggleFeed = (feed) => {
    setSelectedFeeds((prev) =>
      prev.includes(feed) ? prev.filter((item) => item !== feed) : [...prev, feed],
    );
  };

  const finish = async () => {
    safeStorageRemove('wardex_token');
    if (role) safeStorageSet('wardex_role', role);
    safeStorageSet('wardex_onboarding_complete', '1');
    for (const feed of selectedFeeds) {
      try {
        await api.addFeed({ name: feed });
      } catch {
        /* best-effort */
      }
    }
    onComplete?.();
  };

  const createEnrollmentToken = async () => {
    const previous = api.getToken();
    setEnrollment((current) => ({
      ...current,
      busy: true,
      copied: false,
      message: 'Requesting a one-use enrollment token from Wardex...',
    }));
    try {
      if (token.trim()) api.setToken(token.trim());
      const next = await api.agentsToken({ max_uses: 1, ttl_secs: DEFAULT_AGENT_TTL_SECS });
      setEnrollment({
        token: next?.token || '',
        expiresAt: next?.expires_at || '',
        busy: false,
        copied: false,
        message: next?.expires_at
          ? `Token ready. It expires ${next.expires_at}.`
          : 'Token ready. Use it once to enroll the first agent.',
      });
      await refreshReadiness();
    } catch {
      setEnrollment((current) => ({
        ...current,
        busy: false,
        message:
          'Could not create an enrollment token. Confirm the session or paste a fresh admin token.',
      }));
    } finally {
      api.setToken(previous);
    }
  };

  const copyInstallCommand = async () => {
    const copied = await copyTextToClipboard(installCommand);
    setEnrollment((current) => ({
      ...current,
      copied,
      message: copied
        ? 'Install command copied.'
        : 'Clipboard unavailable. Select the command text manually.',
    }));
  };

  return (
    <div className="onboarding-overlay">
      <div
        className="onboarding-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="onboarding-title"
      >
        <div className="onboarding-header">
          <div>
            <div className="onboarding-eyebrow">Workspace Setup</div>
            <h3 id="onboarding-title">Set up the Wardex admin console</h3>
            <p>
              This checklist moves beyond basic login setup and checks whether the workspace is
              actually ready for analyst work.
            </p>
          </div>
          <div className="onboarding-progress">
            <span className="onboarding-progress-count">
              {completedCount}/{checklist.length}
            </span>
            <span className="onboarding-progress-copy">tasks complete</span>
          </div>
        </div>

        <div className="onboarding-grid">
          <section className="onboarding-section">
            <div className="onboarding-connect-card">
              <div>
                <div className="form-label">Connection Path</div>
                <div className="onboarding-connect-title">
                  Admin console → enrollment token → first heartbeat
                </div>
                <div className="form-helper">
                  Keep this panel open while you generate the enrollment token, run the install
                  command, and refresh readiness.
                </div>
              </div>
              <span className={`badge ${readiness?.ready ? 'badge-ok' : 'badge-warn'}`}>
                {readiness?.ready ? 'Ready' : 'Setup in progress'}
              </span>
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="onboarding-token">
                Admin API Token
              </label>
              <input
                id="onboarding-token"
                name="onboarding_token"
                type="password"
                value={token}
                onChange={(event) => {
                  setToken(event.target.value);
                  setTokenCheck({
                    busy: false,
                    ok: false,
                    message: 'Validate the API token before finishing setup.',
                  });
                }}
                placeholder="Paste API token…"
                className="form-input"
                autoComplete="current-password"
              />
              <div className="form-helper">
                The token is printed in the terminal when the Wardex backend starts. Existing
                console sessions can continue without re-entering it.
              </div>
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="onboarding-manager-url">
                Wardex Server URL
              </label>
              <input
                id="onboarding-manager-url"
                className="form-input"
                value={managerUrl}
                onChange={(event) => setManagerUrl(event.target.value)}
                placeholder="http://localhost:8080"
              />
              <div className="form-helper">
                This URL is embedded into the generated agent enrollment command.
              </div>
            </div>

            <div className="form-group">
              <div className="form-label">Role</div>
              <div className="segmented-control" role="radiogroup" aria-label="Choose role">
                {ROLES.map((item) => (
                  <button
                    key={item}
                    type="button"
                    className={`segmented-option ${role === item ? 'active' : ''}`}
                    role="radio"
                    aria-checked={role === item}
                    onClick={() => setRole(item)}
                  >
                    {item}
                  </button>
                ))}
              </div>
              <div className="form-helper">
                Analysts see queue-first workflows. Admins get fleet and configuration controls.
              </div>
            </div>

            <div className="form-group">
              <div className="form-label">Threat Feeds</div>
              <div className="checkbox-stack">
                {FEEDS.map((feed) => (
                  <label key={feed} className="checkbox-card">
                    <input
                      type="checkbox"
                      checked={selectedFeeds.includes(feed)}
                      onChange={() => toggleFeed(feed)}
                    />
                    <span>{feed}</span>
                  </label>
                ))}
              </div>
              <div className="form-helper">
                Pick the feeds you want configured as part of the initial setup.
              </div>
            </div>

            <div className="form-group">
              <div className="form-label">First Agent</div>
              <div
                className="segmented-control"
                role="radiogroup"
                aria-label="Choose agent platform"
              >
                {AGENT_PLATFORMS.map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    className={`segmented-option ${agentPlatform === item.id ? 'active' : ''}`}
                    role="radio"
                    aria-checked={agentPlatform === item.id}
                    onClick={() => setAgentPlatform(item.id)}
                  >
                    {item.label}
                  </button>
                ))}
              </div>
              <div className="onboarding-command-panel">
                <div className="onboarding-command-header">
                  <span>
                    {enrollment.token
                      ? 'Enrollment command ready'
                      : 'Generate token to unlock command'}
                  </span>
                  <div className="btn-group">
                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={createEnrollmentToken}
                      disabled={enrollment.busy}
                    >
                      {enrollment.busy ? 'Creating...' : 'Create Token'}
                    </button>
                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={copyInstallCommand}
                      disabled={!enrollment.token}
                    >
                      {enrollment.copied ? 'Copied' : 'Copy Command'}
                    </button>
                  </div>
                </div>
                <pre className="onboarding-command-preview">{installCommand}</pre>
                {enrollment.expiresAt && (
                  <div className="form-helper">
                    Enrollment token expires {enrollment.expiresAt}.
                  </div>
                )}
              </div>
            </div>
          </section>

          <section className="onboarding-section">
            <div className="onboarding-checklist">
              {checklist.map((item) => (
                <ChecklistItem
                  key={item.key}
                  label={item.label}
                  helper={item.helper}
                  complete={item.complete}
                  actionLabel={item.actionLabel}
                  onAction={item.onAction}
                  busy={item.busy}
                  actionDisabled={item.actionDisabled}
                />
              ))}
            </div>
          </section>
        </div>

        <div className="onboarding-actions">
          <button type="button" className="btn btn-sm" onClick={onComplete}>
            Skip for now
          </button>
          <div className="btn-group">
            <button
              type="button"
              className="btn btn-sm btn-primary"
              onClick={finish}
              disabled={!canFinish}
            >
              Finish Setup
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
