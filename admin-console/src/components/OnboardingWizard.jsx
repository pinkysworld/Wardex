import { useCallback, useEffect, useMemo, useState } from 'react';
import * as api from '../api.js';

const ROLES = ['viewer', 'analyst', 'admin'];
const FEEDS = ['Abuse.ch MalwareBazaar', 'CIRCL MISP (TAXII)', 'Custom URL feed'];

function ChecklistItem({ label, complete, helper, actionLabel, onAction, busy }) {
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
        <button type="button" className="btn btn-sm" onClick={onAction} disabled={busy}>
          {busy ? 'Checking…' : actionLabel}
        </button>
      )}
    </div>
  );
}

export default function OnboardingWizard({ onComplete }) {
  const [token, setToken] = useState(localStorage.getItem('wardex_token') || '');
  const [role, setRole] = useState(localStorage.getItem('wardex_role') || 'analyst');
  const [selectedFeeds, setSelectedFeeds] = useState([FEEDS[0]]);
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

  const readinessItem = (key, fallbackLabel) => readinessChecks[key] || { label: fallbackLabel };

  const checklist = useMemo(
    () => [
      {
        key: 'token-present',
        label: 'Connect backend',
        complete: Boolean(token.trim()),
        helper: token
          ? 'Token entered and ready to validate.'
          : 'Paste the admin token shown in the terminal.',
      },
      {
        key: 'token-verified',
        label: 'Verify token',
        complete: tokenCheck.ok,
        helper: tokenCheck.message,
        actionLabel: 'Verify Token',
        onAction: async () => {
          const previous = api.getToken();
          setTokenCheck({ busy: true, ok: false, message: 'Checking token against the backend…' });
          try {
            api.setToken(token.trim());
            await api.authCheck();
            await refreshReadiness();
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
    [readinessCheck.busy, readinessChecks, refreshReadiness, role, token, tokenCheck],
  );

  const completedCount = checklist.filter((item) => item.complete).length;
  const canFinish = checklist[0].complete && checklist[2].complete;

  const toggleFeed = (feed) => {
    setSelectedFeeds((prev) =>
      prev.includes(feed) ? prev.filter((item) => item !== feed) : [...prev, feed],
    );
  };

  const finish = async () => {
    if (token) localStorage.setItem('wardex_token', token);
    if (role) localStorage.setItem('wardex_role', role);
    localStorage.setItem('wardex_onboarding_complete', '1');
    for (const feed of selectedFeeds) {
      try {
        await api.addFeed({ name: feed });
      } catch {
        /* best-effort */
      }
    }
    onComplete?.();
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
            <div className="form-group">
              <label className="form-label" htmlFor="onboarding-token">
                API Token
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
                The token is printed in the terminal when the Wardex backend starts.
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
