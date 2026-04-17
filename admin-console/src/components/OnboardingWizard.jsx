import { useMemo, useState } from 'react';
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
  const [tokenCheck, setTokenCheck] = useState({
    busy: false,
    ok: false,
    message: 'Validate the API token before finishing setup.',
  });
  const [feedCheck, setFeedCheck] = useState({
    busy: false,
    ok: false,
    message: 'Select at least one feed and validate connectivity.',
  });
  const [telemetryCheck, setTelemetryCheck] = useState({
    busy: false,
    ok: false,
    message: 'Confirm that the backend is already producing telemetry.',
  });

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
        key: 'feeds-validated',
        label: 'Validate feed connectivity',
        complete: feedCheck.ok,
        helper: feedCheck.message,
        actionLabel: 'Validate Feeds',
        onAction: async () => {
          setFeedCheck({ busy: true, ok: false, message: 'Checking feed subsystem status…' });
          try {
            const stats = await api.feedStats();
            const sourceCount =
              stats?.total_sources ?? stats?.active_sources ?? selectedFeeds.length;
            setFeedCheck({
              busy: false,
              ok: selectedFeeds.length > 0,
              message:
                selectedFeeds.length > 0
                  ? `${sourceCount} configured source${sourceCount === 1 ? '' : 's'} available for ingestion.`
                  : 'Select at least one feed before validating connectivity.',
            });
          } catch {
            setFeedCheck({
              busy: false,
              ok: selectedFeeds.length > 0,
              message:
                selectedFeeds.length > 0
                  ? 'Feed service could not be reached right now, but selected feeds will still be saved.'
                  : 'Select at least one feed before validating connectivity.',
            });
          }
        },
        busy: feedCheck.busy,
      },
      {
        key: 'telemetry-confirmed',
        label: 'Confirm first telemetry received',
        complete: telemetryCheck.ok,
        helper: telemetryCheck.message,
        actionLabel: 'Check Telemetry',
        onAction: async () => {
          setTelemetryCheck({
            busy: true,
            ok: false,
            message: 'Checking current telemetry volume…',
          });
          try {
            const telemetry = await api.telemetryCurrent();
            const rate = telemetry?.events_per_sec ?? telemetry?.rate ?? 0;
            const total = telemetry?.total_events ?? 0;
            setTelemetryCheck({
              busy: false,
              ok: rate > 0 || total > 0,
              message:
                rate > 0 || total > 0
                  ? `Telemetry is flowing (${rate || total} observed).`
                  : 'No telemetry observed yet. You can finish setup and return once agents are online.',
            });
          } catch {
            setTelemetryCheck({
              busy: false,
              ok: false,
              message: 'Telemetry check failed. Confirm the backend is running and retry.',
            });
          }
        },
        busy: telemetryCheck.busy,
      },
    ],
    [feedCheck, role, selectedFeeds.length, telemetryCheck, token, tokenCheck],
  );

  const completedCount = checklist.filter((item) => item.complete).length;
  const canFinish = checklist[0].complete && checklist[2].complete;

  const toggleFeed = (feed) => {
    setSelectedFeeds((prev) =>
      prev.includes(feed) ? prev.filter((item) => item !== feed) : [...prev, feed],
    );
    setFeedCheck({
      busy: false,
      ok: false,
      message: 'Validate feed connectivity after updating the feed selection.',
    });
  };

  const finish = async () => {
    if (token) localStorage.setItem('wardex_token', token);
    if (role) localStorage.setItem('wardex_role', role);
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
              This checklist gets the console ready for real analyst and admin workflows without
              hiding the important steps.
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
