import { useId } from 'react';
import { formatNumber } from '../operatorUtils.js';
import {
  collectorIdentifier,
  normalizeCollectorTimeline,
  normalizeValidation,
  validationBadgeClass,
  validationStatusLabel,
} from './helpers.js';

function CollectorTimelineList({ timeline }) {
  if (!Array.isArray(timeline) || timeline.length === 0) return null;
  return (
    <div style={{ display: 'grid', gap: 8, marginTop: 10 }}>
      {timeline.slice(0, 5).map((item, index) => (
        <div
          key={`${item.stage || 'checkpoint'}-${index}`}
          style={{
            padding: '8px 10px',
            borderRadius: 10,
            border: '1px solid var(--border)',
            background: 'var(--bg-card)',
          }}
        >
          <div className="chip-row" style={{ marginBottom: 6 }}>
            <span className={`badge ${validationBadgeClass(item.status)}`}>
              {item.stage || 'Checkpoint'}
            </span>
            {item.title && <span className="scope-chip">{item.title}</span>}
          </div>
          {item.detail && <div className="hint">{item.detail}</div>}
        </div>
      ))}
    </div>
  );
}

function formatCollectorDuration(seconds) {
  const totalSeconds = Number(seconds);
  if (!Number.isFinite(totalSeconds) || totalSeconds < 0) return '—';
  if (totalSeconds < 60) return `${Math.round(totalSeconds)}s`;
  if (totalSeconds < 3600) return `${Math.round(totalSeconds / 60)}m`;
  if (totalSeconds < 86400) return `${Math.round(totalSeconds / 3600)}h`;
  return `${Math.round(totalSeconds / 86400)}d`;
}

export function CollectorLaneCard({
  title,
  hint,
  rows,
  emptyText,
  primaryHref,
  primaryLabel,
  secondaryHref,
  secondaryLabel,
}) {
  return (
    <div className="card">
      <div className="card-title" style={{ marginBottom: 10 }}>
        {title}
      </div>
      <div className="hint" style={{ marginBottom: 12 }}>
        {hint}
      </div>
      <div style={{ display: 'grid', gap: 8 }}>
        {rows.length === 0 ? (
          <div className="empty">{emptyText}</div>
        ) : (
          rows.map((entry, index) => {
            const lifecycleAnalytics = entry.lifecycle_analytics || {};
            const successRate = Number.isFinite(Number(lifecycleAnalytics.success_rate))
              ? Math.round(Number(lifecycleAnalytics.success_rate) * 100)
              : null;
            const recentRuns = Array.isArray(entry.ingestion_evidence?.recent_runs)
              ? entry.ingestion_evidence.recent_runs
              : Array.isArray(entry.lifecycle)
                ? entry.lifecycle
                : [];

            return (
              <div key={`${collectorIdentifier(entry)}-${index}`} className="stat-box">
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    gap: 12,
                    alignItems: 'flex-start',
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 600 }}>
                      {entry.label || entry.name || entry.provider}
                    </div>
                    <div style={{ fontSize: 12, opacity: 0.75, marginTop: 4 }}>
                      {entry.events_ingested ?? entry.total_collected ?? 0} events ingested •{' '}
                      {entry.freshness || validationStatusLabel(entry.validation?.status)}
                    </div>
                    <div style={{ fontSize: 12, opacity: 0.72, marginTop: 4 }}>
                      Checkpoint{' '}
                      {entry.checkpoint_id ? String(entry.checkpoint_id).slice(0, 10) : '—'}
                      {entry.lag_seconds != null ? ` • lag ${entry.lag_seconds}s` : ''}
                      {entry.error_category ? ` • ${entry.error_category}` : ''}
                    </div>
                    <div className="chip-row" style={{ marginTop: 8 }}>
                      <span className="scope-chip">Retries {entry.retry_count ?? 0}</span>
                      {entry.backoff_seconds ? (
                        <span className="scope-chip">
                          Backoff {formatCollectorDuration(entry.backoff_seconds)}
                        </span>
                      ) : null}
                      {entry.last_success_at ? (
                        <span className="scope-chip">Last success recorded</span>
                      ) : null}
                    </div>
                    {entry.lifecycle_analytics && (
                      <div className="chip-row" style={{ marginTop: 8 }}>
                        {successRate != null ? (
                          <span className="scope-chip">Success {successRate}%</span>
                        ) : null}
                        <span className="scope-chip">
                          {entry.lifecycle_analytics.total_runs || 0} validation run
                          {(entry.lifecycle_analytics.total_runs || 0) === 1 ? '' : 's'}
                        </span>
                        <span className="scope-chip">
                          24h events {formatNumber(entry.lifecycle_analytics.events_last_24h || 0)}
                        </span>
                        {(entry.lifecycle_analytics.recent_failure_streak ?? 0) > 0 ? (
                          <span className="scope-chip">
                            Failure streak {entry.lifecycle_analytics.recent_failure_streak}
                          </span>
                        ) : null}
                      </div>
                    )}
                    {entry.ingestion_evidence?.pivots?.length > 0 && (
                      <div className="btn-group" style={{ marginTop: 8, flexWrap: 'wrap' }}>
                        {entry.ingestion_evidence.pivots.map((pivot) => (
                          <a
                            key={`${collectorIdentifier(entry)}-${pivot.surface}`}
                            className="btn btn-sm"
                            href={pivot.href}
                          >
                            {pivot.surface}
                          </a>
                        ))}
                      </div>
                    )}
                  </div>
                  <span className={`badge ${validationBadgeClass(entry.validation?.status)}`}>
                    {validationStatusLabel(entry.validation?.status)}
                  </span>
                </div>
                <CollectorTimelineList timeline={normalizeCollectorTimeline(entry)} />
                {recentRuns.length > 0 && (
                  <div style={{ display: 'grid', gap: 6, marginTop: 10 }}>
                    {recentRuns.slice(0, 3).map((run, runIndex) => (
                      <div key={`${collectorIdentifier(entry)}-run-${runIndex}`} className="hint">
                        {run.recorded_at || 'Recorded run'} •{' '}
                        {run.success ? 'success' : run.error_category || 'failed'} •{' '}
                        {run.event_count || 0} event
                        {(run.event_count || 0) === 1 ? '' : 's'}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
      <div className="btn-group" style={{ marginTop: 12, flexWrap: 'wrap' }}>
        <a className="btn btn-sm btn-primary" href={primaryHref}>
          {primaryLabel}
        </a>
        <a className="btn btn-sm" href={secondaryHref}>
          {secondaryLabel}
        </a>
      </div>
    </div>
  );
}

export function ToggleSwitch({ label, checked, onChange, description }) {
  const toggleId = useId();
  return (
    <label
      htmlFor={toggleId}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        cursor: 'pointer',
        padding: '6px 0',
      }}
    >
      <button
        id={toggleId}
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        onKeyDown={(e) => {
          if (e.key === ' ' || e.key === 'Enter') {
            e.preventDefault();
            onChange(!checked);
          }
        }}
        style={{
          width: 40,
          height: 22,
          borderRadius: 11,
          background: checked ? 'var(--primary)' : 'var(--border)',
          position: 'relative',
          transition: 'background .2s',
          flexShrink: 0,
          border: 'none',
          padding: 0,
        }}
      >
        <span
          style={{
            width: 18,
            height: 18,
            borderRadius: 9,
            background: '#fff',
            position: 'absolute',
            top: 2,
            left: checked ? 20 : 2,
            transition: 'left .2s',
            boxShadow: '0 1px 3px rgba(0,0,0,.2)',
          }}
        />
      </button>
      <span>
        <span style={{ fontSize: 13, fontWeight: 500 }}>{label}</span>
        {description && (
          <span style={{ display: 'block', fontSize: 11, color: 'var(--text-secondary)' }}>
            {description}
          </span>
        )}
      </span>
    </label>
  );
}

export function NumberInput({ label, value, onChange, min, max, step, unit, description }) {
  const inputId = useId();
  return (
    <div style={{ marginBottom: 10 }}>
      <label
        htmlFor={inputId}
        style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}
      >
        {label}
      </label>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <input
          id={inputId}
          name={label.toLowerCase().replace(/\s+/g, '_')}
          type="number"
          value={value ?? ''}
          onChange={(e) => {
            const n = Number(e.target.value);
            onChange(Math.min(max ?? Infinity, Math.max(min ?? -Infinity, n)));
          }}
          min={min}
          max={max}
          step={step || 1}
          style={{
            width: 90,
            padding: '4px 8px',
            borderRadius: 'var(--radius)',
            border: '1px solid var(--border)',
            background: 'var(--bg)',
            color: 'var(--text)',
            fontSize: 13,
          }}
        />
        {unit && <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{unit}</span>}
      </div>
      {description && (
        <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
          {description}
        </div>
      )}
    </div>
  );
}

export function TextInput({ label, value, onChange, placeholder, description, type = 'text' }) {
  const inputId = useId();
  return (
    <div style={{ marginBottom: 10 }}>
      <label
        htmlFor={inputId}
        style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}
      >
        {label}
      </label>
      <input
        id={inputId}
        name={label.toLowerCase().replace(/\s+/g, '_')}
        type={type}
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        style={{
          width: '100%',
          maxWidth: 400,
          padding: '6px 10px',
          borderRadius: 'var(--radius)',
          border: '1px solid var(--border)',
          background: 'var(--bg)',
          color: 'var(--text)',
          fontSize: 13,
        }}
      />
      {description && (
        <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
          {description}
        </div>
      )}
    </div>
  );
}

export function SelectInput({ label, value, onChange, options, description }) {
  const inputId = useId();
  return (
    <div style={{ marginBottom: 10 }}>
      <label
        htmlFor={inputId}
        style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}
      >
        {label}
      </label>
      <select
        id={inputId}
        name={label.toLowerCase().replace(/\s+/g, '_')}
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value)}
        style={{
          width: '100%',
          maxWidth: 400,
          padding: '6px 10px',
          borderRadius: 'var(--radius)',
          border: '1px solid var(--border)',
          background: 'var(--bg)',
          color: 'var(--text)',
          fontSize: 13,
        }}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      {description && (
        <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
          {description}
        </div>
      )}
    </div>
  );
}

export function TextAreaInput({ label, value, onChange, placeholder, rows = 5, description }) {
  const inputId = useId();
  return (
    <div style={{ marginBottom: 10 }}>
      <label
        htmlFor={inputId}
        style={{ display: 'block', fontSize: 13, fontWeight: 500, marginBottom: 4 }}
      >
        {label}
      </label>
      <textarea
        id={inputId}
        name={label.toLowerCase().replace(/\s+/g, '_')}
        value={value ?? ''}
        rows={rows}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        style={{
          width: '100%',
          padding: '8px 10px',
          borderRadius: 'var(--radius)',
          border: '1px solid var(--border)',
          background: 'var(--bg)',
          color: 'var(--text)',
          fontSize: 13,
          fontFamily: 'var(--font-mono, ui-monospace, monospace)',
        }}
      />
      {description && (
        <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
          {description}
        </div>
      )}
    </div>
  );
}

export function ValidationIssues({ validation, style }) {
  const normalized = normalizeValidation(validation);
  if (!normalized.issues.length) return null;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6, ...style }}>
      {normalized.issues.map((issue, index) => (
        <div key={`${issue.field}-${index}`} className="stat-box" style={{ fontSize: 12 }}>
          <span
            className={`badge ${issue.level === 'error' ? 'badge-err' : 'badge-warn'}`}
            style={{ marginRight: 8 }}
          >
            {issue.level}
          </span>
          <strong>{issue.field}:</strong> {issue.message}
        </div>
      ))}
    </div>
  );
}
