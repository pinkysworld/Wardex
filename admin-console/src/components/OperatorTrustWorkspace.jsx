import { useState } from 'react';
import { Link } from 'react-router-dom';
import * as api from '../api.js';
import { useApi, useApiGroup } from '../hooks.jsx';
import EmptyState from './EmptyState.jsx';

const WORKSPACE_CONFIG = {
  detection: {
    title: 'Detection Lab',
    eyebrow: 'Detect',
    summary:
      'Replay telemetry, run safe simulations, and validate Sigma, YARA, and signature packs before promotion.',
    loader: api.detectionLabStatus,
    primaryAction: { label: 'Run validation', run: api.runDetectionLab },
  },
  response: {
    title: 'Response Safety',
    eyebrow: 'Respond',
    summary:
      'Review dry-run previews, approvals, rollback paths, blast radius, and post-action verification before live response.',
    loader: api.responseSafety,
    primaryAction: {
      label: 'Preview block IP',
      run: () => api.responsePreview({ action: 'block_ip', ip: '203.0.113.10' }),
    },
  },
  integrations: {
    title: 'Integrations',
    eyebrow: 'Operate',
    summary:
      'Validate connector setup, sample events, freshness, health, and downstream detection impact from one marketplace view.',
    loader: api.integrationsMarketplace,
    primaryAction: {
      label: 'Validate syslog',
      run: () => api.validateIntegration({ provider: 'generic_syslog' }),
    },
  },
  operations: {
    title: 'Operations Health',
    eyebrow: 'Operate',
    summary:
      'Track ingestion, queues, scans, API errors, storage pressure, connector freshness, and fleet drift as production SLO cards.',
    loader: api.operationsHealth,
    primaryAction: { label: 'Export snapshot', run: api.operationsHealthSnapshot },
  },
  malware: {
    title: 'Malware Trust Center',
    eyebrow: 'Analyze',
    summary:
      'Explain verdicts with signature sources, scan signals, rootkit checks, target presets, and repeated-scan diffs.',
    loader: api.malwareExplain,
    secondaryLoader: api.malwareScanDiff,
    primaryAction: { label: 'Compare scans', run: api.malwareScanDiff },
  },
};

function asArray(value) {
  if (Array.isArray(value)) return value;
  return [];
}

function valueText(value, fallback = 'unknown') {
  if (value === null || value === undefined || value === '') return fallback;
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return JSON.stringify(value);
}

function StatusPill({ value }) {
  const text = valueText(value, 'unknown');
  return (
    <span className={`trust-pill trust-pill-${text.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`}>
      {text}
    </span>
  );
}

function MetricCard({ label, value, detail, status }) {
  return (
    <div className="trust-card trust-metric-card">
      <div className="trust-card-kicker">{label}</div>
      <div className="trust-metric-value">{valueText(value, '0')}</div>
      <div className="trust-card-footer">
        {status && <StatusPill value={status} />}
        {detail && <span>{detail}</span>}
      </div>
    </div>
  );
}

function DetectionLabView({ data }) {
  const modes = asArray(data?.modes);
  const history = asArray(data?.history);
  const recommendations = asArray(data?.recommendations);
  const expected = data?.expected_vs_observed || {};
  return (
    <>
      <div className="trust-grid trust-grid-4">
        <MetricCard
          label="Expected detections"
          value={expected.expected_detections}
          status="target"
        />
        <MetricCard
          label="Observed detections"
          value={expected.observed_detections}
          status="runtime"
        />
        <MetricCard
          label="Missed techniques"
          value={expected.missed_techniques}
          status={expected.missed_techniques ? 'review' : 'pass'}
        />
        <MetricCard
          label="Noise candidates"
          value={expected.duplicate_or_noisy_candidates}
          status="feedback"
        />
      </div>
      <TrustSection title="Validation modes">
        <div className="trust-grid trust-grid-3">
          {modes.map((mode) => (
            <div className="trust-card" key={mode.id}>
              <div className="trust-card-title">{mode.label}</div>
              <StatusPill value={mode.status} />
            </div>
          ))}
        </div>
      </TrustSection>
      <TrustSection title="Recommended rule changes">
        <TrustList
          items={recommendations}
          empty="No detection tuning recommendations are waiting."
          render={(item) => (
            <>
              <strong>{item.rule_name || item.rule_id}</strong>
              <span>{item.detail || item.reason}</span>
              <StatusPill value={item.action || 'monitor'} />
            </>
          )}
        />
      </TrustSection>
      <TrustSection title="Validation history">
        <TrustList
          items={history}
          empty="No validation history has been recorded yet."
          render={(item) => (
            <>
              <strong>{item.id}</strong>
              <span>
                {item.mode} • {item.dataset} • {item.target_platform}
              </span>
              <StatusPill value={item.outcome} />
            </>
          )}
        />
      </TrustSection>
    </>
  );
}

function ResponseSafetyView({ data }) {
  const overview = data?.overview || {};
  const requests = asArray(data?.requests);
  const actions = asArray(data?.available_actions);
  return (
    <>
      <div className="trust-grid trust-grid-4">
        <MetricCard
          label="Pending approvals"
          value={overview.pending_response_approvals}
          status={overview.status}
        />
        <MetricCard label="Ready to execute" value={overview.ready_to_execute} status="approval" />
        <MetricCard
          label="Response requests"
          value={overview.total_response_requests}
          status="audit"
        />
        <MetricCard
          label="Playbook approvals"
          value={overview.pending_playbook_approvals}
          status="playbook"
        />
      </div>
      <TrustSection title="Action safety catalog">
        <div className="trust-grid trust-grid-4">
          {actions.map((action) => (
            <div className="trust-card" key={action.action}>
              <div className="trust-card-title">{action.action}</div>
              <StatusPill value={action.destructive ? 'approval_required' : 'low_impact'} />
            </div>
          ))}
        </div>
      </TrustSection>
      <TrustSection title="Requests with preview">
        <TrustList
          items={requests}
          empty="No response requests are waiting."
          render={(item) => (
            <>
              <strong>
                {item.request?.action_label || item.request?.action || 'Response action'}
              </strong>
              <span>
                {item.request?.target_hostname ||
                  item.request?.target?.hostname ||
                  'selected target'}
              </span>
              <StatusPill value={item.request?.status} />
            </>
          )}
        />
      </TrustSection>
    </>
  );
}

function IntegrationsView({ data }) {
  const connectors = asArray(data?.connectors);
  return (
    <>
      <div className="trust-grid trust-grid-3">
        {connectors.map((connector) => (
          <div className="trust-card" key={connector.id}>
            <div className="trust-card-kicker">{connector.lane}</div>
            <div className="trust-card-title">{connector.label || connector.id}</div>
            <div className="trust-score-row">
              <span>Health</span>
              <strong>{valueText(connector.health_score, '0')}%</strong>
            </div>
            <div className="trust-card-footer">
              <StatusPill value={connector.freshness} />
              <span>{connector.next_fix}</span>
            </div>
            <div className="trust-chip-row">
              {asArray(connector.impact).map((impact) => (
                <span className="trust-chip" key={impact}>
                  {impact}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
      {connectors.length === 0 && (
        <EmptyState
          title="No connectors"
          message="Connector setup cards appear once the backend returns marketplace summaries."
        />
      )}
    </>
  );
}

function OperationsView({ data }) {
  const cards = asArray(data?.slo_cards);
  const attentionCards = cards.filter(
    (card) => !['pass', 'ready', 'ok'].includes(String(card.status || '').toLowerCase()),
  );
  const leadCard = attentionCards[0] || cards[0] || null;
  const leadLabel = leadCard?.id
    ? String(leadCard.id)
        .replaceAll('_', ' ')
        .replace(/\b\w/g, (char) => char.toUpperCase())
    : 'Operations health';
  const operationsFocusTitle = leadCard
    ? attentionCards.length > 0
      ? `${leadLabel} needs operations follow-up`
      : 'Operations SLOs are steady'
    : 'Operations health is waiting for telemetry';
  const operationsFocusCopy = leadCard
    ? attentionCards.length > 0
      ? `${attentionCards.length} SLO card${attentionCards.length === 1 ? ' is' : 's are'} outside the pass lane, with ${leadLabel} as the first queue to validate before release or support work.`
      : `${leadLabel} is currently passing, so operators can work from support evidence and routine snapshot exports without immediate escalation pressure.`
    : 'Operations health cards appear once telemetry has been loaded from the backend.';
  return (
    <>
      <section className="ops-focus-strip" aria-label="Current operations focus">
        <div className="ops-focus-hero">
          <div className="summary-label">Current operations focus</div>
          <h3>{operationsFocusTitle}</h3>
          <p>{operationsFocusCopy}</p>
          <div className="ops-focus-actions btn-group">
            <Link className="btn btn-sm btn-primary" to="/help?context=operations-health">
              Open Support
            </Link>
            <Link className="btn btn-sm" to="/settings?tab=admin">
              Review Admin Controls
            </Link>
          </div>
        </div>
        <div className="trust-grid trust-grid-3 ops-focus-summary-grid">
          <MetricCard
            label="Priority lane"
            value={leadLabel}
            detail={leadCard?.recommended_action || 'Routine operations review'}
            status={leadCard?.status || 'ready'}
          />
          <MetricCard
            label="Attention cards"
            value={attentionCards.length}
            detail={`${cards.length} total SLO card${cards.length === 1 ? '' : 's'}`}
            status={attentionCards.length > 0 ? 'review' : 'pass'}
          />
          <MetricCard
            label="Snapshot support"
            value="Ready"
            detail="Support bundles and release snapshots stay available."
            status="support"
          />
        </div>
      </section>

      <div className="trust-grid trust-grid-4">
        {cards.map((card) => (
          <MetricCard
            key={card.id}
            label={card.id}
            value={card.value}
            status={card.status}
            detail={card.recommended_action}
          />
        ))}
      </div>
      <TrustSection title="Support snapshot">
        <div className="trust-card trust-inline-actions">
          <span>
            Exportable health evidence is available for support bundles and release readiness.
          </span>
          <Link className="btn btn-sm" to="/help?context=operations-health">
            Open support
          </Link>
        </div>
      </TrustSection>
    </>
  );
}

function MalwareView({ data, secondary }) {
  const summary = data?.summary || {};
  const presets = asArray(data?.presets);
  const targetPresets = asArray(data?.target_presets);
  return (
    <>
      <div className="trust-grid trust-grid-4">
        <MetricCard label="Total scans" value={summary.total_scans} status="scanner" />
        <MetricCard
          label="Malicious"
          value={summary.malicious}
          status={summary.malicious ? 'review' : 'pass'}
        />
        <MetricCard
          label="Suspicious"
          value={summary.suspicious}
          status={summary.suspicious ? 'review' : 'pass'}
        />
        <MetricCard label="YARA rules" value={summary.yara_rules} status="rules" />
      </div>
      <TrustSection title="Open-source presets">
        <div className="trust-grid trust-grid-4">
          {presets.map((preset) => (
            <div className="trust-card" key={preset.id}>
              <div className="trust-card-title">{preset.label}</div>
              <StatusPill value={preset.operator_opt_in ? 'operator_opt_in' : 'disabled'} />
              <div className="trust-chip-row">
                {asArray(preset.sources).map((source) => (
                  <span className="trust-chip" key={source}>
                    {source}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </TrustSection>
      <TrustSection title="Scan targets">
        <div className="trust-chip-row">
          {targetPresets.map((target) => (
            <span className="trust-chip trust-chip-large" key={target}>
              {target}
            </span>
          ))}
        </div>
      </TrustSection>
      <TrustSection title="Scan diff">
        <div className="trust-card">
          <div className="trust-card-title">
            {secondary?.comparison?.rootkit_delta || data?.scan_diff?.status || 'available'}
          </div>
          <p>
            {secondary?.next_action ||
              'Repeated scan comparisons show verdict, confidence, matches, rootkit findings, and skipped checks.'}
          </p>
        </div>
      </TrustSection>
    </>
  );
}

function TrustSection({ title, children }) {
  return (
    <section className="trust-section">
      <h2>{title}</h2>
      {children}
    </section>
  );
}

function TrustList({ items, empty, render }) {
  if (!items.length) return <EmptyState compact title={empty} />;
  return (
    <div className="trust-list">
      {items.map((item, index) => (
        <div className="trust-list-row" key={item.id || item.rule_id || index}>
          {render(item)}
        </div>
      ))}
    </div>
  );
}

function OperatorTrustWorkspace({ kind }) {
  const config = WORKSPACE_CONFIG[kind] || WORKSPACE_CONFIG.detection;
  const { data, loading, error, reload } = useApi(config.loader, [kind]);
  const { data: secondaryData } = useApiGroup(
    config.secondaryLoader ? { secondary: config.secondaryLoader } : {},
    [kind],
  );
  const [actionResult, setActionResult] = useState(null);
  const [actionBusy, setActionBusy] = useState(false);

  const runPrimary = async () => {
    if (!config.primaryAction?.run) return;
    setActionBusy(true);
    try {
      const result = await config.primaryAction.run();
      setActionResult(result);
      await reload();
    } finally {
      setActionBusy(false);
    }
  };

  const renderBody = () => {
    if (loading) return <div className="loading">Loading…</div>;
    if (error) {
      return (
        <EmptyState
          title="Workspace unavailable"
          message={error.message || 'The backend did not return this trust workspace.'}
          primaryCta={{ label: 'Retry', onClick: reload }}
        />
      );
    }
    if (kind === 'detection') return <DetectionLabView data={data} />;
    if (kind === 'response') return <ResponseSafetyView data={data} />;
    if (kind === 'integrations') return <IntegrationsView data={data} />;
    if (kind === 'operations') return <OperationsView data={data} />;
    if (kind === 'malware') return <MalwareView data={data} secondary={secondaryData.secondary} />;
    return null;
  };

  return (
    <div className="trust-workspace">
      <header className="trust-hero">
        <div>
          <span className="trust-eyebrow">{config.eyebrow}</span>
          <h1>{config.title}</h1>
          <p>{config.summary}</p>
        </div>
        <div className="trust-hero-actions">
          {config.primaryAction && (
            <button
              className="btn btn-primary"
              type="button"
              onClick={runPrimary}
              disabled={actionBusy}
            >
              {actionBusy ? 'Running…' : config.primaryAction.label}
            </button>
          )}
          <button className="btn btn-sm" type="button" onClick={reload}>
            Refresh
          </button>
        </div>
      </header>
      {actionResult && (
        <div className="trust-action-result" role="status">
          {valueText(actionResult.status || actionResult.state || 'completed')}
        </div>
      )}
      {renderBody()}
    </div>
  );
}

export function DetectionLab() {
  return <OperatorTrustWorkspace kind="detection" />;
}

export function ResponseSafety() {
  return <OperatorTrustWorkspace kind="response" />;
}

export function IntegrationsMarketplace() {
  return <OperatorTrustWorkspace kind="integrations" />;
}

export function OperationsHealth() {
  return <OperatorTrustWorkspace kind="operations" />;
}

export function MalwareTrustCenter() {
  return <OperatorTrustWorkspace kind="malware" />;
}
