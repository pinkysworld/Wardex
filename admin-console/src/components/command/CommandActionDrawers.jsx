import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import * as api from '../../api.js';
import { JsonDetails, SideDrawer, SummaryGrid, WorkspaceEmptyState } from '../operator.jsx';
import { CONNECTOR_LANES, defaultPlannedConnectorConfig, statusBadge } from './helpers.js';

const VALIDATE_CONNECTOR = {
  aws: api.validateAwsCollector,
  azure: api.validateAzureCollector,
  gcp: api.validateGcpCollector,
  okta: api.validateOktaCollector,
  entra: api.validateEntraCollector,
  m365: api.validateM365Collector,
  workspace: api.validateWorkspaceCollector,
  github: api.validateGithubCollector,
  crowdstrike: api.validateCrowdStrikeCollector,
  syslog: api.validateSyslogCollector,
};

const SAVE_CONNECTOR = {
  github: api.saveGithubCollectorConfig,
  crowdstrike: api.saveCrowdStrikeCollectorConfig,
  syslog: api.saveSyslogCollectorConfig,
};

function selectById(items, id) {
  if (!items.length) return null;
  return items.find((item) => String(item.id || item.provider) === String(id)) || items[0];
}

function ActionResult({ result }) {
  if (!result) return null;
  return (
    <div className={`alert-banner ${result.ok ? 'success' : 'warning'}`}>
      <strong>{result.title}</strong>
      <div>{result.message}</div>
      {result.data && <JsonDetails data={result.data} label="Action result" />}
    </div>
  );
}

function ConnectorDrawer({ drawer, connectorRows, onClose, onReload }) {
  const [selectedId, setSelectedId] = useState(drawer?.item?.id || connectorRows[0]?.id || 'aws');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const selected = selectById(connectorRows, selectedId);
  const lane = CONNECTOR_LANES.find((connector) => connector.id === selected?.id) || selected;
  const canSaveSample = Boolean(SAVE_CONNECTOR[selected?.id]);
  const canValidate = Boolean(VALIDATE_CONNECTOR[selected?.id]);

  useEffect(() => {
    if (drawer?.type !== 'connectors') return;
    setSelectedId(drawer?.item?.id || connectorRows[0]?.id || 'aws');
  }, [drawer, connectorRows]);

  const runAction = async (kind) => {
    if (!selected) return;
    setBusy(true);
    setResult(null);
    try {
      let data;
      if (kind === 'save') {
        data = await SAVE_CONNECTOR[selected.id](defaultPlannedConnectorConfig(selected.id));
      } else {
        data = await VALIDATE_CONNECTOR[selected.id]();
      }
      setResult({
        ok: true,
        title: kind === 'save' ? 'Setup draft saved' : 'Validation complete',
        message:
          kind === 'save'
            ? `${selected.label} now has a sample setup draft operators can edit in Settings.`
            : `${selected.label} validation returned successfully.`,
        data,
      });
      onReload?.();
    } catch (error) {
      setResult({
        ok: false,
        title: kind === 'save' ? 'Setup save failed' : 'Validation failed',
        message: error?.message || String(error),
        data: error?.body || null,
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <SideDrawer
      open={drawer?.type === 'connectors'}
      title="Connector Validation"
      subtitle="Save setup drafts, validate stored collector config, and inspect sample-event proof."
      onClose={onClose}
      actions={
        <Link className="btn btn-sm" to={selected?.settingsPath || '/settings'}>
          Open settings
        </Link>
      }
    >
      <label className="field">
        <span>Connector lane</span>
        <select value={selected?.id || ''} onChange={(event) => setSelectedId(event.target.value)}>
          {connectorRows.map((connector) => (
            <option key={connector.id} value={connector.id}>
              {connector.label}
            </option>
          ))}
        </select>
      </label>
      {selected ? (
        <>
          <SummaryGrid
            data={{
              status: selected.status,
              category: selected.category,
              sample: selected.sample,
              required_fields: lane?.requiredFields?.join(', ') || 'stored setup fields',
            }}
            limit={4}
          />
          <div className="chip-row">
            <span className={`badge ${statusBadge(selected.status)}`}>{selected.status}</span>
            <span className="badge badge-info">{selected.provider}</span>
          </div>
          <p className="hint">{selected.detail}</p>
          <div className="actions">
            {canSaveSample && (
              <button
                className="btn"
                type="button"
                onClick={() => runAction('save')}
                disabled={busy}
              >
                Save setup draft
              </button>
            )}
            <button
              className="btn btn-primary"
              type="button"
              onClick={() => runAction('validate')}
              disabled={busy || !canValidate}
            >
              {busy ? 'Running...' : 'Validate now'}
            </button>
          </div>
          <ActionResult result={result} />
        </>
      ) : (
        <WorkspaceEmptyState
          compact
          title="No connectors loaded"
          description="Connector lanes will appear here after the command data refresh completes."
        />
      )}
    </SideDrawer>
  );
}

function RemediationDrawer({ drawer, reviews, onClose, onReload }) {
  const [selectedId, setSelectedId] = useState(drawer?.item?.id || reviews[0]?.id || '');
  const [comment, setComment] = useState('Reviewed in Command Center.');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const selected = selectById(reviews, selectedId);

  useEffect(() => {
    if (drawer?.type !== 'remediation') return;
    setSelectedId(drawer?.item?.id || reviews[0]?.id || '');
  }, [drawer, reviews]);

  const submitDecision = async (decision) => {
    if (!selected?.id) return;
    setBusy(true);
    setResult(null);
    try {
      const data = await api.approveRemediationChangeReview(selected.id, { decision, comment });
      setResult({
        ok: true,
        title: decision === 'approve' ? 'Approval recorded' : 'Denial recorded',
        message: `${selected.title || selected.id} was updated with a signed approval-chain entry.`,
        data,
      });
      onReload?.();
    } catch (error) {
      setResult({
        ok: false,
        title: 'Review update failed',
        message: error?.message || String(error),
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <SideDrawer
      open={drawer?.type === 'remediation'}
      title="Remediation Approval"
      subtitle="Review blast radius, approval quorum, rollback proof, and signed approval status."
      onClose={onClose}
      actions={
        <Link className="btn btn-sm" to="/infrastructure">
          Open infrastructure
        </Link>
      }
    >
      {reviews.length > 0 ? (
        <>
          <label className="field">
            <span>Change review</span>
            <select
              value={selected?.id || ''}
              onChange={(event) => setSelectedId(event.target.value)}
            >
              {reviews.map((review) => (
                <option key={review.id} value={review.id}>
                  {review.title || review.id}
                </option>
              ))}
            </select>
          </label>
          <SummaryGrid
            data={{
              asset: selected?.asset_id || 'unscoped',
              approval_status: selected?.approval_status || 'pending',
              approvals: `${selected?.approvals?.length || 0}/${selected?.required_approvers || 1}`,
              rollback: selected?.rollback_proof ? 'ready' : 'pending',
            }}
            limit={4}
          />
          <label className="field">
            <span>Approval comment</span>
            <textarea
              value={comment}
              onChange={(event) => setComment(event.target.value)}
              rows={4}
            />
          </label>
          <div className="actions">
            <button
              className="btn"
              type="button"
              onClick={() => submitDecision('deny')}
              disabled={busy}
            >
              Deny
            </button>
            <button
              className="btn btn-primary"
              type="button"
              onClick={() => submitDecision('approve')}
              disabled={busy}
            >
              {busy ? 'Signing...' : 'Approve'}
            </button>
          </div>
          <JsonDetails data={selected} label="Selected review" />
          <ActionResult result={result} />
        </>
      ) : (
        <WorkspaceEmptyState
          compact
          title="No reviews pending"
          description="New remediation reviews will appear here with approval quorum and rollback-proof state."
        />
      )}
    </SideDrawer>
  );
}

function RuleReplayDrawer({ drawer, rules, suppressionCount, onClose, onReload }) {
  const [selectedId, setSelectedId] = useState(drawer?.item?.id || rules[0]?.id || '');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const selected = selectById(rules, selectedId);

  useEffect(() => {
    if (drawer?.type !== 'rules') return;
    setSelectedId(drawer?.item?.id || rules[0]?.id || '');
  }, [drawer, rules]);

  const runReplay = async () => {
    if (!selected?.id) return;
    setBusy(true);
    setResult(null);
    try {
      const data = await api.contentRuleTest(selected.id, { source: 'command_center' });
      setResult({
        ok: true,
        title: 'Replay complete',
        message: `${selected.name || selected.title || selected.id} replay evidence is ready.`,
        data,
      });
      onReload?.();
    } catch (error) {
      setResult({ ok: false, title: 'Replay failed', message: error?.message || String(error) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <SideDrawer
      open={drawer?.type === 'rules'}
      title="Rule Replay and Promotion"
      subtitle="Validate noisy or stale detections before suppression or promotion decisions."
      onClose={onClose}
      actions={
        <Link className="btn btn-sm" to="/detection">
          Open detection
        </Link>
      }
    >
      {rules.length > 0 ? (
        <>
          <label className="field">
            <span>Rule</span>
            <select
              value={selected?.id || ''}
              onChange={(event) => setSelectedId(event.target.value)}
            >
              {rules.map((rule) => (
                <option key={rule.id} value={rule.id}>
                  {rule.name || rule.title || rule.id}
                </option>
              ))}
            </select>
          </label>
          <SummaryGrid
            data={{
              lifecycle: selected?.lifecycle || 'draft',
              replay_hits: selected?.last_test_match_count || 0,
              suppressions: suppressionCount[selected?.id] || 0,
              last_test_at: selected?.last_test_at || 'not run',
            }}
            limit={4}
          />
          <div className="actions">
            <button className="btn btn-primary" type="button" onClick={runReplay} disabled={busy}>
              {busy ? 'Running replay...' : 'Run replay'}
            </button>
            <Link
              className="btn"
              to={`/detection?rule=${encodeURIComponent(selected?.id || '')}&panel=promotion`}
            >
              Promotion view
            </Link>
          </div>
          <JsonDetails data={selected} label="Rule detail" />
          <ActionResult result={result} />
        </>
      ) : (
        <WorkspaceEmptyState
          compact
          title="No rules need tuning"
          description="Noisy and stale rules will appear here when replay or suppression review is needed."
        />
      )}
    </SideDrawer>
  );
}

function ReleaseDrawer({ drawer, releases, configData, sbomData, onClose }) {
  const activeRelease = releases[0] || null;
  return (
    <SideDrawer
      open={drawer?.type === 'release'}
      title="Release Readiness"
      subtitle="Check version inventory, SBOM state, package metadata, and rollback posture."
      onClose={onClose}
      actions={
        <Link className="btn btn-sm" to="/infrastructure">
          Open rollouts
        </Link>
      }
    >
      <SummaryGrid
        data={{
          current_version: configData?.version || configData?.app_version || 'unknown',
          latest_release: activeRelease?.version || activeRelease?.tag || 'unknown',
          sbom_components: sbomData?.components?.length || sbomData?.component_count || 0,
          release_candidates: releases.length,
        }}
        limit={4}
      />
      <JsonDetails data={activeRelease || releases} label="Release readiness evidence" />
    </SideDrawer>
  );
}

function EvidenceDrawer({ drawer, reportTemplates, complianceData, onClose, onReload }) {
  const [selectedId, setSelectedId] = useState(reportTemplates[0]?.id || 'command-center-pack');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const selected = selectById(reportTemplates, selectedId);

  useEffect(() => {
    if (drawer?.type !== 'evidence') return;
    setSelectedId(drawer?.item?.id || reportTemplates[0]?.id || 'command-center-pack');
  }, [drawer, reportTemplates]);

  const createEvidenceRun = async () => {
    setBusy(true);
    setResult(null);
    try {
      const data = await api.createReportRun({
        name: selected?.name || 'Command Center Evidence Pack',
        kind: selected?.kind || 'command_center_evidence',
        scope: selected?.scope || 'global',
        format: selected?.format || 'json',
        audience: selected?.audience || 'operations',
        source: 'command_center',
        summary: 'Evidence pack generated from Command Center lane health.',
      });
      setResult({
        ok: true,
        title: 'Evidence pack queued',
        message: 'A persisted report run was created for audit and operator review.',
        data,
      });
      onReload?.();
    } catch (error) {
      setResult({
        ok: false,
        title: 'Evidence export failed',
        message: error?.message || String(error),
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <SideDrawer
      open={drawer?.type === 'evidence'}
      title="Compliance Evidence Pack"
      subtitle="Persist a report run from operational truth, release metadata, and compliance posture."
      onClose={onClose}
      actions={
        <Link className="btn btn-sm" to="/reports">
          Open reports
        </Link>
      }
    >
      {reportTemplates.length > 0 && (
        <label className="field">
          <span>Template</span>
          <select
            value={selected?.id || ''}
            onChange={(event) => setSelectedId(event.target.value)}
          >
            {reportTemplates.map((template) => (
              <option key={template.id || template.name} value={template.id || template.name}>
                {template.name || template.title}
              </option>
            ))}
          </select>
        </label>
      )}
      <SummaryGrid
        data={{
          compliance_status: complianceData?.status || complianceData?.overall_status || 'unknown',
          templates: reportTemplates.length,
          selected: selected?.name || 'Command Center Evidence Pack',
        }}
        limit={3}
      />
      <button className="btn btn-primary" type="button" onClick={createEvidenceRun} disabled={busy}>
        {busy ? 'Creating...' : 'Create evidence pack'}
      </button>
      <ActionResult result={result} />
    </SideDrawer>
  );
}

export default function CommandActionDrawers({
  drawer,
  connectorRows,
  reviews,
  rules,
  releases,
  reportTemplates,
  suppressionCount,
  data,
  onClose,
  onReload,
}) {
  const tuningRules = useMemo(
    () => rules.filter((rule) => rule.enabled !== false).slice(0, 12),
    [rules],
  );

  return (
    <>
      <ConnectorDrawer
        drawer={drawer}
        connectorRows={connectorRows}
        onClose={onClose}
        onReload={onReload}
      />
      <RemediationDrawer drawer={drawer} reviews={reviews} onClose={onClose} onReload={onReload} />
      <RuleReplayDrawer
        drawer={drawer}
        rules={tuningRules}
        suppressionCount={suppressionCount}
        onClose={onClose}
        onReload={onReload}
      />
      <ReleaseDrawer
        drawer={drawer}
        releases={releases}
        configData={data.configData}
        sbomData={data.sbomData}
        onClose={onClose}
      />
      <EvidenceDrawer
        drawer={drawer}
        reportTemplates={reportTemplates}
        complianceData={data.complianceData}
        onClose={onClose}
        onReload={onReload}
      />
    </>
  );
}
