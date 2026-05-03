import { useState } from 'react';
import { useApi, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import { JsonDetails, SummaryGrid } from './operator.jsx';
import { formatDateTime } from './operatorUtils.js';

const TABS = [
  'compliance',
  'policy',
  'crypto',
  'digital-twin',
  'harness',
  'deception',
  'enforcement',
];

const POLICY_OPERATORS = [
  {
    value: 'max',
    label: 'Max severity',
    description: 'Choose the more severe decision when the two candidates disagree.',
  },
  {
    value: 'min',
    label: 'Min severity',
    description: 'Prefer the least disruptive decision to model conservative enforcement.',
  },
  {
    value: 'left',
    label: 'Left priority',
    description: 'Always prefer decision A when both paths are present.',
  },
  {
    value: 'right',
    label: 'Right priority',
    description: 'Always prefer decision B when both paths are present.',
  },
];

const DIGITAL_TWIN_EVENTS = [
  {
    value: 'cpu_spike',
    label: 'CPU spike',
    description: 'Drive the host into a degraded state with critical CPU usage.',
  },
  {
    value: 'memory_exhaust',
    label: 'Memory exhaustion',
    description: 'Model memory pressure and alert generation on an overloaded host.',
  },
  {
    value: 'network_flood',
    label: 'Network flood',
    description: 'Stress network ingress to model flood and saturation behavior.',
  },
  {
    value: 'malware_inject',
    label: 'Malware injection',
    description: 'Raise threat score and force the twin into an under-attack state.',
  },
  {
    value: 'process_burst',
    label: 'Process burst',
    description: 'Simulate runaway process creation to test process-burst alerts.',
  },
  {
    value: 'connection_burst',
    label: 'Connection burst',
    description: 'Simulate a sudden spike in open connections and lateral activity.',
  },
];

const DECEPTION_TYPES = [
  {
    value: 'honeypot',
    label: 'Honeypot',
    description: 'Deploy a service lure that attracts interactive attacker behavior.',
  },
  {
    value: 'honeyfile',
    label: 'Honey file',
    description: 'Deploy a file lure to track discovery and exfiltration attempts.',
  },
  {
    value: 'honeycredential',
    label: 'Honey credential',
    description: 'Plant credentials that should never be used legitimately.',
  },
  {
    value: 'honeyservice',
    label: 'Honey service',
    description: 'Expose a decoy internal service to observe probing and abuse.',
  },
  {
    value: 'canary',
    label: 'Canary token',
    description: 'Deploy a token that should only fire during unauthorized access.',
  },
];

function MetricCard({ label, value, meta }) {
  return (
    <div className="summary-card">
      <div className="summary-label">{label}</div>
      <div className="summary-value">{value}</div>
      {meta ? <div className="summary-meta">{meta}</div> : null}
    </div>
  );
}

function DataTable({ columns, rows, emptyMessage = 'No records available.', rowKey }) {
  if (!Array.isArray(rows) || rows.length === 0) return <div className="empty">{emptyMessage}</div>;

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.label}>{column.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={rowKey ? rowKey(row, index) : row.id || row.name || row.action || index}>
              {columns.map((column) => (
                <td key={column.label}>
                  {column.render ? column.render(row, index) : (row[column.key] ?? '-')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function BucketBars({ buckets }) {
  if (!Array.isArray(buckets) || buckets.length === 0)
    return <div className="empty">No bucket data yet.</div>;

  const maxCount = Math.max(...buckets, 1);

  return (
    <div>
      <div
        aria-label="Harness score coverage buckets"
        style={{
          display: 'grid',
          gridTemplateColumns: `repeat(${buckets.length}, minmax(0, 1fr))`,
          gap: 6,
          alignItems: 'end',
          minHeight: 140,
        }}
      >
        {buckets.map((count, index) => {
          const height = `${Math.max((Number(count) / maxCount) * 100, count > 0 ? 8 : 2)}%`;
          return (
            <div key={`bucket-${index}`} style={{ display: 'grid', gap: 6 }}>
              <div
                style={{
                  height,
                  minHeight: 6,
                  borderRadius: 8,
                  background: 'var(--primary)',
                  opacity: count > 0 ? 0.9 : 0.25,
                }}
              />
              <div style={{ fontSize: 10, color: 'var(--text-secondary)', textAlign: 'center' }}>
                {index + 1}
              </div>
              <div style={{ fontSize: 11, textAlign: 'center' }}>{count}</div>
            </div>
          );
        })}
      </div>
      <div className="hint" style={{ marginTop: 8 }}>
        Buckets show how much of the detector score range the harness exercised during the last run.
      </div>
    </div>
  );
}

function formatPercent(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return '0%';
  return `${Math.round(numeric * 100)}%`;
}

function formatScore(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return '0.00';
  return numeric.toFixed(2);
}

function parseFloatField(label, value, min, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) throw new Error(`${label} must be a valid number.`);
  if (parsed < min || parsed > max) {
    throw new Error(`${label} must be between ${min} and ${max}.`);
  }
  return parsed;
}

function parseIntField(label, value, min, max) {
  const parsed = Number.parseInt(String(value), 10);
  if (!Number.isInteger(parsed)) throw new Error(`${label} must be an integer.`);
  if (parsed < min || parsed > max) {
    throw new Error(`${label} must be between ${min} and ${max}.`);
  }
  return parsed;
}

export default function SecurityPolicy() {
  const toast = useToast();
  const [tab, setTab] = useState('compliance');
  const { data: compliance } = useApi(api.complianceStatus);
  const { data: attestation } = useApi(api.attestationStatus);
  const { data: privacy } = useApi(api.privacyBudget);
  const { data: quantum, reload: reloadQuantum } = useApi(api.quantumKeyStatus);
  const { data: policy } = useApi(api.policyCurrent);
  const { data: twin, reload: reloadTwin } = useApi(api.digitalTwinStatus);
  const { data: deception, reload: reloadDeception } = useApi(api.deceptionStatus);
  const { data: enforcement, reload: reloadEnforcement } = useApi(api.enforcementStatus);

  const [composeDraft, setComposeDraft] = useState({
    operator: 'max',
    scoreA: '0.80',
    batteryA: '42',
    scoreB: '0.35',
    batteryB: '88',
  });
  const [twinDraft, setTwinDraft] = useState({
    deviceId: 'lab-edge-01',
    eventType: 'cpu_spike',
  });
  const [harnessDraft, setHarnessDraft] = useState({
    tracesPerStrategy: '10',
    traceLength: '50',
    evasionThreshold: '1.5',
  });
  const [deceptionDraft, setDeceptionDraft] = useState({
    decoyType: 'honeypot',
    name: 'ssh-canary-01',
    description: 'SSH decoy on the engineering subnet.',
  });
  const [quarantineTarget, setQuarantineTarget] = useState('suspect-endpoint-01');

  const [composeResult, setComposeResult] = useState(null);
  const [simResult, setSimResult] = useState(null);
  const [harnessResult, setHarnessResult] = useState(null);
  const [deployResult, setDeployResult] = useState(null);
  const [quarantineResult, setQuarantineResult] = useState(null);

  const [composing, setComposing] = useState(false);
  const [rotatingKeys, setRotatingKeys] = useState(false);
  const [runningSimulation, setRunningSimulation] = useState(false);
  const [runningHarness, setRunningHarness] = useState(false);
  const [deployingDecoy, setDeployingDecoy] = useState(false);
  const [runningQuarantine, setRunningQuarantine] = useState(false);

  const twinDevices = Array.isArray(twin?.devices) ? twin.devices : [];
  const harnessStrategies = Array.isArray(harnessResult?.strategies)
    ? harnessResult.strategies
    : [];
  const deceptionDecoys = Array.isArray(deception?.decoys) ? deception.decoys : [];
  const attackerProfiles = Array.isArray(deception?.attacker_profiles)
    ? deception.attacker_profiles
    : [];
  const recentDeceptionActivity = deceptionDecoys
    .filter((decoy) => decoy.last_interaction?.timestamp)
    .sort(
      (left, right) =>
        Date.parse(right.last_interaction?.timestamp || 0) -
        Date.parse(left.last_interaction?.timestamp || 0),
    )
    .slice(0, 6);
  const recentHistory = Array.isArray(enforcement?.recent_history)
    ? enforcement.recent_history
    : [];

  const handleCompose = async (event) => {
    event.preventDefault();

    try {
      const payload = {
        operator: composeDraft.operator,
        score_a: parseFloatField('Decision A score', composeDraft.scoreA, 0, 100),
        battery_a: parseFloatField('Decision A battery', composeDraft.batteryA, 0, 100),
        score_b: parseFloatField('Decision B score', composeDraft.scoreB, 0, 100),
        battery_b: parseFloatField('Decision B battery', composeDraft.batteryB, 0, 100),
      };

      setComposing(true);
      const result = await api.policyCompose(payload);
      setComposeResult(result);
      toast('Policy preview updated', 'success');
    } catch (error) {
      toast(error?.message || 'Compose failed', 'error');
    } finally {
      setComposing(false);
    }
  };

  const handleRotateKeys = async () => {
    try {
      setRotatingKeys(true);
      await api.quantumRotate();
      await reloadQuantum();
      toast('Key rotation complete', 'success');
    } catch {
      toast('Rotation failed', 'error');
    } finally {
      setRotatingKeys(false);
    }
  };

  const handleSimulate = async (event) => {
    event.preventDefault();

    if (!twinDraft.deviceId.trim()) {
      toast('Device ID is required.', 'error');
      return;
    }

    try {
      setRunningSimulation(true);
      const result = await api.digitalTwinSimulate({
        device_id: twinDraft.deviceId.trim(),
        event_type: twinDraft.eventType,
      });
      setSimResult(result);
      await reloadTwin();
      toast('Simulation complete', 'success');
    } catch {
      toast('Simulation failed', 'error');
    } finally {
      setRunningSimulation(false);
    }
  };

  const handleHarnessRun = async (event) => {
    event.preventDefault();

    try {
      const payload = {
        traces_per_strategy: parseIntField(
          'Traces per strategy',
          harnessDraft.tracesPerStrategy,
          1,
          10,
        ),
        trace_length: parseIntField('Trace length', harnessDraft.traceLength, 10, 500),
        evasion_threshold: parseFloatField(
          'Evasion threshold',
          harnessDraft.evasionThreshold,
          0.1,
          10,
        ),
      };

      setRunningHarness(true);
      const result = await api.harnessRun(payload);
      setHarnessResult(result);
      toast('Harness run complete', 'success');
    } catch (error) {
      toast(error?.message || 'Harness run failed', 'error');
    } finally {
      setRunningHarness(false);
    }
  };

  const handleDeployDecoy = async (event) => {
    event.preventDefault();

    if (!deceptionDraft.name.trim()) {
      toast('Decoy name is required.', 'error');
      return;
    }

    try {
      setDeployingDecoy(true);
      const result = await api.deceptionDeploy({
        decoy_type: deceptionDraft.decoyType,
        name: deceptionDraft.name.trim(),
        description: deceptionDraft.description.trim() || undefined,
      });
      setDeployResult(result);
      await reloadDeception();
      toast('Decoy deployed', 'success');
    } catch {
      toast('Decoy deployment failed', 'error');
    } finally {
      setDeployingDecoy(false);
    }
  };

  const handleQuarantine = async (event) => {
    event.preventDefault();

    if (!quarantineTarget.trim()) {
      toast('Target is required.', 'error');
      return;
    }

    try {
      setRunningQuarantine(true);
      const result = await api.quarantine({ target: quarantineTarget.trim() });
      setQuarantineResult(result);
      await reloadEnforcement();
      toast('Target quarantined', 'success');
    } catch {
      toast('Quarantine failed', 'error');
    } finally {
      setRunningQuarantine(false);
    }
  };

  return (
    <div>
      <div className="tabs" style={{ flexWrap: 'wrap' }}>
        {TABS.map((item) => (
          <button
            key={item}
            className={`tab ${tab === item ? 'active' : ''}`}
            onClick={() => setTab(item)}
          >
            {item.replace(/-/g, ' ').replace(/^\w/, (value) => value.toUpperCase())}
          </button>
        ))}
      </div>

      {tab === 'compliance' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Compliance Status
            </div>
            <SummaryGrid data={compliance} limit={10} />
            <JsonDetails data={compliance} />
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Attestation
            </div>
            <SummaryGrid data={attestation} limit={10} />
            <JsonDetails data={attestation} />
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Privacy Budget
            </div>
            <SummaryGrid data={privacy} limit={10} />
            <JsonDetails data={privacy} />
          </div>
        </div>
      )}

      {tab === 'policy' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Current Policy
            </div>
            <SummaryGrid data={policy} limit={12} />
            <JsonDetails data={policy} />
          </div>

          <div className="card">
            <div className="card-header">
              <div>
                <span className="card-title">Compose Decision Preview</span>
                <div className="hint">
                  Model how the policy engine resolves two candidate decisions before rollout.
                </div>
              </div>
            </div>
            <form onSubmit={handleCompose} style={{ display: 'grid', gap: 16 }}>
              <label style={{ display: 'grid', gap: 6 }}>
                <span>Composition Operator</span>
                <select
                  aria-label="Policy operator"
                  className="form-select"
                  value={composeDraft.operator}
                  onChange={(event) =>
                    setComposeDraft((current) => ({ ...current, operator: event.target.value }))
                  }
                >
                  {POLICY_OPERATORS.map((operator) => (
                    <option key={operator.value} value={operator.value}>
                      {operator.label}
                    </option>
                  ))}
                </select>
              </label>

              <div className="hint">
                {
                  POLICY_OPERATORS.find((operator) => operator.value === composeDraft.operator)
                    ?.description
                }
              </div>

              <div
                className="card-grid"
                style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}
              >
                <label style={{ display: 'grid', gap: 6 }}>
                  <span>Decision A Score</span>
                  <input
                    aria-label="Decision A score"
                    className="form-input"
                    value={composeDraft.scoreA}
                    onChange={(event) =>
                      setComposeDraft((current) => ({ ...current, scoreA: event.target.value }))
                    }
                  />
                </label>
                <label style={{ display: 'grid', gap: 6 }}>
                  <span>Decision A Battery %</span>
                  <input
                    aria-label="Decision A battery"
                    className="form-input"
                    value={composeDraft.batteryA}
                    onChange={(event) =>
                      setComposeDraft((current) => ({ ...current, batteryA: event.target.value }))
                    }
                  />
                </label>
                <label style={{ display: 'grid', gap: 6 }}>
                  <span>Decision B Score</span>
                  <input
                    aria-label="Decision B score"
                    className="form-input"
                    value={composeDraft.scoreB}
                    onChange={(event) =>
                      setComposeDraft((current) => ({ ...current, scoreB: event.target.value }))
                    }
                  />
                </label>
                <label style={{ display: 'grid', gap: 6 }}>
                  <span>Decision B Battery %</span>
                  <input
                    aria-label="Decision B battery"
                    className="form-input"
                    value={composeDraft.batteryB}
                    onChange={(event) =>
                      setComposeDraft((current) => ({ ...current, batteryB: event.target.value }))
                    }
                  />
                </label>
              </div>

              <div className="btn-group">
                <button className="btn btn-sm btn-primary" type="submit" disabled={composing}>
                  {composing ? 'Composing...' : 'Compose and Preview'}
                </button>
              </div>
            </form>

            {composeResult ? (
              <>
                <div className="summary-grid" style={{ marginTop: 16 }}>
                  <MetricCard
                    label="Resolved Level"
                    value={composeResult.result?.level || 'No decision'}
                    meta={composeResult.result?.action || 'No action generated'}
                  />
                  <MetricCard
                    label="Conflict"
                    value={composeResult.conflict ? 'Resolved' : 'None'}
                    meta={composeResult.conflict?.resolution || 'No conflict detected'}
                  />
                </div>
                <JsonDetails data={composeResult} label="Composition details" />
              </>
            ) : (
              <div className="hint" style={{ marginTop: 16 }}>
                Run a composition preview to inspect the merged decision and conflict handling.
              </div>
            )}
          </div>
        </div>
      )}

      {tab === 'crypto' && (
        <div className="card">
          <div className="card-header">
            <div>
              <span className="card-title">Post-Quantum Key Status</span>
              <div className="hint">
                Rotate the active epoch and confirm the new cryptographic state.
              </div>
            </div>
            <button
              className="btn btn-sm btn-primary"
              onClick={handleRotateKeys}
              disabled={rotatingKeys}
            >
              {rotatingKeys ? 'Rotating...' : 'Rotate Keys'}
            </button>
          </div>
          <SummaryGrid data={quantum} limit={10} />
          <JsonDetails data={quantum} />
        </div>
      )}

      {tab === 'digital-twin' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Digital Twin Inventory
            </div>
            <div className="summary-grid" style={{ marginBottom: 16 }}>
              <MetricCard
                label="Registered Twins"
                value={twin?.twin_count || 0}
                meta="Tracked device models ready for simulation."
              />
              <MetricCard
                label="Last Run Alerts"
                value={simResult?.alerts || 0}
                meta={
                  simResult
                    ? `${simResult.event_type} on ${simResult.device_id}`
                    : 'No simulation run yet.'
                }
              />
              <MetricCard
                label="Last Run Transitions"
                value={simResult?.transitions || 0}
                meta={
                  simResult?.seeded_device
                    ? 'Latest run seeded a new device twin.'
                    : 'Latest run used an existing twin.'
                }
              />
            </div>
            <DataTable
              columns={[
                { label: 'Device', key: 'device_id' },
                {
                  label: 'State',
                  render: (row) => (
                    <span className="badge badge-info">{row.state || 'Unknown'}</span>
                  ),
                },
                { label: 'Threat Score', render: (row) => formatScore(row.threat_score) },
                { label: 'CPU', render: (row) => `${Math.round(Number(row.cpu_load) || 0)}%` },
                { label: 'Processes', key: 'processes' },
              ]}
              rows={twinDevices}
              emptyMessage="No twins registered yet. The simulation builder can seed the first device automatically."
              rowKey={(row) => row.device_id}
            />
            <JsonDetails data={twin} label="Twin inventory details" />
          </div>

          <div className="card">
            <div className="card-header">
              <div>
                <span className="card-title">Simulation Builder</span>
                <div className="hint">
                  Select a device and event profile to generate a concrete twin result.
                </div>
              </div>
            </div>
            <form onSubmit={handleSimulate} style={{ display: 'grid', gap: 16 }}>
              <label style={{ display: 'grid', gap: 6 }}>
                <span>Device ID</span>
                <input
                  aria-label="Twin device id"
                  className="form-input"
                  value={twinDraft.deviceId}
                  onChange={(event) =>
                    setTwinDraft((current) => ({ ...current, deviceId: event.target.value }))
                  }
                />
              </label>
              <label style={{ display: 'grid', gap: 6 }}>
                <span>Event Profile</span>
                <select
                  aria-label="Twin event profile"
                  className="form-select"
                  value={twinDraft.eventType}
                  onChange={(event) =>
                    setTwinDraft((current) => ({ ...current, eventType: event.target.value }))
                  }
                >
                  {DIGITAL_TWIN_EVENTS.map((item) => (
                    <option key={item.value} value={item.value}>
                      {item.label}
                    </option>
                  ))}
                </select>
              </label>
              <div className="hint">
                {
                  DIGITAL_TWIN_EVENTS.find((item) => item.value === twinDraft.eventType)
                    ?.description
                }
              </div>
              <div className="btn-group">
                <button
                  className="btn btn-sm btn-primary"
                  type="submit"
                  disabled={runningSimulation}
                >
                  {runningSimulation ? 'Running...' : 'Run Simulation'}
                </button>
              </div>
            </form>

            {simResult ? (
              <>
                <div className="summary-grid" style={{ marginTop: 16 }}>
                  <MetricCard
                    label="Ticks Simulated"
                    value={simResult.ticks_simulated || 0}
                    meta={`Event profile: ${simResult.event_type || 'n/a'}`}
                  />
                  <MetricCard
                    label="Alerts Generated"
                    value={simResult.alerts || 0}
                    meta={
                      simResult.seeded_device
                        ? 'A new twin was seeded for this run.'
                        : 'Run executed against an existing twin.'
                    }
                  />
                  <MetricCard
                    label="State Transitions"
                    value={simResult.transitions || 0}
                    meta={`Tracked twins: ${simResult.twin_count || twin?.twin_count || 0}`}
                  />
                </div>
                {simResult.final_state ? (
                  <div style={{ marginTop: 16 }}>
                    <div className="card-title" style={{ marginBottom: 8 }}>
                      Final Twin State
                    </div>
                    <SummaryGrid data={simResult.final_state} limit={10} />
                  </div>
                ) : null}
                <div style={{ marginTop: 16 }}>
                  <div className="card-title" style={{ marginBottom: 8 }}>
                    Alerts Generated
                  </div>
                  <DataTable
                    columns={[
                      { label: 'Type', key: 'alert_type' },
                      { label: 'Message', key: 'message' },
                      { label: 'Severity', render: (row) => formatScore(row.severity) },
                    ]}
                    rows={simResult.alerts_generated}
                    emptyMessage="This simulation did not emit any alerts."
                  />
                </div>
                <div style={{ marginTop: 16 }}>
                  <div className="card-title" style={{ marginBottom: 8 }}>
                    State Transitions
                  </div>
                  <DataTable
                    columns={[
                      { label: 'Device', key: 'device_id' },
                      { label: 'From', render: (row) => String(row.from || '') || '-' },
                      { label: 'To', render: (row) => String(row.to || '') || '-' },
                      { label: 'Reason', key: 'reason' },
                    ]}
                    rows={simResult.state_transitions}
                    emptyMessage="This simulation did not change device state."
                  />
                </div>
                <JsonDetails data={simResult} label="Simulation details" />
              </>
            ) : (
              <div className="empty" style={{ marginTop: 16 }}>
                Run a simulation to inspect alerts, transitions, and the final twin snapshot.
              </div>
            )}
          </div>
        </div>
      )}

      {tab === 'harness' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-header">
              <div>
                <span className="card-title">Adversarial Harness Run</span>
                <div className="hint">
                  Tune the baseline harness config and inspect evasion versus coverage results.
                </div>
              </div>
            </div>
            <form onSubmit={handleHarnessRun} style={{ display: 'grid', gap: 16 }}>
              <div
                className="card-grid"
                style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}
              >
                <label style={{ display: 'grid', gap: 6 }}>
                  <span>Traces per Strategy</span>
                  <input
                    aria-label="Harness traces per strategy"
                    className="form-input"
                    value={harnessDraft.tracesPerStrategy}
                    onChange={(event) =>
                      setHarnessDraft((current) => ({
                        ...current,
                        tracesPerStrategy: event.target.value,
                      }))
                    }
                  />
                </label>
                <label style={{ display: 'grid', gap: 6 }}>
                  <span>Trace Length</span>
                  <input
                    aria-label="Harness trace length"
                    className="form-input"
                    value={harnessDraft.traceLength}
                    onChange={(event) =>
                      setHarnessDraft((current) => ({
                        ...current,
                        traceLength: event.target.value,
                      }))
                    }
                  />
                </label>
                <label style={{ display: 'grid', gap: 6 }}>
                  <span>Evasion Threshold</span>
                  <input
                    aria-label="Harness evasion threshold"
                    className="form-input"
                    value={harnessDraft.evasionThreshold}
                    onChange={(event) =>
                      setHarnessDraft((current) => ({
                        ...current,
                        evasionThreshold: event.target.value,
                      }))
                    }
                  />
                </label>
              </div>
              <div className="btn-group">
                <button className="btn btn-sm btn-primary" type="submit" disabled={runningHarness}>
                  {runningHarness ? 'Running...' : 'Run Harness'}
                </button>
              </div>
            </form>

            {harnessResult ? (
              <>
                <div className="summary-grid" style={{ marginTop: 16 }}>
                  <MetricCard
                    label="Evasion Rate"
                    value={formatPercent(harnessResult.evasion_rate)}
                    meta={`${harnessResult.evasion_count || 0} of ${harnessResult.total_count || 0} traces evaded.`}
                  />
                  <MetricCard
                    label="Coverage Ratio"
                    value={formatPercent(harnessResult.coverage_ratio)}
                    meta={`${harnessResult.transition_count || 0} bucket transitions recorded.`}
                  />
                  <MetricCard
                    label="Trace Length"
                    value={harnessResult.config?.trace_length || '-'}
                    meta={`${harnessResult.config?.traces_per_strategy || '-'} traces per strategy.`}
                  />
                </div>

                <div style={{ marginTop: 16 }}>
                  <div className="card-title" style={{ marginBottom: 8 }}>
                    Strategy Breakdown
                  </div>
                  <DataTable
                    columns={[
                      { label: 'Strategy', key: 'strategy' },
                      { label: 'Total', key: 'total' },
                      { label: 'Evaded', key: 'evaded' },
                      { label: 'Detected', key: 'detected' },
                      { label: 'Avg Max Score', render: (row) => formatScore(row.avg_max_score) },
                    ]}
                    rows={harnessStrategies}
                    emptyMessage="No per-strategy data available for this harness run."
                    rowKey={(row) => row.strategy}
                  />
                </div>

                <div style={{ marginTop: 16 }}>
                  <div className="card-title" style={{ marginBottom: 8 }}>
                    Score Buckets
                  </div>
                  <BucketBars buckets={harnessResult.score_buckets} />
                </div>
                <JsonDetails data={harnessResult} label="Harness details" />
              </>
            ) : (
              <div className="empty" style={{ marginTop: 16 }}>
                Run the adversarial harness to inspect evasion rate and score-space coverage.
              </div>
            )}
          </div>
        </div>
      )}

      {tab === 'deception' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Deception Posture
            </div>
            <div className="summary-grid" style={{ marginBottom: 16 }}>
              <MetricCard
                label="Active Decoys"
                value={deception?.active_decoys || 0}
                meta={`${deception?.total_decoys || 0} total decoys are tracked.`}
              />
              <MetricCard
                label="Interactions"
                value={deception?.total_interactions || 0}
                meta={`${deception?.high_threat_interactions || 0} interactions scored high threat.`}
              />
              <MetricCard
                label="Attacker Profiles"
                value={attackerProfiles.length}
                meta="Profiles are grouped by source touching one or more decoys."
              />
            </div>

            <div className="card-title" style={{ marginBottom: 8 }}>
              Decoy Inventory
            </div>
            <DataTable
              columns={[
                { label: 'Name', key: 'name' },
                { label: 'Type', key: 'decoy_type' },
                {
                  label: 'Status',
                  render: (row) => (
                    <span className={`badge ${row.deployed ? 'badge-ok' : 'badge-err'}`}>
                      {row.deployed ? 'Active' : 'Disabled'}
                    </span>
                  ),
                },
                { label: 'Interactions', key: 'interaction_count' },
                {
                  label: 'Last Interaction',
                  render: (row) => formatDateTime(row.last_interaction?.timestamp),
                },
              ]}
              rows={deceptionDecoys}
              emptyMessage="No decoys have been deployed yet."
              rowKey={(row) => row.id}
            />

            <div className="card-title" style={{ marginTop: 16, marginBottom: 8 }}>
              Attacker Profiles
            </div>
            <DataTable
              columns={[
                { label: 'Source', key: 'source_id' },
                { label: 'Interactions', key: 'interaction_count' },
                {
                  label: 'Threat Score',
                  render: (row) => Number(row.threat_score || 0).toFixed(1),
                },
                {
                  label: 'Decoys Touched',
                  render: (row) =>
                    Array.isArray(row.decoys_touched) && row.decoys_touched.length > 0
                      ? row.decoys_touched.join(', ')
                      : '—',
                },
              ]}
              rows={attackerProfiles}
              emptyMessage="No attacker profiles have been grouped yet."
              rowKey={(row) => row.source_id}
            />

            <div className="card-title" style={{ marginTop: 16, marginBottom: 8 }}>
              Recent Decoy Interactions
            </div>
            <DataTable
              columns={[
                { label: 'Decoy', key: 'name' },
                {
                  label: 'Last Seen',
                  render: (row) => formatDateTime(row.last_interaction?.timestamp),
                },
                { label: 'Interactions', key: 'interaction_count' },
                {
                  label: 'Average Threat',
                  render: (row) => Number(row.avg_threat_score || 0).toFixed(1),
                },
              ]}
              rows={recentDeceptionActivity}
              emptyMessage="No recent decoy interactions have been recorded yet."
              rowKey={(row) => `${row.id}-${row.last_interaction?.timestamp || 'none'}`}
            />
            <JsonDetails data={deception} label="Deception details" />
          </div>

          <div className="card">
            <div className="card-header">
              <div>
                <span className="card-title">Deploy Decoy</span>
                <div className="hint">
                  Add a specific lure and then confirm it appears in the live decoy inventory.
                </div>
              </div>
            </div>
            <form onSubmit={handleDeployDecoy} style={{ display: 'grid', gap: 16 }}>
              <label style={{ display: 'grid', gap: 6 }}>
                <span>Decoy Type</span>
                <select
                  aria-label="Decoy type"
                  className="form-select"
                  value={deceptionDraft.decoyType}
                  onChange={(event) =>
                    setDeceptionDraft((current) => ({ ...current, decoyType: event.target.value }))
                  }
                >
                  {DECEPTION_TYPES.map((item) => (
                    <option key={item.value} value={item.value}>
                      {item.label}
                    </option>
                  ))}
                </select>
              </label>
              <div className="hint">
                {
                  DECEPTION_TYPES.find((item) => item.value === deceptionDraft.decoyType)
                    ?.description
                }
              </div>
              <label style={{ display: 'grid', gap: 6 }}>
                <span>Decoy Name</span>
                <input
                  aria-label="Decoy name"
                  className="form-input"
                  value={deceptionDraft.name}
                  onChange={(event) =>
                    setDeceptionDraft((current) => ({ ...current, name: event.target.value }))
                  }
                />
              </label>
              <label style={{ display: 'grid', gap: 6 }}>
                <span>Description</span>
                <textarea
                  aria-label="Decoy description"
                  className="form-input"
                  rows={4}
                  value={deceptionDraft.description}
                  onChange={(event) =>
                    setDeceptionDraft((current) => ({
                      ...current,
                      description: event.target.value,
                    }))
                  }
                />
              </label>
              <div className="btn-group">
                <button className="btn btn-sm btn-primary" type="submit" disabled={deployingDecoy}>
                  {deployingDecoy ? 'Deploying...' : 'Deploy Decoy'}
                </button>
              </div>
            </form>

            {deployResult ? (
              <div style={{ marginTop: 16 }}>
                <div className="summary-grid">
                  <MetricCard
                    label="Last Deploy Status"
                    value={deployResult.status || 'deployed'}
                  />
                  <MetricCard label="Decoy ID" value={deployResult.decoy_id || '-'} />
                </div>
              </div>
            ) : null}

            <div className="card-title" style={{ marginBottom: 8, marginTop: 16 }}>
              Attacker Profiles
            </div>
            <DataTable
              columns={[
                { label: 'Source', key: 'source_id' },
                { label: 'Interactions', key: 'interaction_count' },
                {
                  label: 'Threat Score',
                  render: (row) => formatScore(row.threat_score),
                },
                {
                  label: 'Decoys Touched',
                  render: (row) =>
                    Array.isArray(row.decoys_touched) ? row.decoys_touched.join(', ') : '-',
                },
              ]}
              rows={attackerProfiles}
              emptyMessage="No attacker profiles have been recorded yet."
              rowKey={(row) => row.source_id}
            />
          </div>
        </div>
      )}

      {tab === 'enforcement' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Enforcement Status
            </div>
            <div className="summary-grid" style={{ marginBottom: 16 }}>
              <MetricCard
                label="Process Enforcer"
                value={enforcement?.process_enforcer || 'inactive'}
                meta="Local process response controls."
              />
              <MetricCard
                label="Network Enforcer"
                value={enforcement?.network_enforcer || 'inactive'}
                meta="Network throttling and block actions."
              />
              <MetricCard
                label="Filesystem Enforcer"
                value={enforcement?.filesystem_enforcer || 'inactive'}
                meta="Path quarantine and local containment actions."
              />
              <MetricCard
                label="Recorded Actions"
                value={enforcement?.history_len || 0}
                meta={`${enforcement?.topology_nodes || 0} topology nodes tracked.`}
              />
            </div>
            <SummaryGrid
              data={enforcement?.tpm ? { tpm: enforcement.tpm } : enforcement}
              limit={6}
            />
            <JsonDetails data={enforcement} label="Enforcement details" />
          </div>

          <div className="card">
            <div className="card-header">
              <div>
                <span className="card-title">Quarantine Target</span>
                <div className="hint">
                  Execute the quarantine workflow and inspect the exact actions returned by the
                  engine.
                </div>
              </div>
            </div>
            <form onSubmit={handleQuarantine} style={{ display: 'grid', gap: 16 }}>
              <label style={{ display: 'grid', gap: 6 }}>
                <span>Target</span>
                <input
                  aria-label="Enforcement target"
                  className="form-input"
                  value={quarantineTarget}
                  onChange={(event) => setQuarantineTarget(event.target.value)}
                />
              </label>
              <div className="btn-group">
                <button
                  className="btn btn-sm btn-primary"
                  type="submit"
                  disabled={runningQuarantine}
                >
                  {runningQuarantine ? 'Quarantining...' : 'Quarantine Target'}
                </button>
              </div>
            </form>

            {quarantineResult ? (
              <>
                <div className="summary-grid" style={{ marginTop: 16 }}>
                  <MetricCard label="Target" value={quarantineResult.target || '-'} />
                  <MetricCard label="Actions" value={quarantineResult.actions || 0} />
                </div>
                <div style={{ marginTop: 16 }}>
                  <div className="card-title" style={{ marginBottom: 8 }}>
                    Last Quarantine Result
                  </div>
                  <DataTable
                    columns={[
                      { label: 'Action', key: 'action' },
                      {
                        label: 'Success',
                        render: (row) => (
                          <span className={`badge ${row.success ? 'badge-ok' : 'badge-err'}`}>
                            {row.success ? 'Yes' : 'No'}
                          </span>
                        ),
                      },
                      { label: 'Detail', key: 'detail' },
                    ]}
                    rows={quarantineResult.results}
                    emptyMessage="The enforcement engine did not return action details."
                  />
                </div>
              </>
            ) : null}

            <div className="card-title" style={{ marginBottom: 8, marginTop: 16 }}>
              Recent Enforcement History
            </div>
            <DataTable
              columns={[
                { label: 'Action', key: 'action' },
                {
                  label: 'Success',
                  render: (row) => (
                    <span className={`badge ${row.success ? 'badge-ok' : 'badge-err'}`}>
                      {row.success ? 'Yes' : 'No'}
                    </span>
                  ),
                },
                { label: 'Detail', key: 'detail' },
                {
                  label: 'Rollback',
                  render: (row) => row.rollback_command || 'n/a',
                },
              ]}
              rows={recentHistory}
              emptyMessage="No enforcement history has been recorded yet."
            />
          </div>
        </div>
      )}
    </div>
  );
}
