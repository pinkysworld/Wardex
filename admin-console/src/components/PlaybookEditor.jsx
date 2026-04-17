import { useState } from 'react';
import { useApi, useToast } from '../hooks.jsx';
import * as api from '../api.js';

const STEP_TYPES = [
  { value: 'CheckThreshold', label: 'Check Threshold', icon: '📊' },
  { value: 'MatchPattern', label: 'Match Pattern', icon: '🔍' },
  { value: 'RunAction', label: 'Run Action', icon: '⚡' },
  { value: 'Notify', label: 'Notify', icon: '🔔' },
  { value: 'Escalate', label: 'Escalate', icon: '🚨' },
  { value: 'Wait', label: 'Wait', icon: '⏱' },
];

function StepCard({ step, index, onRemove, onUpdate }) {
  const typeInfo = STEP_TYPES.find((t) => t.value === step.type) || STEP_TYPES[0];
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        padding: '10px 14px',
        background: 'var(--bg)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        marginBottom: 8,
      }}
    >
      <span style={{ fontSize: 20 }}>{typeInfo.icon}</span>
      <div style={{ flex: 1 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 }}>
          <select
            className="input"
            value={step.type}
            onChange={(e) => onUpdate({ ...step, type: e.target.value })}
            style={{ width: 160, fontSize: 12, padding: '3px 6px' }}
          >
            {STEP_TYPES.map((t) => (
              <option key={t.value} value={t.value}>
                {t.label}
              </option>
            ))}
          </select>
          <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Step {index + 1}</span>
        </div>
        <input
          className="input"
          value={step.description || ''}
          placeholder="Step description…"
          onChange={(e) => onUpdate({ ...step, description: e.target.value })}
          style={{ width: '100%', fontSize: 12 }}
        />
      </div>
      <button
        className="btn btn-ghost btn-sm"
        onClick={onRemove}
        title="Remove step"
        style={{ color: 'var(--danger)', fontSize: 16 }}
      >
        ×
      </button>
    </div>
  );
}

export default function PlaybookEditor() {
  const toast = useToast();
  const { data: playbookList } = useApi(api.playbooks);
  const [selected, setSelected] = useState(null);
  const [steps, setSteps] = useState([]);
  const [pbName, setPbName] = useState('');
  const [running, setRunning] = useState(false);

  const selectPlaybook = async (pb) => {
    setSelected(pb);
    setPbName(pb.name || pb.id || '');
    setSteps(
      (pb.steps || []).map((s, i) => ({
        type: s.type || 'RunAction',
        description: s.description || s.label || `Step ${i + 1}`,
      })),
    );
  };

  const addStep = () => {
    setSteps((prev) => [...prev, { type: 'RunAction', description: '' }]);
  };

  const updateStep = (idx, step) => {
    setSteps((prev) => prev.map((s, i) => (i === idx ? step : s)));
  };

  const removeStep = (idx) => {
    setSteps((prev) => prev.filter((_, i) => i !== idx));
  };

  const runPlaybook = async () => {
    if (!selected) return;
    setRunning(true);
    try {
      await api.playbookRun(selected.id || selected.name);
      toast('Playbook executed', 'success');
    } catch (e) {
      toast('Playbook run failed: ' + (e.message || e), 'error');
    }
    setRunning(false);
  };

  const list = Array.isArray(playbookList)
    ? playbookList
    : playbookList?.playbooks || playbookList?.items || [];

  return (
    <div>
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-title" style={{ marginBottom: 12 }}>
          Playbooks
        </div>
        {list.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Steps</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {list.map((pb, i) => (
                  <tr
                    key={pb.id || pb.name || i}
                    style={{
                      cursor: 'pointer',
                      background: selected === pb ? 'rgba(59,130,246,.06)' : undefined,
                    }}
                    onClick={() => selectPlaybook(pb)}
                  >
                    <td style={{ fontWeight: 500 }}>{pb.name || pb.id}</td>
                    <td>{pb.steps?.length || pb.step_count || '—'}</td>
                    <td>
                      <button
                        className="btn btn-ghost btn-sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          selectPlaybook(pb);
                        }}
                      >
                        Edit
                      </button>
                      <button
                        className="btn btn-ghost btn-sm"
                        style={{ color: 'var(--primary)' }}
                        onClick={async (e) => {
                          e.stopPropagation();
                          try {
                            await api.playbookRun(pb.id || pb.name);
                            toast('Playbook executed', 'success');
                          } catch (err) {
                            toast('Run failed: ' + (err.message || err), 'error');
                          }
                        }}
                      >
                        Run
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty">
            No playbooks defined. Create one using the DSL or add steps below.
          </div>
        )}
      </div>

      {selected && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>
            Edit: {pbName}
          </div>
          <div style={{ marginBottom: 12 }}>
            {steps.map((step, i) => (
              <StepCard
                key={i}
                step={step}
                index={i}
                onRemove={() => removeStep(i)}
                onUpdate={(s) => updateStep(i, s)}
              />
            ))}
            {steps.length === 0 && (
              <div className="empty" style={{ marginBottom: 8 }}>
                No steps yet.
              </div>
            )}
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-ghost" onClick={addStep}>
              + Add Step
            </button>
            <button className="btn btn-primary" onClick={runPlaybook} disabled={running}>
              {running ? 'Running…' : '▶ Run Playbook'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
