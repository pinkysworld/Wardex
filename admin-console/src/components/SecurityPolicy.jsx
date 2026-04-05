import { useState } from 'react';
import { useApi, useToast } from '../hooks.jsx';
import * as api from '../api.js';

export default function SecurityPolicy() {
  const toast = useToast();
  const [tab, setTab] = useState('compliance');
  const { data: compliance } = useApi(api.complianceStatus);
  const { data: attestation } = useApi(api.attestationStatus);
  const { data: privacy } = useApi(api.privacyBudget);
  const { data: quantum } = useApi(api.quantumKeyStatus);
  const { data: policy } = useApi(api.policyCurrent);
  const { data: twin } = useApi(api.digitalTwinStatus);
  const [composeResult, setComposeResult] = useState(null);
  const [simResult, setSimResult] = useState(null);
  const [harnessResult, setHarnessResult] = useState(null);

  return (
    <div>
      <div className="tabs">
        {['compliance', 'policy', 'crypto', 'digital-twin', 'harness'].map(t => (
          <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
            {t.replace(/-/g, ' ').replace(/^\w/, c => c.toUpperCase())}
          </button>
        ))}
      </div>

      {tab === 'compliance' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Compliance Status</div>
            <div className="json-block">{JSON.stringify(compliance, null, 2)}</div>
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Attestation</div>
            <div className="json-block">{JSON.stringify(attestation, null, 2)}</div>
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Privacy Budget</div>
            <div className="json-block">{JSON.stringify(privacy, null, 2)}</div>
          </div>
        </div>
      )}

      {tab === 'policy' && (
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header">
              <span className="card-title">Current Policy</span>
              <button className="btn btn-sm btn-primary" onClick={async () => {
                try {
                  const r = await api.policyCompose({ merge: true });
                  setComposeResult(r);
                  toast('Policy composed', 'success');
                } catch { toast('Compose failed', 'error'); }
              }}>Compose & Preview</button>
            </div>
            <div className="json-block">{JSON.stringify(policy, null, 2)}</div>
          </div>
          {composeResult && (
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Composed Policy Preview</div>
              <div className="json-block">{JSON.stringify(composeResult, null, 2)}</div>
            </div>
          )}
        </>
      )}

      {tab === 'crypto' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Post-Quantum Key Status</span>
            <button className="btn btn-sm btn-primary" onClick={async () => {
              try { await api.quantumRotate(); toast('Key rotated', 'success'); } catch { toast('Rotation failed', 'error'); }
            }}>Rotate Keys</button>
          </div>
          <div className="json-block">{JSON.stringify(quantum, null, 2)}</div>
        </div>
      )}

      {tab === 'digital-twin' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Digital Twin</span>
            <button className="btn btn-sm btn-primary" onClick={async () => {
              try {
                const r = await api.digitalTwinSimulate({ scenario: 'default' });
                setSimResult(r);
                toast('Simulation complete', 'success');
              } catch { toast('Simulation failed', 'error'); }
            }}>Run Simulation</button>
          </div>
          <div className="json-block" style={{ marginBottom: 16 }}>{JSON.stringify(twin, null, 2)}</div>
          {simResult && (
            <>
              <div className="card-title" style={{ marginBottom: 8 }}>Simulation Results</div>
              <div className="json-block">{JSON.stringify(simResult, null, 2)}</div>
            </>
          )}
        </div>
      )}

      {tab === 'harness' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Adversarial Harness</span>
            <button className="btn btn-sm btn-primary" onClick={async () => {
              try {
                const r = await api.harnessRun({ campaign: 'default' });
                setHarnessResult(r);
                toast('Harness run complete', 'success');
              } catch { toast('Harness run failed', 'error'); }
            }}>Run Harness</button>
          </div>
          {harnessResult ? (
            <div className="json-block">{JSON.stringify(harnessResult, null, 2)}</div>
          ) : (
            <div className="empty">Run the adversarial harness to test detection coverage</div>
          )}
        </div>
      )}
    </div>
  );
}
