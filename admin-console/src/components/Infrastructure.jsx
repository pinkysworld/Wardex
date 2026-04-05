import { useState } from 'react';
import { useApi, useToast } from '../hooks.jsx';
import * as api from '../api.js';

export default function Infrastructure() {
  const toast = useToast();
  const [tab, setTab] = useState('monitor');
  const { data: monSt } = useApi(api.monitorStatus);
  const { data: corrData } = useApi(api.correlation);
  const { data: drift } = useApi(api.driftStatus);
  const { data: fp } = useApi(api.fingerprintStatus);
  const { data: causal } = useApi(api.causalGraph);
  const { data: threads } = useApi(api.threadsStatus);
  const { data: energy } = useApi(api.energyStatus);
  const { data: tenants } = useApi(api.tenantsCount);
  const { data: patchData } = useApi(api.patches);
  const { data: mesh } = useApi(api.meshHealth);
  const { data: tls } = useApi(api.tlsStatus);
  const { data: slo } = useApi(api.sloStatus);
  const { data: deps } = useApi(api.systemDeps);

  return (
    <div>
      <div className="tabs">
        {['monitor', 'correlation', 'drift', 'energy', 'mesh', 'system'].map(t => (
          <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {tab === 'monitor' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Monitor Status</div>
            <div className="json-block">{JSON.stringify(monSt, null, 2)}</div>
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Fingerprint</div>
            <div className="json-block">{JSON.stringify(fp, null, 2)}</div>
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Causal Graph</div>
            <div className="json-block">{JSON.stringify(causal, null, 2)}</div>
          </div>
        </div>
      )}

      {tab === 'correlation' && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>Correlation Engine</div>
          <div className="json-block">{JSON.stringify(corrData, null, 2)}</div>
        </div>
      )}

      {tab === 'drift' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Configuration Drift</span>
            <button className="btn btn-sm btn-primary" onClick={async () => {
              try { await api.driftReset(); toast('Drift baseline reset', 'success'); } catch { toast('Failed', 'error'); }
            }}>Reset Baseline</button>
          </div>
          <div className="json-block">{JSON.stringify(drift, null, 2)}</div>
        </div>
      )}

      {tab === 'energy' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Energy Status</div>
            <div className="json-block">{JSON.stringify(energy, null, 2)}</div>
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Tenants</div>
            <div className="json-block">{JSON.stringify(tenants, null, 2)}</div>
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Patches</div>
            <div className="json-block">{JSON.stringify(patchData, null, 2)}</div>
          </div>
        </div>
      )}

      {tab === 'mesh' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-header">
              <span className="card-title">Service Mesh</span>
              <button className="btn btn-sm btn-primary" onClick={async () => {
                try { await api.meshHeal(); toast('Mesh heal initiated', 'success'); } catch { toast('Failed', 'error'); }
              }}>Heal</button>
            </div>
            <div className="json-block">{JSON.stringify(mesh, null, 2)}</div>
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>TLS Status</div>
            <div className="json-block">{JSON.stringify(tls, null, 2)}</div>
          </div>
        </div>
      )}

      {tab === 'system' && (
        <div className="card-grid">
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Threads</div>
            <div className="json-block">{JSON.stringify(threads, null, 2)}</div>
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>SLO Status</div>
            <div className="json-block">{JSON.stringify(slo, null, 2)}</div>
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Dependencies</div>
            <div className="json-block">{JSON.stringify(deps, null, 2)}</div>
          </div>
        </div>
      )}
    </div>
  );
}
