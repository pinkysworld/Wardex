import { useApi } from '../hooks.jsx';
import * as api from '../api.js';
import { JsonDetails, RawJsonDetails, SummaryGrid } from './operator.jsx';

export default function HelpDocs() {
  const { data: epList } = useApi(api.endpoints);
  const { data: research } = useApi(api.researchTracks);
  const { data: openApi } = useApi(api.openapi);
  const { data: hostData } = useApi(api.hostInfo);
  const { data: statusData } = useApi(api.status);

  const epArr = Array.isArray(epList) ? epList : epList?.endpoints || [];
  const openApiSummary = openApi ? {
    title: openApi?.info?.title,
    version: openApi?.info?.version,
    paths: openApi?.paths ? Object.keys(openApi.paths).length : 0,
    schemas: openApi?.components?.schemas ? Object.keys(openApi.components.schemas).length : 0,
  } : null;

  return (
    <div>
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-title" style={{ marginBottom: 12 }}>System Info</div>
        <div className="card-grid">
          <div>
            <span className="metric-label">Version</span>
            <div style={{ fontSize: 18, fontWeight: 600 }}>{statusData?.version || '—'}</div>
          </div>
          <div>
            <span className="metric-label">Hostname</span>
            <div style={{ fontSize: 18, fontWeight: 600 }}>{hostData?.hostname || '—'}</div>
          </div>
          <div>
            <span className="metric-label">OS</span>
            <div style={{ fontSize: 18, fontWeight: 600 }}>{hostData?.os || hostData?.platform || '—'}</div>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header">
          <span className="card-title">API Endpoints ({epArr.length})</span>
        </div>
        {epArr.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Method</th><th>Path</th><th>Description</th></tr></thead>
              <tbody>
                {epArr.map((ep, i) => (
                  <tr key={i}>
                    <td><span className="badge badge-info">{ep.method || 'GET'}</span></td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{ep.path || ep.url || ep}</td>
                    <td>{ep.description || ep.summary || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <>
            <div className="empty">Endpoint metadata is not available.</div>
            <RawJsonDetails data={epList} label="Endpoint metadata JSON" />
          </>
        )}
      </div>

      {research && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-title" style={{ marginBottom: 12 }}>Research Tracks</div>
          <SummaryGrid data={research} limit={10} />
          <JsonDetails data={research} />
        </div>
      )}

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-title" style={{ marginBottom: 12 }}>Documentation Links</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <a href="https://github.com/pinkysworld/Wardex" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)' }}>GitHub Repository</a>
          <a href="/api/openapi.json" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)' }}>OpenAPI Specification (JSON)</a>
        </div>
      </div>

      {openApi && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: 12 }}>OpenAPI Schema</div>
          <SummaryGrid data={openApiSummary} limit={6} />
          <RawJsonDetails data={openApi} label="OpenAPI JSON" />
        </div>
      )}
    </div>
  );
}
