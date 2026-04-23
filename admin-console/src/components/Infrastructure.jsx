import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useApi, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import { JsonDetails, SummaryGrid } from './operator.jsx';
import { formatDateTime, formatRelativeTime } from './operatorUtils.js';
import WorkflowGuidance from './WorkflowGuidance.jsx';
import { buildHref } from './workflowPivots.js';

const TABS = ['overview', 'assets', 'exposure', 'integrity', 'observability'];
const SAVED_VIEWS = [
  {
    id: 'critical',
    label: 'Critical Assets',
    match: (item) => item.priority === 'critical' || item.severity === 'critical',
  },
  { id: 'certs', label: 'Certificate Issues', match: (item) => item.type === 'certificate' },
  { id: 'containers', label: 'Container Risks', match: (item) => item.type === 'container' },
  { id: 'drifted', label: 'Drifted Systems', match: (item) => item.type === 'drift' },
];

const DEFAULT_SCAN_BEHAVIOR = {
  suspicious_process_tree: false,
  defense_evasion: false,
  persistence_installed: false,
  c2_beaconing_detected: false,
  credential_access: false,
};

function splitListInput(value) {
  return String(value || '')
    .split('\n')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function encodeBase64Utf8(value) {
  const bytes = new TextEncoder().encode(String(value || ''));
  let binary = '';
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  if (typeof btoa === 'function') return btoa(binary);
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');
  return binary;
}

function verdictBadgeClass(value) {
  switch (String(value || '').toLowerCase()) {
    case 'critical':
    case 'high':
    case 'malicious':
    case 'ransomware':
      return 'badge-err';
    case 'medium':
    case 'suspicious':
      return 'badge-warn';
    default:
      return 'badge-ok';
  }
}

function scoreBandBadgeClass(value) {
  switch (String(value || '').toLowerCase()) {
    case 'malicious':
    case 'likely_malicious':
      return 'badge-err';
    case 'suspicious':
      return 'badge-warn';
    default:
      return 'badge-info';
  }
}

function normalizeRecentMalwareEntries(malwareRecent) {
  const items =
    Array.isArray(malwareRecent) ? malwareRecent : malwareRecent?.matches || malwareRecent?.recent || malwareRecent?.items || [];
  return items.map((entry, index) => ({
    id: entry.id || entry.sha256 || entry.hash || `malware-${index}`,
    title: entry.name || entry.family || entry.file || entry.hash || `Malware finding ${index + 1}`,
    subtitle:
      [
        entry.family && entry.family !== entry.name ? entry.family : null,
        entry.source || null,
        entry.detected_at ? `Detected ${formatRelativeTime(entry.detected_at)}` : null,
      ]
        .filter(Boolean)
        .join(' • ') || 'Recent malware activity',
    type: 'malware',
    status: entry.status || 'detected',
    severity: entry.severity || 'high',
    priority: entry.severity === 'critical' ? 'critical' : 'high',
    evidence: entry,
  }));
}

function normalizeAssets(
  assetSummary,
  vulnSummary,
  certSummary,
  certAlerts,
  malwareRecent,
  drift,
  containerStats,
) {
  const items = [];
  const baseAssets = assetSummary?.assets || assetSummary?.items || assetSummary?.resources || [];
  baseAssets.forEach((asset, index) => {
    items.push({
      id: asset.id || asset.asset_id || asset.name || `asset-${index}`,
      title: asset.name || asset.hostname || asset.id || `Asset ${index + 1}`,
      subtitle: asset.cloud || asset.account || asset.platform || asset.region || 'Tracked asset',
      type: asset.kind || asset.asset_type || 'asset',
      status: asset.status || asset.health || 'tracked',
      severity: asset.severity || 'medium',
      priority: asset.priority || 'medium',
      evidence: asset,
    });
  });

  const vulnerabilities = vulnSummary?.findings || vulnSummary?.assets || vulnSummary?.items || [];
  vulnerabilities.forEach((finding, index) => {
    items.push({
      id: finding.id || finding.asset_id || `vuln-${index}`,
      title:
        finding.asset_name || finding.hostname || finding.package || `Vulnerability ${index + 1}`,
      subtitle: finding.cve || finding.summary || 'Vulnerability finding',
      type: 'vulnerability',
      status: finding.status || 'open',
      severity: finding.severity || 'high',
      priority: finding.severity === 'critical' ? 'critical' : 'high',
      evidence: finding,
    });
  });

  const certificates = certAlerts?.alerts || certSummary?.certificates || certSummary?.items || [];
  certificates.forEach((certificate, index) => {
    items.push({
      id: certificate.id || certificate.common_name || `cert-${index}`,
      title: certificate.common_name || certificate.subject || `Certificate ${index + 1}`,
      subtitle: certificate.expires_at || certificate.issuer || 'Certificate issue',
      type: 'certificate',
      status: certificate.status || (certificate.days_remaining <= 14 ? 'expiring' : 'tracked'),
      severity: certificate.days_remaining <= 7 ? 'critical' : 'medium',
      priority: certificate.days_remaining <= 7 ? 'critical' : 'medium',
      evidence: certificate,
    });
  });

  const malwareItems = Array.isArray(malwareRecent)
    ? malwareRecent
    : malwareRecent?.matches || malwareRecent?.recent || malwareRecent?.items || [];
  malwareItems.forEach((entry, index) => {
    items.push({
      id: entry.id || entry.sha256 || entry.hash || `malware-${index}`,
      title:
        entry.title || entry.name || entry.family || entry.file || entry.hash || `Malware finding ${index + 1}`,
      subtitle: entry.subtitle || entry.hostname || entry.signature || 'Recent malware activity',
      type: 'malware',
      status: entry.status || entry.verdict || 'detected',
      severity: entry.severity || 'high',
      priority: entry.severity === 'critical' ? 'critical' : 'high',
      evidence: entry.evidence || entry,
    });
  });

  const driftChanges = drift?.changes || drift?.drifts || [];
  driftChanges.forEach((change, index) => {
    items.push({
      id: change.id || change.path || `drift-${index}`,
      title: change.path || change.file || `Drift change ${index + 1}`,
      subtitle: change.type || change.detected || 'Configuration drift',
      type: 'drift',
      status: change.type || 'changed',
      severity: change.type === 'removed' ? 'high' : 'medium',
      priority: 'medium',
      evidence: change,
    });
  });

  const containers =
    containerStats?.containers || containerStats?.images || containerStats?.items || [];
  containers.forEach((container, index) => {
    items.push({
      id: container.id || container.image || `container-${index}`,
      title: container.name || container.image || `Container ${index + 1}`,
      subtitle: container.runtime || container.namespace || 'Container risk',
      type: 'container',
      status: container.status || 'running',
      severity: container.severity || 'medium',
      priority: container.severity === 'critical' ? 'critical' : 'medium',
      evidence: container,
    });
  });

  return items;
}

export default function Infrastructure() {
  const toast = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const { data: monSt } = useApi(api.monitorStatus);
  const { data: drift, reload: reloadDrift } = useApi(api.driftStatus);
  const { data: threads } = useApi(api.threadsStatus);
  const { data: slo } = useApi(api.sloStatus);
  const { data: deps } = useApi(api.systemDeps);
  const { data: vulnSummary, reload: reloadVuln } = useApi(api.vulnerabilitySummary);
  const { data: ndrData } = useApi(api.ndrReport);
  const { data: containerSt, reload: reloadContainers } = useApi(api.containerStats);
  const { data: certSummary, reload: reloadCerts } = useApi(api.certsSummary);
  const { data: certAlerts } = useApi(api.certsAlerts);
  const { data: assetSummary, reload: reloadAssets } = useApi(api.assetsSummary);
  const { data: malwareStatsData, reload: reloadMalwareStats } = useApi(api.malwareStats);
  const { data: malwareRecentData, reload: reloadMalware } = useApi(api.malwareRecent);
  const { data: compData } = useApi(api.complianceSummary);
  const { data: analyticsData } = useApi(api.apiAnalytics);
  const { data: tracesData } = useApi(api.traces);
  const [scanFilename, setScanFilename] = useState('sample.bin');
  const [scanSample, setScanSample] = useState('');
  const [scanBehavior, setScanBehavior] = useState(DEFAULT_SCAN_BEHAVIOR);
  const [trustedPublishersText, setTrustedPublishersText] = useState('');
  const [internalToolsText, setInternalToolsText] = useState('');
  const [runningDeepScan, setRunningDeepScan] = useState(false);
  const [deepScanResult, setDeepScanResult] = useState(null);
  const [focusedMalwareId, setFocusedMalwareId] = useState('');

  const activeTab = TABS.includes(searchParams.get('tab')) ? searchParams.get('tab') : 'overview';
  const savedView = searchParams.get('view') || 'critical';
  const query = searchParams.get('q') || '';
  const typeFilter = searchParams.get('type') || 'all';
  const recentMalware = useMemo(
    () => normalizeRecentMalwareEntries(malwareRecentData),
    [malwareRecentData],
  );
  const assets = normalizeAssets(
    assetSummary,
    vulnSummary,
    certSummary,
    certAlerts,
    recentMalware,
    drift,
    containerSt,
  );
  const filteredAssets = assets.filter((item) => {
    const view = SAVED_VIEWS.find((entry) => entry.id === savedView);
    const viewMatch = view ? view.match(item) : true;
    const search = query.trim().toLowerCase();
    const searchMatch =
      !search ||
      String(item.title).toLowerCase().includes(search) ||
      String(item.subtitle).toLowerCase().includes(search) ||
      String(item.id).toLowerCase().includes(search);
    const typeMatch = typeFilter === 'all' || item.type === typeFilter;
    return viewMatch && searchMatch && typeMatch;
  });
  const selectedAssetId = searchParams.get('asset');
  const selectedAsset =
    filteredAssets.find((item) => item.id === selectedAssetId) ||
    assets.find((item) => item.id === selectedAssetId) ||
    filteredAssets[0] ||
    assets[0] ||
    null;
  const focusedMalware =
    recentMalware.find((item) => item.id === focusedMalwareId) ||
    (selectedAsset?.type === 'malware' ? selectedAsset : null) ||
    recentMalware[0] ||
    null;
  const deepScanSummary = deepScanResult
    ? {
        verdict: deepScanResult.scan?.verdict || 'unknown',
        confidence: `${Math.round((Number(deepScanResult.scan?.confidence) || 0) * 100)}%`,
        family: deepScanResult.scan?.malware_family || 'Unclassified',
        file_type: deepScanResult.static_profile?.file_type || 'unknown',
        execution_surface: deepScanResult.static_profile?.platform_hint || 'generic',
        behavior_severity: deepScanResult.behavior_profile?.severity || 'none',
        score_band: deepScanResult.scan?.static_score?.band || 'unknown',
        static_score: deepScanResult.scan?.static_score?.score ?? 0,
      }
    : null;
  const whySafeOrNoisy = deepScanResult
    ? [
        deepScanResult.static_profile?.trusted_publisher_match
          ? `Trusted publisher allowlist matched "${deepScanResult.static_profile.trusted_publisher_match}".`
          : null,
        deepScanResult.static_profile?.internal_tool_match
          ? `Internal tool allowlist matched "${deepScanResult.static_profile.internal_tool_match}".`
          : null,
        deepScanResult.static_profile?.probable_signed
          ? 'Probable signing artefacts were detected in the sample.'
          : null,
        (deepScanResult.behavior_profile?.observed_tactics || []).length === 0
          ? 'No runtime tactics were supplied, so this verdict is driven by static evidence only.'
          : null,
      ].filter(Boolean)
    : [];

  useEffect(() => {
    if (!selectedAsset || selectedAsset.id === selectedAssetId) return;
    const next = new URLSearchParams(searchParams);
    next.set('asset', selectedAsset.id);
    setSearchParams(next, { replace: true });
  }, [selectedAsset, selectedAssetId, searchParams, setSearchParams]);

  useEffect(() => {
    if (focusedMalwareId && recentMalware.some((item) => item.id === focusedMalwareId)) return;
    setFocusedMalwareId(recentMalware[0]?.id || '');
  }, [focusedMalwareId, recentMalware]);

  const counts = {
    critical: assets.filter((item) => item.priority === 'critical').length,
    vulnerabilities: assets.filter((item) => item.type === 'vulnerability').length,
    certificates: assets.filter((item) => item.type === 'certificate').length,
    drifted: assets.filter((item) => item.type === 'drift').length,
    containers: assets.filter((item) => item.type === 'container').length,
    malware: assets.filter((item) => item.type === 'malware').length,
  };
  const focalAsset = selectedAsset?.title || selectedAsset?.id || 'critical assets';
  const focalQuery = selectedAsset?.id || selectedAsset?.title || query;
  const workflowItems = [
    {
      id: 'ndr',
      title: 'Validate Network Impact',
      description: `Use NDR to confirm whether ${focalAsset} is tied to unusual destinations, TLS issues, or beaconing.`,
      to: buildHref('/ndr', { params: { tab: 'overview' } }),
      minRole: 'analyst',
      tone: 'primary',
      badge: 'Network',
    },
    {
      id: 'threat-detection',
      title: 'Launch Asset-Focused Hunt',
      description: `Carry ${focalAsset} into Threat Detection for hunt and suppression workflows.`,
      to: buildHref('/detection', {
        params: {
          intent: 'run-hunt',
          huntQuery: `${selectedAsset?.type || 'asset'} ${focalQuery} drift vulnerability malware`,
          huntName: `Hunt ${focalAsset}`,
        },
      }),
      minRole: 'analyst',
      badge: 'Detect',
    },
    {
      id: 'soc-workbench',
      title: 'Escalate Into Cases',
      description: 'Move the selected asset context into case triage, approvals, and response tracking.',
      to: '/soc#cases',
      minRole: 'analyst',
      badge: 'Investigate',
    },
    {
      id: 'attack-graph',
      title: 'Check Campaign Linkage',
      description: 'Cross-check whether infrastructure findings align with active attack paths or propagation chains.',
      to: '/attack-graph',
      minRole: 'analyst',
      badge: 'Graph',
    },
    {
      id: 'reports',
      title: 'Open Compliance And Evidence',
      description: 'Use reporting workflows to package compliance, attestation, and evidence for the current backlog.',
      to: buildHref('/reports', {
        params: {
          tab: 'compliance',
          source: 'infrastructure',
          target: focalQuery || undefined,
        },
      }),
      minRole: 'viewer',
      badge: 'Report',
    },
  ];

  const updateParams = (changes) => {
    const next = new URLSearchParams(searchParams);
    Object.entries(changes).forEach(([key, value]) => {
      if (value == null || value === '' || value === 'all') next.delete(key);
      else next.set(key, value);
    });
    setSearchParams(next, { replace: true });
  };

  const refreshInfrastructure = () => {
    reloadAssets();
    reloadVuln();
    reloadCerts();
    reloadContainers();
    reloadMalware();
    reloadMalwareStats();
    reloadDrift();
  };

  const runDeepMalwareScan = async () => {
    if (!String(scanSample || '').trim()) {
      toast('Paste a sample or command trace before running a deep malware scan.', 'warning');
      return;
    }

    setRunningDeepScan(true);
    try {
      const result = await api.scanBufferV2({
        data: encodeBase64Utf8(scanSample),
        filename: String(scanFilename || '').trim() || 'sample.bin',
        behavior: scanBehavior,
        allowlist: {
          trusted_publishers: splitListInput(trustedPublishersText),
          internal_tools: splitListInput(internalToolsText),
        },
      });
      setDeepScanResult(result);
      reloadMalware();
      reloadMalwareStats();
      toast('Deep malware scan completed.', 'success');
    } catch {
      setDeepScanResult(null);
      toast('Unable to complete the deep malware scan.', 'error');
    } finally {
      setRunningDeepScan(false);
    }
  };

  return (
    <div>
      <div className="tabs" style={{ flexWrap: 'wrap' }}>
        {TABS.map((tab) => (
          <button
            key={tab}
            className={`tab ${activeTab === tab ? 'active' : ''}`}
            onClick={() => updateParams({ tab })}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>

      <WorkflowGuidance
        title="Infrastructure Pivots"
        description="Move from asset health into hunts, cases, network validation, graph review, and evidence workflows without dropping the current filter context."
        items={workflowItems}
      />

      {activeTab === 'overview' && (
        <>
          <div className="card-grid">
            <div className="card metric">
              <div className="metric-label">Critical Assets</div>
              <div className="metric-value">{counts.critical}</div>
              <div className="metric-sub">Assets or findings that should be triaged first</div>
            </div>
            <div className="card metric">
              <div className="metric-label">Exposure Queue</div>
              <div className="metric-value">
                {counts.vulnerabilities + counts.certificates + counts.containers}
              </div>
              <div className="metric-sub">Vulnerabilities, certificates, and container risks</div>
            </div>
            <div className="card metric">
              <div className="metric-label">Integrity Queue</div>
              <div className="metric-value">{counts.drifted + counts.malware}</div>
              <div className="metric-sub">
                Drift and malware findings that need narrative review
              </div>
            </div>
            <div className="card metric">
              <div className="metric-label">Observability Health</div>
              <div className="metric-value">{slo?.health_gate || monSt?.health_gate || '—'}</div>
              <div className="metric-sub">Threads, APIs, and monitoring systems</div>
            </div>
          </div>

          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header">
              <span className="card-title">Attention Queues</span>
              <div className="btn-group">
                <button
                  className="btn btn-sm"
                  onClick={() => updateParams({ tab: 'assets', view: 'critical' })}
                >
                  Open Assets
                </button>
                <button className="btn btn-sm" onClick={() => updateParams({ tab: 'exposure' })}>
                  Review Exposure
                </button>
                <button className="btn btn-sm" onClick={() => updateParams({ tab: 'integrity' })}>
                  Review Integrity
                </button>
              </div>
            </div>
            <div className="summary-grid">
              <div className="summary-card">
                <div className="summary-label">Vulnerable Assets</div>
                <div className="summary-value">{counts.vulnerabilities}</div>
                <div className="summary-meta">
                  Use the asset explorer to pivot from a finding into the affected system.
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Expiring Certificates</div>
                <div className="summary-value">{counts.certificates}</div>
                <div className="summary-meta">
                  Certificates are normalized into the same asset queue for quicker ownership
                  checks.
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Drifted Systems</div>
                <div className="summary-value">{counts.drifted}</div>
                <div className="summary-meta">
                  Raw subsystem details remain available below, but no longer drive the top-level
                  IA.
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Recent Malware</div>
                <div className="summary-value">{counts.malware}</div>
                <div className="summary-meta">
                  Recent detections feed the same sticky detail pane as infrastructure issues.
                </div>
              </div>
            </div>
          </div>

          <div className="card-grid">
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                Platform Overview
              </div>
              <SummaryGrid data={monSt} limit={8} />
              <JsonDetails data={monSt} label="Monitor status details" />
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                Compliance Snapshot
              </div>
              <SummaryGrid data={compData} limit={8} />
              <JsonDetails data={compData} label="Compliance detail" />
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                Dependencies and SLOs
              </div>
              <SummaryGrid
                data={{
                  ...slo,
                  dependency_count: deps?.dependencies?.length || deps?.deps?.length || 0,
                }}
                limit={8}
              />
              <JsonDetails data={{ slo, deps, threads }} label="Observability detail" />
            </div>
          </div>
        </>
      )}

      {activeTab === 'assets' && (
        <div className="triage-layout">
          <section className="triage-list">
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>
                Saved Views
              </div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {SAVED_VIEWS.map((view) => (
                  <button
                    key={view.id}
                    className={`filter-chip-button ${savedView === view.id ? 'active' : ''}`}
                    onClick={() => updateParams({ view: view.id, asset: '' })}
                  >
                    {view.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="card">
              <div className="triage-toolbar">
                <div className="triage-toolbar-group">
                  <input
                    className="form-input triage-search"
                    placeholder="Search assets, hosts, findings"
                    value={query}
                    onChange={(event) => updateParams({ q: event.target.value, asset: '' })}
                  />
                  <select
                    className="form-select"
                    value={typeFilter}
                    onChange={(event) => updateParams({ type: event.target.value, asset: '' })}
                  >
                    <option value="all">All types</option>
                    {[...new Set(assets.map((item) => item.type))].map((type) => (
                      <option key={type} value={type}>
                        {type}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="triage-toolbar-group">
                  <button
                    className="btn btn-sm"
                    onClick={refreshInfrastructure}
                  >
                    Refresh
                  </button>
                </div>
              </div>

              <div className="sticky-bulk-bar">
                <span className="hint">
                  Each row is normalized into one explorer so operators can move from host posture
                  to evidence without changing screens.
                </span>
              </div>

              <div className="split-list-table">
                <table>
                  <thead>
                    <tr>
                      <th>Entity</th>
                      <th>Type</th>
                      <th>Status</th>
                      <th>Severity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredAssets.length === 0 ? (
                      <tr>
                        <td colSpan="4">
                          <div className="empty" style={{ padding: 24 }}>
                            No assets match the current view.
                          </div>
                        </td>
                      </tr>
                    ) : (
                      filteredAssets.map((item) => (
                        <tr
                          key={item.id}
                          className={selectedAsset?.id === item.id ? 'row-active' : ''}
                          onClick={() => updateParams({ asset: item.id })}
                          style={{ cursor: 'pointer' }}
                        >
                          <td>
                            <div className="row-primary">{item.title}</div>
                            <div className="row-secondary">{item.subtitle}</div>
                          </td>
                          <td>{item.type}</td>
                          <td>
                            <span
                              className={`badge ${item.status === 'expiring' || item.status === 'detected' ? 'badge-err' : 'badge-info'}`}
                            >
                              {item.status}
                            </span>
                          </td>
                          <td>
                            <span
                              className={`badge ${item.severity === 'critical' || item.severity === 'high' ? 'badge-err' : 'badge-warn'}`}
                            >
                              {item.severity}
                            </span>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </section>

          <aside className="triage-detail">
            <div className="card">
              {!selectedAsset ? (
                <div className="empty">
                  Select an asset to review posture, related evidence, and subsystem details.
                </div>
              ) : (
                <>
                  <div className="detail-hero">
                    <div>
                      <div className="detail-hero-title">{selectedAsset.title}</div>
                      <div className="detail-hero-copy">{selectedAsset.subtitle}</div>
                    </div>
                    <span
                      className={`badge ${selectedAsset.priority === 'critical' ? 'badge-err' : 'badge-info'}`}
                    >
                      {selectedAsset.type}
                    </span>
                  </div>
                  <div className="summary-grid" style={{ marginTop: 16 }}>
                    <div className="summary-card">
                      <div className="summary-label">Status</div>
                      <div className="summary-value">{selectedAsset.status}</div>
                      <div className="summary-meta">Current posture for this entity.</div>
                    </div>
                    <div className="summary-card">
                      <div className="summary-label">Severity</div>
                      <div className="summary-value">{selectedAsset.severity}</div>
                      <div className="summary-meta">Derived from the owning subsystem.</div>
                    </div>
                    <div className="summary-card">
                      <div className="summary-label">Priority</div>
                      <div className="summary-value">{selectedAsset.priority}</div>
                      <div className="summary-meta">Controls queue ordering in saved views.</div>
                    </div>
                    <div className="summary-card">
                      <div className="summary-label">Explorer Scope</div>
                      <div className="summary-value">{savedView}</div>
                      <div className="summary-meta">URL-persisted view to share or revisit.</div>
                    </div>
                  </div>
                  <div className="btn-group" style={{ marginTop: 16 }}>
                    <button
                      className="btn btn-sm"
                      onClick={() => updateParams({ tab: 'exposure' })}
                    >
                      Open Related Exposure
                    </button>
                    <button
                      className="btn btn-sm"
                      onClick={() => updateParams({ tab: 'integrity' })}
                    >
                      Open Integrity Context
                    </button>
                    <button
                      className="btn btn-sm"
                      onClick={() => updateParams({ tab: 'observability' })}
                    >
                      Open Telemetry Context
                    </button>
                  </div>
                  <div className="detail-callout" style={{ marginTop: 16 }}>
                    This sticky pane keeps technical evidence available while the left-hand list
                    stays focused on scan speed. Raw subsystem payloads remain below for expert
                    users.
                  </div>
                  <JsonDetails
                    data={selectedAsset.evidence}
                    label="Asset evidence and subsystem payload"
                  />
                </>
              )}
            </div>
          </aside>
        </div>
      )}

      {activeTab === 'exposure' && (
        <>
          <div className="card-grid">
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                Vulnerability Summary
              </div>
              <SummaryGrid data={vulnSummary} limit={10} />
              <JsonDetails data={vulnSummary} />
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                Certificate Summary
              </div>
              <SummaryGrid data={certSummary} limit={10} />
              <JsonDetails data={certSummary} />
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                Container Risk
              </div>
              <SummaryGrid data={containerSt} limit={10} />
              <JsonDetails data={containerSt} />
            </div>
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Exposure Narrative
            </div>
            <div className="summary-grid">
              <div className="summary-card">
                <div className="summary-label">Vulnerabilities</div>
                <div className="summary-value">{counts.vulnerabilities}</div>
                <div className="summary-meta">
                  Use the asset explorer to pivot into a specific system or package owner.
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Certificate Issues</div>
                <div className="summary-value">{counts.certificates}</div>
                <div className="summary-meta">
                  Expiring credentials are normalized into the same workflow as host risk.
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-label">NDR Findings</div>
                <div className="summary-value">
                  {ndrData?.findings?.length || ndrData?.alerts?.length || 0}
                </div>
                <div className="summary-meta">
                  Network detections can be reviewed without opening a separate subsystem tab.
                </div>
              </div>
            </div>
            <JsonDetails data={ndrData} label="Network detection details" />
          </div>
        </>
      )}

      {activeTab === 'integrity' && (
        <>
          <div className="card-grid">
            <div className="card">
              <div className="card-header">
                <span className="card-title">Configuration Drift</span>
                <button
                  className="btn btn-sm btn-primary"
                  onClick={async () => {
                    try {
                      await api.driftReset();
                      reloadDrift();
                      toast('Drift baseline reset.', 'success');
                    } catch {
                      toast('Unable to reset drift baseline.', 'error');
                    }
                  }}
                >
                  Reset Baseline
                </button>
              </div>
              <SummaryGrid data={drift} limit={10} />
              <JsonDetails data={drift} />
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                Malware Queue Snapshot
              </div>
              <SummaryGrid data={{ ...malwareStatsData, recent_hits: counts.malware }} limit={10} />
              <div className="hint" style={{ marginTop: 12 }}>
                Recent detections, deep-scan verdicts, and allowlist context stay together here so
                analysts can explain why something fired and what to do next.
              </div>
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                Compliance Signals
              </div>
              <SummaryGrid data={compData} limit={10} />
              <JsonDetails data={compData} />
            </div>
          </div>

          <div className="card-grid" style={{ marginTop: 16 }}>
            <div className="card">
              <div className="card-header">
                <div>
                  <span className="card-title">Recent Malware Triage</span>
                  <div className="hint" style={{ marginTop: 6 }}>
                    Review the latest detections with family, source, and timing context before
                    pivoting to cases or response.
                  </div>
                </div>
                <button className="btn btn-sm" onClick={reloadMalware}>
                  Refresh
                </button>
              </div>
              {recentMalware.length === 0 ? (
                <div className="empty">No recent malware detections have been recorded yet.</div>
              ) : (
                <div style={{ display: 'grid', gap: 10 }}>
                  {recentMalware.slice(0, 6).map((entry) => (
                    <button
                      key={entry.id}
                      className="card"
                      style={{
                        textAlign: 'left',
                        padding: 14,
                        borderColor:
                          focusedMalware?.id === entry.id ? 'var(--accent)' : 'var(--border)',
                        background:
                          focusedMalware?.id === entry.id ? 'var(--bg)' : 'var(--bg-card)',
                      }}
                      onClick={() => setFocusedMalwareId(entry.id)}
                    >
                      <div
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          gap: 12,
                          alignItems: 'flex-start',
                        }}
                      >
                        <div>
                          <div className="row-primary">{entry.title}</div>
                          <div className="row-secondary">{entry.subtitle}</div>
                        </div>
                        <span className={`badge ${verdictBadgeClass(entry.severity)}`}>
                          {entry.severity}
                        </span>
                      </div>
                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 10 }}>
                        <span className="badge badge-info">
                          {entry.evidence?.source || 'unknown source'}
                        </span>
                        <span className="badge badge-info">
                          {entry.evidence?.family || 'unknown family'}
                        </span>
                      </div>
                    </button>
                  ))}
                </div>
              )}
              {focusedMalware ? (
                <>
                  <div className="card-title" style={{ marginTop: 18, marginBottom: 10 }}>
                    Focused Detection
                  </div>
                  <SummaryGrid
                    data={{
                      name: focusedMalware.title,
                      family: focusedMalware.evidence?.family || 'unknown',
                      severity: focusedMalware.severity,
                      source: focusedMalware.evidence?.source || 'unknown',
                      detected_at: focusedMalware.evidence?.detected_at || null,
                      sha256: focusedMalware.evidence?.sha256 || null,
                    }}
                    limit={6}
                  />
                  <div className="btn-group" style={{ marginTop: 12, flexWrap: 'wrap' }}>
                    <button
                      className="btn btn-sm"
                      onClick={() => updateParams({ tab: 'assets', asset: focusedMalware.id })}
                    >
                      Open In Asset Explorer
                    </button>
                    <button className="btn btn-sm" onClick={() => updateParams({ tab: 'observability' })}>
                      Check Telemetry Context
                    </button>
                    <button className="btn btn-sm btn-primary" onClick={() => updateParams({ tab: 'integrity' })}>
                      Stay In Integrity
                    </button>
                  </div>
                  <JsonDetails
                    data={focusedMalware.evidence}
                    label="Focused malware detection payload"
                  />
                </>
              ) : null}
            </div>

            <div className="card">
              <div className="card-header">
                <div>
                  <span className="card-title">Deep Malware Scan</span>
                  <div className="hint" style={{ marginTop: 6 }}>
                    Combine static content, runtime behavior, and allowlist context to explain why
                    a sample is malicious, noisy, or likely safe.
                  </div>
                </div>
                <button className="btn btn-sm" onClick={() => setDeepScanResult(null)}>
                  Clear Result
                </button>
              </div>

              <div className="form-group">
                <label className="form-label" htmlFor="deep-scan-filename">
                  Sample filename
                </label>
                <input
                  id="deep-scan-filename"
                  className="form-input"
                  value={scanFilename}
                  onChange={(event) => setScanFilename(event.target.value)}
                  placeholder="invoice_update.ps1"
                />
              </div>
              <div className="form-group">
                <label className="form-label" htmlFor="deep-scan-sample">
                  Sample content or script body
                </label>
                <textarea
                  id="deep-scan-sample"
                  className="form-input"
                  rows={8}
                  value={scanSample}
                  onChange={(event) => setScanSample(event.target.value)}
                  placeholder="Paste a suspicious script snippet, command line, or decoded sample here."
                />
              </div>

              <div
                style={{
                  display: 'grid',
                  gap: 12,
                  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                }}
              >
                <div>
                  <div className="form-label" style={{ marginBottom: 8 }}>
                    Runtime behavior
                  </div>
                  <div style={{ display: 'grid', gap: 8 }}>
                    {[
                      ['suspicious_process_tree', 'Suspicious process tree'],
                      ['defense_evasion', 'Defense evasion'],
                      ['persistence_installed', 'Persistence installed'],
                      ['c2_beaconing_detected', 'C2 beaconing'],
                      ['credential_access', 'Credential access'],
                    ].map(([key, label]) => (
                      <label
                        key={key}
                        style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 13 }}
                      >
                        <input
                          type="checkbox"
                          checked={Boolean(scanBehavior[key])}
                          onChange={(event) =>
                            setScanBehavior((current) => ({
                              ...current,
                              [key]: event.target.checked,
                            }))
                          }
                        />
                        {label}
                      </label>
                    ))}
                  </div>
                </div>

                <div>
                  <label className="form-label" htmlFor="deep-scan-trusted-publishers">
                    Trusted publishers
                  </label>
                  <textarea
                    id="deep-scan-trusted-publishers"
                    className="form-input"
                    rows={5}
                    value={trustedPublishersText}
                    onChange={(event) => setTrustedPublishersText(event.target.value)}
                    placeholder="microsoft&#10;adobe"
                  />
                </div>

                <div>
                  <label className="form-label" htmlFor="deep-scan-internal-tools">
                    Internal tools
                  </label>
                  <textarea
                    id="deep-scan-internal-tools"
                    className="form-input"
                    rows={5}
                    value={internalToolsText}
                    onChange={(event) => setInternalToolsText(event.target.value)}
                    placeholder="corp-updater&#10;internal-deployer"
                  />
                </div>
              </div>

              <div className="btn-group" style={{ marginTop: 16, flexWrap: 'wrap' }}>
                <button
                  className="btn btn-sm btn-primary"
                  disabled={runningDeepScan}
                  onClick={runDeepMalwareScan}
                >
                  {runningDeepScan ? 'Scanning…' : 'Run Deep Scan'}
                </button>
                <button
                  className="btn btn-sm"
                  onClick={() => {
                    setScanBehavior(DEFAULT_SCAN_BEHAVIOR);
                    setTrustedPublishersText('');
                    setInternalToolsText('');
                  }}
                >
                  Reset Context
                </button>
              </div>

              {!deepScanResult ? (
                <div className="detail-callout" style={{ marginTop: 16 }}>
                  Use deep scan when you need analyst-facing provenance: static traits, runtime
                  tactics, allowlist influence, and recommended follow-up actions in one view.
                </div>
              ) : (
                <>
                  <div style={{ marginTop: 18 }}>
                    <SummaryGrid data={deepScanSummary} limit={8} />
                  </div>

                  <div className="card-title" style={{ marginTop: 18, marginBottom: 10 }}>
                    Why this fired
                  </div>
                  <div style={{ display: 'grid', gap: 8 }}>
                    {(deepScanResult.analyst_summary || []).map((line, index) => (
                      <div
                        key={`analyst-summary-${index}`}
                        style={{
                          border: '1px solid var(--border)',
                          borderRadius: 10,
                          padding: 12,
                          background: 'var(--bg)',
                        }}
                      >
                        {line}
                      </div>
                    ))}
                    {(deepScanResult.scan?.matches || []).map((match, index) => (
                      <div
                        key={`scan-match-${index}`}
                        style={{
                          border: '1px solid var(--border)',
                          borderRadius: 10,
                          padding: 12,
                          background: 'var(--bg)',
                        }}
                      >
                        <div
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            gap: 10,
                            alignItems: 'flex-start',
                          }}
                        >
                          <div>
                            <div className="row-primary">{match.rule_name}</div>
                            <div className="row-secondary">{match.detail}</div>
                          </div>
                          <span className={`badge ${verdictBadgeClass(match.severity)}`}>
                            {match.severity}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>

                  <div
                    style={{
                      display: 'grid',
                      gap: 14,
                      gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
                      marginTop: 18,
                    }}
                  >
                    <div
                      style={{
                        border: '1px solid var(--border)',
                        borderRadius: 12,
                        padding: 14,
                        background: 'var(--bg-card)',
                      }}
                    >
                      <div className="card-title" style={{ marginBottom: 10 }}>
                        Why this might be safe or noisy
                      </div>
                      {whySafeOrNoisy.length === 0 ? (
                        <div className="empty">
                          No allowlist or signing context reduced the verdict confidence.
                        </div>
                      ) : (
                        <div style={{ display: 'grid', gap: 8 }}>
                          {whySafeOrNoisy.map((line) => (
                            <div key={line}>{line}</div>
                          ))}
                        </div>
                      )}
                    </div>

                    <div
                      style={{
                        border: '1px solid var(--border)',
                        borderRadius: 12,
                        padding: 14,
                        background: 'var(--bg-card)',
                      }}
                    >
                      <div className="card-title" style={{ marginBottom: 10 }}>
                        What to do next
                      </div>
                      <div style={{ display: 'grid', gap: 8 }}>
                        {(deepScanResult.behavior_profile?.recommended_actions || []).map(
                          (line, index) => (
                            <div key={`recommended-action-${index}`}>{line}</div>
                          ),
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="card-title" style={{ marginTop: 18, marginBottom: 10 }}>
                    Static and behavior profiles
                  </div>
                  <div
                    style={{
                      display: 'grid',
                      gap: 14,
                      gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
                    }}
                  >
                    <div>
                      <SummaryGrid
                        data={{
                          file_type: deepScanResult.static_profile?.file_type,
                          platform_hint: deepScanResult.static_profile?.platform_hint,
                          probable_signed: deepScanResult.static_profile?.probable_signed,
                          trusted_publisher:
                            deepScanResult.static_profile?.trusted_publisher_match || 'none',
                          internal_tool:
                            deepScanResult.static_profile?.internal_tool_match || 'none',
                        }}
                        limit={6}
                      />
                    </div>
                    <div>
                      <SummaryGrid
                        data={{
                          observed_tactics:
                            deepScanResult.behavior_profile?.observed_tactics?.length || 0,
                          behavior_severity: deepScanResult.behavior_profile?.severity || 'none',
                          allowlist_match:
                            deepScanResult.behavior_profile?.allowlist_match || 'none',
                          score_band: deepScanResult.scan?.static_score?.band || 'unknown',
                        }}
                        limit={6}
                      />
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 14 }}>
                    <span className={`badge ${verdictBadgeClass(deepScanResult.scan?.verdict)}`}>
                      {deepScanResult.scan?.verdict || 'unknown'}
                    </span>
                    <span
                      className={`badge ${scoreBandBadgeClass(
                        deepScanResult.scan?.static_score?.band,
                      )}`}
                    >
                      {deepScanResult.scan?.static_score?.band || 'unknown band'}
                    </span>
                    {(deepScanResult.behavior_profile?.observed_tactics || []).map((tactic) => (
                      <span key={tactic} className="badge badge-info">
                        {tactic}
                      </span>
                    ))}
                  </div>

                  <JsonDetails data={deepScanResult} label="Deep malware scan payload" />
                </>
              )}
            </div>
          </div>
        </>
      )}

      {activeTab === 'observability' && (
        <>
          <div className="card-grid">
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                Threads and Services
              </div>
              <SummaryGrid data={threads} limit={10} />
              <JsonDetails data={threads} />
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                Dependency Health
              </div>
              <SummaryGrid data={deps} limit={10} />
              <JsonDetails data={deps} />
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                API Analytics
              </div>
              <SummaryGrid data={analyticsData} limit={10} />
              <JsonDetails data={analyticsData} />
            </div>
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Telemetry Detail
            </div>
            <SummaryGrid
              data={{
                trace_count: tracesData?.traces?.length || tracesData?.count || 0,
                generated_at: tracesData?.generated_at || null,
              }}
              limit={4}
            />
            <JsonDetails data={tracesData} label="Trace collector detail" />
          </div>
        </>
      )}

      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-title" style={{ marginBottom: 12 }}>
          Technical Sections
        </div>
        <div className="hint">
          Raw subsystem summaries stay available here so experts can drop down into the original
          data without turning the whole screen back into a tab wall.
        </div>
        <JsonDetails
          data={{
            assetSummary,
            vulnSummary,
            certSummary,
            certAlerts,
            drift,
            containerSt,
            malwareStatsData,
            malwareRecentData,
            monSt,
            deps,
            slo,
          }}
          label="Expanded technical detail"
        />
        {selectedAsset && (
          <div className="hint" style={{ marginTop: 12 }}>
            Current scope: {selectedAsset.title} • {selectedAsset.type} •{' '}
            {selectedAsset.evidence?.updated_at
              ? `Updated ${formatRelativeTime(selectedAsset.evidence.updated_at)}`
              : `Selected ${formatDateTime(new Date())}`}
          </div>
        )}
      </div>
    </div>
  );
}
