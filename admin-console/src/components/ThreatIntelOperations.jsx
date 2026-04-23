import { useMemo, useState } from 'react';
import { useApi, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import { JsonDetails, SummaryGrid } from './operator.jsx';
import { downloadData, formatDateTime, formatRelativeTime } from './operatorUtils.js';

const TABS = ['indicators', 'connectors', 'deception'];

const IOC_TYPE_OPTIONS = [
  { value: 'ip', label: 'IP Address' },
  { value: 'domain', label: 'Domain' },
  { value: 'hash', label: 'File Hash' },
  { value: 'process', label: 'Process Name' },
  { value: 'behavior', label: 'Behavior Pattern' },
  { value: 'network_signature', label: 'Network Signature' },
  { value: 'registry_key', label: 'Registry Key' },
  { value: 'certificate', label: 'Certificate' },
];

const CONNECTOR_KIND_OPTIONS = [
  'virustotal',
  'misp',
  'otx',
  'abuseipdb',
  'shodan',
  'whois',
  'custom',
];

const CONNECTOR_AUTH_OPTIONS = ['api_key', 'bearer', 'basic', 'none'];

const DECOY_TYPE_OPTIONS = [
  { value: 'honeypot', label: 'Honeypot' },
  { value: 'honeyfile', label: 'Honey File' },
  { value: 'honeycredential', label: 'Honey Credential' },
  { value: 'honeyservice', label: 'Honey Service' },
  { value: 'canary', label: 'Canary Token' },
];

const defaultIndicatorDraft = () => ({
  value: '',
  iocType: 'domain',
  confidence: '0.80',
});

const defaultConnectorDraft = () => ({
  id: '',
  kind: 'virustotal',
  displayName: '',
  endpoint: '',
  authMode: 'api_key',
  enabled: true,
  timeoutSecs: '10',
  metadataText: '',
});

const defaultDeceptionDraft = () => ({
  decoyType: 'honeypot',
  name: '',
  description: '',
});

function normalizeIocType(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'ipaddress' || normalized === 'ip') return 'ip';
  if (normalized === 'domain') return 'domain';
  if (normalized === 'filehash' || normalized === 'hash') return 'hash';
  if (normalized === 'processname' || normalized === 'process') return 'process';
  if (normalized === 'behaviorpattern' || normalized === 'behavior') return 'behavior';
  if (normalized === 'networksignature' || normalized === 'network_signature') {
    return 'network_signature';
  }
  if (normalized === 'registrykey' || normalized === 'registry_key') return 'registry_key';
  if (normalized === 'certificate') return 'certificate';
  return normalized || 'unknown';
}

function iocTypeLabel(value) {
  const normalized = normalizeIocType(value);
  return IOC_TYPE_OPTIONS.find((entry) => entry.value === normalized)?.label || value || 'Unknown';
}

function formatConfidence(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return '0.00';
  return numeric.toFixed(2);
}

function formatThreatScore(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return '0.0';
  return numeric.toFixed(1);
}

function formatWeight(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return '1.0';
  return numeric.toFixed(1);
}

function connectorMetadataToText(metadata) {
  if (!metadata || typeof metadata !== 'object') return '';
  return Object.entries(metadata)
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');
}

function metadataTextToObject(value) {
  return String(value || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .reduce((acc, line) => {
      const separator = line.includes('=') ? '=' : ':';
      const [rawKey, ...rawValue] = line.split(separator);
      const key = String(rawKey || '').trim();
      const nextValue = rawValue.join(separator).trim();
      if (key && nextValue) acc[key] = nextValue;
      return acc;
    }, {});
}

function createConnectorDraft(connector = null) {
  if (!connector) return defaultConnectorDraft();
  return {
    id: connector.id || '',
    kind: connector.kind || 'custom',
    displayName: connector.display_name || connector.name || '',
    endpoint: connector.endpoint || '',
    authMode: connector.auth_mode || 'none',
    enabled: connector.enabled !== false,
    timeoutSecs: String(connector.timeout_secs || 10),
    metadataText: connectorMetadataToText(connector.metadata),
  };
}

export default function ThreatIntelOperations() {
  const toast = useToast();
  const [tab, setTab] = useState('indicators');
  const [indicatorDraft, setIndicatorDraft] = useState(() => defaultIndicatorDraft());
  const [indicatorQuery, setIndicatorQuery] = useState('');
  const [indicatorTypeFilter, setIndicatorTypeFilter] = useState('all');
  const [indicatorSourceFilter, setIndicatorSourceFilter] = useState('all');
  const [indicatorSeverityFilter, setIndicatorSeverityFilter] = useState('all');
  const [purgeTtlDays, setPurgeTtlDays] = useState('90');
  const [indicatorSubmitting, setIndicatorSubmitting] = useState(false);
  const [purgingIndicators, setPurgingIndicators] = useState(false);

  const [connectorDraft, setConnectorDraft] = useState(() => defaultConnectorDraft());
  const [selectedConnectorId, setSelectedConnectorId] = useState('');
  const [connectorQuery, setConnectorQuery] = useState('');
  const [connectorStatusFilter, setConnectorStatusFilter] = useState('all');
  const [connectorSaving, setConnectorSaving] = useState(false);

  const [deceptionDraft, setDeceptionDraft] = useState(() => defaultDeceptionDraft());
  const [deceptionQuery, setDeceptionQuery] = useState('');
  const [deceptionTypeFilter, setDeceptionTypeFilter] = useState('all');
  const [deceptionSubmitting, setDeceptionSubmitting] = useState(false);

  const {
    data: libraryData,
    loading: libraryLoading,
    error: libraryError,
    reload: reloadLibrary,
  } = useApi(api.threatIntelLibraryV2);
  const {
    data: sightingsData,
    loading: sightingsLoading,
    error: sightingsError,
    reload: reloadSightings,
  } = useApi(() => api.threatIntelSightings(50));
  const {
    data: connectorsData,
    loading: connectorsLoading,
    error: connectorsError,
    reload: reloadConnectors,
  } = useApi(api.enrichmentConnectors);
  const {
    data: deceptionData,
    loading: deceptionLoading,
    error: deceptionError,
    reload: reloadDeception,
  } = useApi(api.deceptionStatus);

  const iocs = useMemo(() => {
    if (Array.isArray(libraryData?.indicators)) return libraryData.indicators;
    if (Array.isArray(libraryData?.iocs)) return libraryData.iocs;
    if (Array.isArray(libraryData)) return libraryData;
    return [];
  }, [libraryData]);
  const feeds = useMemo(() => {
    if (Array.isArray(libraryData?.feeds)) return libraryData.feeds;
    return [];
  }, [libraryData]);
  const recentMatches = useMemo(() => {
    if (Array.isArray(libraryData?.recent_matches)) return libraryData.recent_matches;
    return [];
  }, [libraryData]);
  const recentSightings = useMemo(() => {
    if (Array.isArray(sightingsData?.items)) return sightingsData.items;
    if (Array.isArray(libraryData?.recent_sightings)) return libraryData.recent_sightings;
    return [];
  }, [libraryData, sightingsData]);
  const libraryStats = useMemo(() => {
    if (libraryData?.stats && typeof libraryData.stats === 'object') return libraryData.stats;
    return null;
  }, [libraryData]);
  const connectors = useMemo(() => {
    if (Array.isArray(connectorsData?.connectors)) return connectorsData.connectors;
    if (Array.isArray(connectorsData?.items)) return connectorsData.items;
    if (Array.isArray(connectorsData)) return connectorsData;
    return [];
  }, [connectorsData]);
  const decoys = useMemo(() => {
    if (Array.isArray(deceptionData?.decoys)) return deceptionData.decoys;
    return [];
  }, [deceptionData]);
  const attackerProfiles = useMemo(() => {
    if (Array.isArray(deceptionData?.attacker_profiles)) return deceptionData.attacker_profiles;
    return [];
  }, [deceptionData]);

  const indicatorSources = [...new Set(iocs.map((ioc) => ioc.source).filter(Boolean))].sort();
  const indicatorSeverities = [...new Set(iocs.map((ioc) => ioc.severity).filter(Boolean))].sort();
  const connectorStatuses = [...new Set(connectors.map((connector) => connector.status).filter(Boolean))].sort();

  const filteredIocs = iocs.filter((ioc) => {
    const query = indicatorQuery.trim().toLowerCase();
    const normalizedType = normalizeIocType(ioc.ioc_type);
    const queryMatch =
      !query ||
      String(ioc.value || '').toLowerCase().includes(query) ||
      String(ioc.metadata?.normalized_value || '')
        .toLowerCase()
        .includes(query) ||
      String(ioc.source || '').toLowerCase().includes(query) ||
      String(ioc.severity || '').toLowerCase().includes(query) ||
      (Array.isArray(ioc.tags) && ioc.tags.some((tag) => String(tag).toLowerCase().includes(query)));
    const typeMatch = indicatorTypeFilter === 'all' || normalizedType === indicatorTypeFilter;
    const sourceMatch = indicatorSourceFilter === 'all' || ioc.source === indicatorSourceFilter;
    const severityMatch =
      indicatorSeverityFilter === 'all' || ioc.severity === indicatorSeverityFilter;
    return queryMatch && typeMatch && sourceMatch && severityMatch;
  });

  const filteredConnectors = connectors.filter((connector) => {
    const query = connectorQuery.trim().toLowerCase();
    const queryMatch =
      !query ||
      String(connector.display_name || connector.id || '').toLowerCase().includes(query) ||
      String(connector.kind || '').toLowerCase().includes(query) ||
      String(connector.endpoint || '').toLowerCase().includes(query);
    const statusMatch =
      connectorStatusFilter === 'all' || connector.status === connectorStatusFilter;
    return queryMatch && statusMatch;
  });

  const filteredDecoys = decoys.filter((decoy) => {
    const query = deceptionQuery.trim().toLowerCase();
    const decoyType = String(decoy.decoy_type || '').toLowerCase();
    const queryMatch =
      !query ||
      String(decoy.name || '').toLowerCase().includes(query) ||
      String(decoy.description || '').toLowerCase().includes(query) ||
      String(decoy.fingerprint || '').toLowerCase().includes(query);
    const typeMatch = deceptionTypeFilter === 'all' || decoyType === deceptionTypeFilter;
    return queryMatch && typeMatch;
  });

  const selectedConnector =
    filteredConnectors.find((connector) => connector.id === selectedConnectorId) ||
    connectors.find((connector) => connector.id === selectedConnectorId) ||
    null;

  const overallSummary = {
    indicators: libraryStats?.total_iocs ?? iocs.length,
    avg_confidence: formatConfidence(libraryStats?.avg_confidence),
    active_feeds: libraryStats?.active_feeds ?? feeds.filter((feed) => feed.active).length,
    ready_connectors: connectors.filter((connector) => connector.status === 'ready').length,
    active_decoys: deceptionData?.active_decoys ?? 0,
    high_threat_interactions: deceptionData?.high_threat_interactions ?? 0,
  };

  const refreshAll = () => {
    reloadLibrary();
    reloadSightings();
    reloadConnectors();
    reloadDeception();
  };

  const addIndicator = async () => {
    const value = String(indicatorDraft.value || '').trim();
    const confidence = Number(indicatorDraft.confidence);
    if (!value) {
      toast('Enter an indicator value before saving it.', 'error');
      return;
    }
    if (!Number.isFinite(confidence) || confidence <= 0 || confidence > 1) {
      toast('Confidence must be between 0 and 1.', 'error');
      return;
    }

    setIndicatorSubmitting(true);
    try {
      await api.threatIntelIoc({
        value,
        ioc_type: indicatorDraft.iocType,
        confidence,
      });
      setIndicatorDraft((current) => ({ ...current, value: '' }));
      reloadLibrary();
      toast('Indicator added to the threat library.', 'success');
    } catch {
      toast('Failed to add the indicator.', 'error');
    } finally {
      setIndicatorSubmitting(false);
    }
  };

  const purgeIndicators = async () => {
    const ttlDays = Number(purgeTtlDays);
    if (!Number.isFinite(ttlDays) || ttlDays <= 0) {
      toast('TTL days must be greater than zero.', 'error');
      return;
    }

    setPurgingIndicators(true);
    try {
      const result = await api.threatIntelPurge({ ttl_days: ttlDays });
      reloadLibrary();
      reloadSightings();
      toast(`${result?.purged ?? 0} expired indicators removed.`, 'success');
    } catch {
      toast('Failed to purge expired indicators.', 'error');
    } finally {
      setPurgingIndicators(false);
    }
  };

  const openConnectorEditor = (connector = null) => {
    setSelectedConnectorId(connector?.id || '');
    setConnectorDraft(createConnectorDraft(connector));
  };

  const saveConnector = async () => {
    const displayName = String(connectorDraft.displayName || '').trim();
    const kind = String(connectorDraft.kind || '').trim();
    const timeoutSecs = Number(connectorDraft.timeoutSecs);
    if (!displayName) {
      toast('Connector display name is required.', 'error');
      return;
    }
    if (!kind) {
      toast('Connector kind is required.', 'error');
      return;
    }
    if (!Number.isFinite(timeoutSecs) || timeoutSecs <= 0) {
      toast('Connector timeout must be greater than zero.', 'error');
      return;
    }

    setConnectorSaving(true);
    try {
      const result = await api.createEnrichmentConnector({
        id: connectorDraft.id || undefined,
        kind,
        display_name: displayName,
        endpoint: String(connectorDraft.endpoint || '').trim() || undefined,
        auth_mode: String(connectorDraft.authMode || '').trim() || undefined,
        enabled: connectorDraft.enabled !== false,
        timeout_secs: timeoutSecs,
        metadata: metadataTextToObject(connectorDraft.metadataText),
      });
      const saved = result?.connector || null;
      if (saved) openConnectorEditor(saved);
      reloadConnectors();
      toast(connectorDraft.id ? 'Connector updated.' : 'Connector created.', 'success');
    } catch {
      toast('Failed to save enrichment connector.', 'error');
    } finally {
      setConnectorSaving(false);
    }
  };

  const deployDecoy = async () => {
    const name = String(deceptionDraft.name || '').trim();
    if (!name) {
      toast('Decoy name is required.', 'error');
      return;
    }

    setDeceptionSubmitting(true);
    try {
      await api.deceptionDeploy({
        decoy_type: deceptionDraft.decoyType,
        name,
        description: String(deceptionDraft.description || '').trim() || undefined,
      });
      setDeceptionDraft((current) => ({ ...current, name: '' }));
      reloadDeception();
      toast('Decoy deployed to the deception engine.', 'success');
    } catch {
      toast('Failed to deploy the decoy.', 'error');
    } finally {
      setDeceptionSubmitting(false);
    }
  };

  return (
    <div className="card" style={{ marginBottom: 16 }}>
      <div className="card-header">
        <div>
          <span className="card-title">Threat Ops Workspace</span>
          <div className="hint" style={{ marginTop: 6 }}>
            Manage indicators, enrichment connectors, and deception coverage without dropping into
            raw JSON or setup-only screens.
          </div>
        </div>
        <div className="btn-group">
          <button className="btn btn-sm" onClick={refreshAll}>
            Refresh All
          </button>
          <button
            className="btn btn-sm"
            onClick={() =>
              downloadData(
                {
                  exported_at: new Date().toISOString(),
                  indicators: iocs,
                  stats: libraryStats,
                  sightings: recentSightings,
                  connectors,
                  decoys,
                },
                'threat-ops-snapshot.json',
              )
            }
          >
            Download Snapshot
          </button>
        </div>
      </div>

      <div style={{ marginTop: 16 }}>
        <SummaryGrid data={overallSummary} limit={6} />
      </div>

      <div className="tabs" style={{ marginTop: 16, flexWrap: 'wrap' }}>
        {TABS.map((entry) => (
          <button
            key={entry}
            className={`tab ${tab === entry ? 'active' : ''}`}
            onClick={() => setTab(entry)}
          >
            {entry.charAt(0).toUpperCase() + entry.slice(1)}
          </button>
        ))}
      </div>

      {tab === 'indicators' && (
        <div className="card-grid" style={{ marginTop: 16 }}>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Add Indicator
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="indicator-value">
                Indicator value
              </label>
              <input
                id="indicator-value"
                className="form-input"
                placeholder="bad.example, 203.0.113.42, hash, or behavior signature"
                value={indicatorDraft.value}
                onChange={(event) =>
                  setIndicatorDraft((current) => ({ ...current, value: event.target.value }))
                }
              />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="indicator-type">
                Indicator type
              </label>
              <select
                id="indicator-type"
                className="form-select"
                value={indicatorDraft.iocType}
                onChange={(event) =>
                  setIndicatorDraft((current) => ({ ...current, iocType: event.target.value }))
                }
              >
                {IOC_TYPE_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="indicator-confidence">
                Confidence
              </label>
              <input
                id="indicator-confidence"
                className="form-input"
                value={indicatorDraft.confidence}
                onChange={(event) =>
                  setIndicatorDraft((current) => ({ ...current, confidence: event.target.value }))
                }
              />
            </div>
            <div className="btn-group">
              <button
                className="btn btn-sm btn-primary"
                disabled={indicatorSubmitting}
                onClick={addIndicator}
              >
                {indicatorSubmitting ? 'Adding...' : 'Add Indicator'}
              </button>
              <button
                className="btn btn-sm"
                onClick={() =>
                  downloadData(
                    {
                      exported_at: new Date().toISOString(),
                      indicators: iocs,
                      stats: libraryStats,
                    },
                    'threat-intel-library.json',
                  )
                }
              >
                Download Library
              </button>
            </div>

            <div className="card-title" style={{ marginTop: 20, marginBottom: 12 }}>
              Purge Expired Indicators
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="indicator-purge-ttl">
                Purge TTL days
              </label>
              <input
                id="indicator-purge-ttl"
                className="form-input"
                value={purgeTtlDays}
                onChange={(event) => setPurgeTtlDays(event.target.value)}
              />
            </div>
            <button
              className="btn btn-sm"
              disabled={purgingIndicators}
              onClick={purgeIndicators}
            >
              {purgingIndicators ? 'Purging...' : 'Purge Expired'}
            </button>
          </div>

          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Indicator Library
            </div>
            <div className="triage-toolbar">
              <div className="triage-toolbar-group">
                <input
                  className="form-input triage-search"
                  placeholder="Search value, source, or severity"
                  value={indicatorQuery}
                  onChange={(event) => setIndicatorQuery(event.target.value)}
                />
                <select
                  className="form-select"
                  value={indicatorTypeFilter}
                  onChange={(event) => setIndicatorTypeFilter(event.target.value)}
                >
                  <option value="all">All types</option>
                  {IOC_TYPE_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
                <select
                  className="form-select"
                  value={indicatorSourceFilter}
                  onChange={(event) => setIndicatorSourceFilter(event.target.value)}
                >
                  <option value="all">All sources</option>
                  {indicatorSources.map((source) => (
                    <option key={source} value={source}>
                      {source}
                    </option>
                  ))}
                </select>
                <select
                  className="form-select"
                  value={indicatorSeverityFilter}
                  onChange={(event) => setIndicatorSeverityFilter(event.target.value)}
                >
                  <option value="all">All severities</option>
                  {indicatorSeverities.map((severity) => (
                    <option key={severity} value={severity}>
                      {severity}
                    </option>
                  ))}
                </select>
              </div>
              <div className="triage-toolbar-group">
                <button className="btn btn-sm" onClick={reloadLibrary}>
                  Refresh
                </button>
              </div>
            </div>
            {libraryError ? (
              <div className="empty">Threat intel library is unavailable right now.</div>
            ) : libraryLoading ? (
              <div className="hint">Loading indicator library and enrichment statistics.</div>
            ) : filteredIocs.length === 0 ? (
              <div className="empty">No indicators match the current filter scope.</div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Value</th>
                      <th>Type</th>
                      <th>Source</th>
                      <th>Severity</th>
                      <th>Confidence</th>
                      <th>Recent Activity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredIocs.map((ioc) => (
                      <tr key={`${ioc.ioc_type}-${ioc.value}`}>
                        <td>
                          <div className="row-primary">{ioc.value}</div>
                          <div className="row-secondary">
                            {ioc.metadata?.normalized_value &&
                            ioc.metadata.normalized_value !== ioc.value
                              ? `Normalized ${ioc.metadata.normalized_value}`
                              : `First seen ${ioc.first_seen ? formatRelativeTime(ioc.first_seen) : 'unknown'}`}
                          </div>
                          {ioc.metadata?.normalized_value &&
                          ioc.metadata.normalized_value !== ioc.value ? (
                            <div className="row-secondary">
                              First seen {ioc.first_seen ? formatRelativeTime(ioc.first_seen) : 'unknown'}
                            </div>
                          ) : null}
                        </td>
                        <td>{iocTypeLabel(ioc.ioc_type)}</td>
                        <td>
                          <div className="row-primary">{ioc.source || 'unknown'}</div>
                          <div className="row-secondary">
                            TTL {ioc.metadata?.ttl_days ?? 90}d · Weight{' '}
                            {formatWeight(ioc.metadata?.source_weight)}
                          </div>
                        </td>
                        <td>
                          <span
                            className={`badge ${ioc.severity === 'high' || ioc.severity === 'critical' ? 'badge-err' : 'badge-info'}`}
                          >
                            {ioc.severity || 'unknown'}
                          </span>
                        </td>
                        <td>
                          <div className="row-secondary">
                            Decay {formatConfidence(ioc.metadata?.confidence_decay ?? 0.98)}
                          </div>
                          <div>{formatConfidence(ioc.confidence)}</div>
                        </td>
                        <td>
                          <div>
                            {ioc.metadata?.last_sighting
                              ? formatRelativeTime(ioc.metadata.last_sighting)
                              : ioc.last_seen
                                ? formatRelativeTime(ioc.last_seen)
                                : 'unknown'}
                          </div>
                          <div className="row-secondary">
                            {(ioc.metadata?.sightings ?? ioc.sightings?.length ?? 0)} sightings
                          </div>
                          <div className="row-secondary">
                            {ioc.metadata?.last_sighting
                              ? formatDateTime(ioc.metadata.last_sighting)
                              : ioc.last_seen
                                ? formatDateTime(ioc.last_seen)
                                : 'No timestamp'}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Feed and Match Context
            </div>
            <SummaryGrid
              data={{
                total_iocs: libraryStats?.total_iocs ?? iocs.length,
                active_feeds: libraryStats?.active_feeds ?? feeds.filter((feed) => feed.active).length,
                total_feeds: libraryStats?.total_feeds ?? feeds.length,
                match_history: libraryStats?.match_history_size ?? recentMatches.length,
                recent_sightings: recentSightings.length,
              }}
              limit={5}
            />
            <div className="card-title" style={{ marginTop: 20, marginBottom: 12 }}>
              Registered feeds
            </div>
            {feeds.length === 0 ? (
              <div className="empty">Threat feed registry is empty.</div>
            ) : (
              <div style={{ display: 'grid', gap: 10 }}>
                {feeds.slice(0, 5).map((feed) => (
                  <div
                    key={feed.feed_id}
                    style={{ border: '1px solid var(--border)', borderRadius: 12, padding: 14 }}
                  >
                    <div className="row-primary">{feed.name}</div>
                    <div className="row-secondary">{feed.url}</div>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 10 }}>
                      <span className="badge badge-info">{feed.format}</span>
                      <span className={`badge ${feed.active ? 'badge-ok' : 'badge-warn'}`}>
                        {feed.active ? 'Active' : 'Inactive'}
                      </span>
                      <span className="badge badge-info">{feed.ioc_count || 0} IoCs</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
            <div className="card-title" style={{ marginTop: 20, marginBottom: 12 }}>
              Recent sightings
            </div>
            {sightingsError ? (
              <div className="empty">
                Sighting history is temporarily unavailable, but the indicator library is still
                online.
              </div>
            ) : sightingsLoading && recentSightings.length === 0 ? (
              <div className="hint">Loading normalized sighting activity.</div>
            ) : recentSightings.length === 0 ? (
              <div className="empty">No indicator sightings have been recorded yet.</div>
            ) : (
              <div style={{ display: 'grid', gap: 10 }}>
                {recentSightings.slice(0, 6).map((sighting, index) => (
                  <div
                    key={`${sighting.timestamp || 'sighting'}-${sighting.value || index}`}
                    style={{ border: '1px solid var(--border)', borderRadius: 12, padding: 14 }}
                  >
                    <div className="row-primary">{sighting.value || 'Unknown indicator'}</div>
                    <div className="row-secondary">{sighting.context || sighting.source || 'No context'}</div>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 10 }}>
                      <span className="badge badge-info">
                        {iocTypeLabel(sighting.ioc_type)}
                      </span>
                      <span
                        className={`badge ${sighting.severity === 'high' || sighting.severity === 'critical' ? 'badge-err' : 'badge-info'}`}
                      >
                        {sighting.severity || 'unknown'}
                      </span>
                      <span className="badge badge-info">{sighting.source || 'unknown source'}</span>
                      <span className="badge badge-info">
                        Weight {formatWeight(sighting.weight)}
                      </span>
                    </div>
                    <div className="row-secondary" style={{ marginTop: 8 }}>
                      {sighting.timestamp
                        ? `${formatRelativeTime(sighting.timestamp)} • ${formatDateTime(sighting.timestamp)}`
                        : 'No timestamp'}
                    </div>
                  </div>
                ))}
              </div>
            )}
            <div className="card-title" style={{ marginTop: 20, marginBottom: 12 }}>
              Recent matches
            </div>
            {recentMatches.length === 0 ? (
              <div className="empty">No indicator match activity has been recorded yet.</div>
            ) : (
              <div style={{ display: 'grid', gap: 10 }}>
                {recentMatches.slice(0, 5).map((match, index) => (
                  <div
                    key={`${match.match_type || 'match'}-${index}`}
                    style={{ border: '1px solid var(--border)', borderRadius: 12, padding: 14 }}
                  >
                    <div className="row-primary">{match.context || 'Match event'}</div>
                    <div className="row-secondary">
                      {match.ioc?.value || 'No mapped indicator value'}
                    </div>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 10 }}>
                      <span className={`badge ${match.matched ? 'badge-ok' : 'badge-info'}`}>
                        {match.match_type || 'unknown'}
                      </span>
                      <span className="badge badge-info">{iocTypeLabel(match.ioc?.ioc_type)}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
            <JsonDetails data={libraryStats} label="Threat intel statistics" />
          </div>
        </div>
      )}

      {tab === 'connectors' && (
        <div className="card-grid" style={{ marginTop: 16 }}>
          <div className="card">
            <div className="card-header">
              <span className="card-title">Enrichment Connectors</span>
              <button className="btn btn-sm" onClick={() => openConnectorEditor(null)}>
                New Connector
              </button>
            </div>
            <div className="triage-toolbar" style={{ marginTop: 12 }}>
              <div className="triage-toolbar-group">
                <input
                  className="form-input triage-search"
                  placeholder="Search connectors by name, kind, or endpoint"
                  value={connectorQuery}
                  onChange={(event) => setConnectorQuery(event.target.value)}
                />
                <select
                  className="form-select"
                  value={connectorStatusFilter}
                  onChange={(event) => setConnectorStatusFilter(event.target.value)}
                >
                  <option value="all">All statuses</option>
                  {connectorStatuses.map((status) => (
                    <option key={status} value={status}>
                      {status}
                    </option>
                  ))}
                </select>
              </div>
              <div className="triage-toolbar-group">
                <button className="btn btn-sm" onClick={reloadConnectors}>
                  Refresh
                </button>
              </div>
            </div>
            {connectorsError ? (
              <div className="empty">Connector state is unavailable right now.</div>
            ) : connectorsLoading ? (
              <div className="hint">Loading enrichment connectors.</div>
            ) : filteredConnectors.length === 0 ? (
              <div className="empty">No connectors match the current filter scope.</div>
            ) : (
              <div style={{ display: 'grid', gap: 10, marginTop: 12 }}>
                {filteredConnectors.map((connector) => (
                  <button
                    key={connector.id}
                    className="card"
                    style={{
                      textAlign: 'left',
                      padding: 14,
                      borderColor:
                        selectedConnector?.id === connector.id ? 'var(--accent)' : 'var(--border)',
                      background:
                        selectedConnector?.id === connector.id ? 'var(--bg)' : 'var(--bg-card)',
                    }}
                    onClick={() => openConnectorEditor(connector)}
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
                        <div className="row-primary">{connector.display_name || connector.id}</div>
                        <div className="row-secondary">{connector.endpoint || 'No endpoint configured'}</div>
                      </div>
                      <span
                        className={`badge ${connector.status === 'ready' ? 'badge-ok' : connector.status === 'error' ? 'badge-err' : 'badge-warn'}`}
                      >
                        {connector.status || 'unknown'}
                      </span>
                    </div>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 10 }}>
                      <span className="badge badge-info">{connector.kind || 'custom'}</span>
                      <span className="badge badge-info">{connector.auth_mode || 'no auth'}</span>
                      <span className={`badge ${connector.enabled ? 'badge-ok' : 'badge-warn'}`}>
                        {connector.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              {connectorDraft.id ? 'Edit Connector' : 'Create Connector'}
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="connector-display-name">
                Connector display name
              </label>
              <input
                id="connector-display-name"
                className="form-input"
                value={connectorDraft.displayName}
                onChange={(event) =>
                  setConnectorDraft((current) => ({ ...current, displayName: event.target.value }))
                }
              />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="connector-kind">
                Connector kind
              </label>
              <select
                id="connector-kind"
                className="form-select"
                value={connectorDraft.kind}
                onChange={(event) =>
                  setConnectorDraft((current) => ({ ...current, kind: event.target.value }))
                }
              >
                {CONNECTOR_KIND_OPTIONS.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="connector-endpoint">
                Endpoint
              </label>
              <input
                id="connector-endpoint"
                className="form-input"
                placeholder="https://api.example.com/enrich"
                value={connectorDraft.endpoint}
                onChange={(event) =>
                  setConnectorDraft((current) => ({ ...current, endpoint: event.target.value }))
                }
              />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="connector-auth-mode">
                Auth mode
              </label>
              <select
                id="connector-auth-mode"
                className="form-select"
                value={connectorDraft.authMode}
                onChange={(event) =>
                  setConnectorDraft((current) => ({ ...current, authMode: event.target.value }))
                }
              >
                {CONNECTOR_AUTH_OPTIONS.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="connector-timeout-secs">
                Timeout seconds
              </label>
              <input
                id="connector-timeout-secs"
                className="form-input"
                value={connectorDraft.timeoutSecs}
                onChange={(event) =>
                  setConnectorDraft((current) => ({ ...current, timeoutSecs: event.target.value }))
                }
              />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="connector-metadata">
                Metadata
              </label>
              <textarea
                id="connector-metadata"
                className="form-input"
                rows={5}
                placeholder="api_key_ref=secret://intel/virustotal\ntenant=security-ops"
                value={connectorDraft.metadataText}
                onChange={(event) =>
                  setConnectorDraft((current) => ({ ...current, metadataText: event.target.value }))
                }
              />
            </div>
            <label className="hint" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <input
                type="checkbox"
                checked={connectorDraft.enabled}
                onChange={(event) =>
                  setConnectorDraft((current) => ({ ...current, enabled: event.target.checked }))
                }
              />
              Enabled for analyst enrichment flows
            </label>
            <div className="btn-group" style={{ marginTop: 16 }}>
              <button
                className="btn btn-sm btn-primary"
                disabled={connectorSaving}
                onClick={saveConnector}
              >
                {connectorSaving ? 'Saving...' : 'Save Connector'}
              </button>
              <button className="btn btn-sm" onClick={() => openConnectorEditor(null)}>
                Reset Form
              </button>
            </div>
            {selectedConnector && (
              <div style={{ marginTop: 16 }}>
                <SummaryGrid
                  data={{
                    id: selectedConnector.id,
                    status: selectedConnector.status,
                    last_sync_at: selectedConnector.last_sync_at
                      ? formatDateTime(selectedConnector.last_sync_at)
                      : 'Never',
                    last_error: selectedConnector.last_error || 'None',
                  }}
                  limit={4}
                />
              </div>
            )}
            <JsonDetails data={selectedConnector || connectorsData} label="Connector payload" />
          </div>
        </div>
      )}

      {tab === 'deception' && (
        <div className="card-grid" style={{ marginTop: 16 }}>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Deception Coverage
            </div>
            {deceptionError ? (
              <div className="empty">Deception coverage is unavailable right now.</div>
            ) : deceptionLoading ? (
              <div className="hint">Loading deception posture.</div>
            ) : (
              <>
                <SummaryGrid
                  data={{
                    total_decoys: deceptionData?.total_decoys ?? 0,
                    active_decoys: deceptionData?.active_decoys ?? 0,
                    total_interactions: deceptionData?.total_interactions ?? 0,
                    high_threat_interactions: deceptionData?.high_threat_interactions ?? 0,
                    attacker_profiles: attackerProfiles.length,
                  }}
                  limit={5}
                />
                <div className="triage-toolbar" style={{ marginTop: 16 }}>
                  <div className="triage-toolbar-group">
                    <input
                      className="form-input triage-search"
                      placeholder="Search decoys by name or fingerprint"
                      value={deceptionQuery}
                      onChange={(event) => setDeceptionQuery(event.target.value)}
                    />
                    <select
                      className="form-select"
                      value={deceptionTypeFilter}
                      onChange={(event) => setDeceptionTypeFilter(event.target.value)}
                    >
                      <option value="all">All decoy types</option>
                      {DECOY_TYPE_OPTIONS.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="triage-toolbar-group">
                    <button className="btn btn-sm" onClick={reloadDeception}>
                      Refresh
                    </button>
                  </div>
                </div>
                {filteredDecoys.length === 0 ? (
                  <div className="empty" style={{ marginTop: 16 }}>
                    No decoys match the current filter scope.
                  </div>
                ) : (
                  <div className="table-wrap" style={{ marginTop: 16 }}>
                    <table>
                      <thead>
                        <tr>
                          <th>Name</th>
                          <th>Type</th>
                          <th>Status</th>
                          <th>Interactions</th>
                          <th>Threat</th>
                          <th>Last Interaction</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredDecoys.map((decoy) => (
                          <tr key={decoy.id}>
                            <td>
                              <div className="row-primary">{decoy.name}</div>
                              <div className="row-secondary">{decoy.description || 'No description'}</div>
                            </td>
                            <td>{DECOY_TYPE_OPTIONS.find((option) => option.value === String(decoy.decoy_type || '').toLowerCase())?.label || decoy.decoy_type || 'Unknown'}</td>
                            <td>
                              <span className={`badge ${decoy.deployed ? 'badge-ok' : 'badge-warn'}`}>
                                {decoy.deployed ? 'Deployed' : 'Inactive'}
                              </span>
                            </td>
                            <td>{decoy.interaction_count || 0}</td>
                            <td>{formatThreatScore(decoy.avg_threat_score)}</td>
                            <td>
                              {decoy.last_interaction?.timestamp
                                ? formatDateTime(decoy.last_interaction.timestamp)
                                : 'No interactions'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}
          </div>

          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Deploy Decoy
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="threat-ops-decoy-type">
                Decoy type
              </label>
              <select
                id="threat-ops-decoy-type"
                className="form-select"
                value={deceptionDraft.decoyType}
                onChange={(event) =>
                  setDeceptionDraft((current) => ({ ...current, decoyType: event.target.value }))
                }
              >
                {DECOY_TYPE_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="threat-ops-decoy-name">
                Decoy name
              </label>
              <input
                id="threat-ops-decoy-name"
                className="form-input"
                value={deceptionDraft.name}
                onChange={(event) =>
                  setDeceptionDraft((current) => ({ ...current, name: event.target.value }))
                }
              />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="threat-ops-decoy-description">
                Description
              </label>
              <textarea
                id="threat-ops-decoy-description"
                className="form-input"
                rows={5}
                value={deceptionDraft.description}
                onChange={(event) =>
                  setDeceptionDraft((current) => ({ ...current, description: event.target.value }))
                }
              />
            </div>
            <button
              className="btn btn-sm btn-primary"
              disabled={deceptionSubmitting}
              onClick={deployDecoy}
            >
              {deceptionSubmitting ? 'Deploying...' : 'Deploy Decoy'}
            </button>

            <div className="card-title" style={{ marginTop: 20, marginBottom: 12 }}>
              Attacker Profiles
            </div>
            {attackerProfiles.length === 0 ? (
              <div className="empty">No attacker profiles have been built yet.</div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Source</th>
                      <th>Interactions</th>
                      <th>Threat</th>
                      <th>Last Seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {attackerProfiles.map((profile) => (
                      <tr key={profile.source_id}>
                        <td>
                          <div className="row-primary">{profile.source_id}</div>
                          <div className="row-secondary">
                            {Array.isArray(profile.decoys_touched)
                              ? profile.decoys_touched.join(', ')
                              : 'No decoys recorded'}
                          </div>
                        </td>
                        <td>{profile.interaction_count || 0}</td>
                        <td>{formatThreatScore(profile.threat_score)}</td>
                        <td>
                          {profile.last_seen ? formatDateTime(profile.last_seen) : 'No activity'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <JsonDetails data={deceptionData} label="Deception payload" />
          </div>
        </div>
      )}

      <JsonDetails
        data={{ library: libraryData, connectors: connectorsData, deception: deceptionData }}
        label="Threat ops payloads"
      />
    </div>
  );
}
