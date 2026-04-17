import { useState, useMemo, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useApi, useInterval, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import {
  ConfirmDialog,
  JsonDetails,
  SummaryGrid,
  formatDateTime,
  formatRelativeTime,
} from './operator.jsx';

const AGENT_COLUMNS = ['id', 'hostname', 'os', 'version', 'status', 'last_seen'];
const PAGE_SIZE = 25;
const SAVED_VIEWS = [
  { id: 'all', label: 'All Agents', filters: { status: 'all', q: '', os: 'all' } },
  { id: 'offline', label: 'Offline Agents > 1h', filters: { status: 'offline', q: '', os: 'all' } },
  { id: 'linux', label: 'Linux Fleet', filters: { status: 'all', q: '', os: 'linux' } },
];

function TriageEmptyState({ title, description, actionLabel, onAction }) {
  return (
    <div className="triage-empty">
      <div className="triage-empty-title">{title}</div>
      <div className="triage-empty-copy">{description}</div>
      {actionLabel && onAction && (
        <button className="btn btn-sm" onClick={onAction}>
          {actionLabel}
        </button>
      )}
    </div>
  );
}

function MobileAgentCard({ agent, active, onOpen, onCopy }) {
  return (
    <article
      className={`mobile-stack-card ${active ? 'active' : ''}`}
      role="button"
      tabIndex={0}
      onClick={() => onOpen(agent)}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          onOpen(agent);
        }
      }}
    >
      <div className="mobile-card-header">
        <div>
          <div className="mobile-card-title">{agent.hostname}</div>
          <div className="row-secondary">{agent.id}</div>
        </div>
        <span
          className={`badge ${agent.status === 'online' ? 'badge-ok' : agent.status === 'offline' ? 'badge-err' : 'badge-warn'}`}
        >
          {agent.status}
        </span>
      </div>
      <div className="mobile-card-meta">
        <span>{agent.os}</span>
        <span>{agent.version}</span>
        <span>{formatRelativeTime(agent.lastSeen)}</span>
      </div>
      <div className="mobile-card-actions">
        <button
          className="btn btn-sm btn-primary"
          onClick={(event) => {
            event.stopPropagation();
            onOpen(agent);
          }}
        >
          Inspect
        </button>
        <button
          className="btn btn-sm"
          onClick={(event) => {
            event.stopPropagation();
            onCopy(agent);
          }}
        >
          Copy
        </button>
      </div>
    </article>
  );
}

function normalizeAgent(agent, index) {
  const id = agent.id || agent.agent_id || `agent-${index}`;
  return {
    id,
    hostname: agent.hostname || agent.host || id,
    os: agent.os || agent.platform || 'unknown',
    version: agent.version || '—',
    status: agent.status || 'unknown',
    lastSeen: agent.last_seen || agent.last_heartbeat || null,
    raw: agent,
  };
}

export default function FleetAgents() {
  const toast = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const [tab, setTab] = useState(() => searchParams.get('fleetTab') || 'fleet');
  const [query, setQuery] = useState(() => searchParams.get('q') || '');
  const [statusFilter, setStatusFilter] = useState(() => searchParams.get('status') || 'all');
  const [osFilter, setOsFilter] = useState(() => searchParams.get('os') || 'all');
  const [nowMs, setNowMs] = useState(() => Date.now());
  const { data: fleetSt, reload: rFleet } = useApi(api.fleetStatus);
  const { data: dash } = useApi(api.fleetDashboard);
  const { data: agentList, reload: rAgents } = useApi(api.agents);
  const { data: swarm } = useApi(api.swarmPosture);
  const { data: swarmIntelData } = useApi(api.swarmIntel);
  const { data: plat } = useApi(api.platform);
  const { data: evts, reload: rEvents } = useApi(api.events);
  const { data: evtSum } = useApi(api.eventsSummary);
  const { data: policyHist } = useApi(api.policyHistory);
  const { data: releases } = useApi(api.updatesReleases);
  const { data: rollout } = useApi(api.rolloutConfig);
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [hoveredAgent, setHoveredAgent] = useState(null);
  const [agentDetail, setAgentDetail] = useState(null);
  const [selected, setSelected] = useState(new Set());
  const [page, setPage] = useState(0);
  const [confirmState, setConfirmState] = useState(null);

  const setFleetQueryState = useCallback(
    (updates) => {
      const next = new URLSearchParams(searchParams);
      Object.entries(updates).forEach(([key, value]) => {
        if (!value || value === 'all') next.delete(key);
        else next.set(key, value);
      });
      setSearchParams(next, { replace: true });
    },
    [searchParams, setSearchParams],
  );

  const handleTabChange = useCallback(
    (nextTab) => {
      setTab(nextTab);
      setFleetQueryState({ fleetTab: nextTab });
    },
    [setFleetQueryState],
  );

  useInterval(() => {
    rFleet();
    rAgents();
    setNowMs(Date.now());
  }, 15000);

  const agentArr = useMemo(
    () => (Array.isArray(agentList) ? agentList : agentList?.agents || []).map(normalizeAgent),
    [agentList],
  );
  const eventArr = Array.isArray(evts) ? evts : evts?.events || [];
  const statusOptions = ['all', ...new Set(agentArr.map((agent) => agent.status))];
  const osOptions = ['all', ...new Set(agentArr.map((agent) => String(agent.os).toLowerCase()))];

  const filteredAgents = useMemo(() => {
    return agentArr.filter((agent) => {
      const matchesQuery =
        !query || JSON.stringify(agent.raw).toLowerCase().includes(query.toLowerCase());
      const matchesStatus = statusFilter === 'all' || agent.status === statusFilter;
      const matchesOs =
        osFilter === 'all' || String(agent.os).toLowerCase().includes(osFilter.toLowerCase());
      if (statusFilter === 'offline' && SAVED_VIEWS[1].filters.status === 'offline') {
        const lastSeenMs = agent.lastSeen ? new Date(agent.lastSeen).getTime() : 0;
        const olderThanHour = !lastSeenMs || nowMs - lastSeenMs > 60 * 60 * 1000;
        return matchesQuery && matchesStatus && matchesOs && olderThanHour;
      }
      return matchesQuery && matchesStatus && matchesOs;
    });
  }, [agentArr, nowMs, osFilter, query, statusFilter]);

  const pagedAgents = useMemo(
    () => filteredAgents.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE),
    [filteredAgents, page],
  );
  const totalPages = Math.max(1, Math.ceil(filteredAgents.length / PAGE_SIZE));
  const hasFleetFilters = statusFilter !== 'all' || osFilter !== 'all' || Boolean(query);

  const currentPreview =
    agentDetail && selectedAgent
      ? { ...normalizeAgent(agentDetail, 0), raw: agentDetail }
      : hoveredAgent;
  const currentPreviewIndex = currentPreview
    ? filteredAgents.findIndex((agent) => agent.id === currentPreview.id)
    : -1;

  const queueHealth = useMemo(
    () => ({
      offline: agentArr.filter((agent) => agent.status === 'offline').length,
      stale: agentArr.filter(
        (agent) => agent.lastSeen && nowMs - new Date(agent.lastSeen).getTime() > 30 * 60 * 1000,
      ).length,
      linux: agentArr.filter((agent) => String(agent.os).toLowerCase().includes('linux')).length,
    }),
    [agentArr, nowMs],
  );

  const clearFleetFilters = useCallback(() => {
    setQuery('');
    setStatusFilter('all');
    setOsFilter('all');
    setPage(0);
    setFleetQueryState({ q: '', status: 'all', os: 'all' });
  }, [setFleetQueryState]);

  const openAgent = async (agent) => {
    setSelectedAgent(agent.id);
    setHoveredAgent(agent);
    try {
      const detail = await api.agentDetails(agent.id);
      setAgentDetail(detail);
    } catch {
      setAgentDetail(agent.raw);
    }
  };

  const copyRow = useCallback(
    (agent) => {
      const text = AGENT_COLUMNS.map(
        (column) =>
          `${column}: ${agent.raw[column] || agent.raw[column === 'id' ? 'agent_id' : column] || '—'}`,
      ).join(', ');
      navigator.clipboard.writeText(text).then(() => toast('Copied', 'success'));
    },
    [toast],
  );

  const toggleSelect = useCallback((id) => {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }, []);

  const allSelected =
    pagedAgents.length > 0 && pagedAgents.every((agent) => selected.has(agent.id));
  const toggleAll = useCallback(() => {
    setSelected((prev) => {
      const next = new Set(prev);
      pagedAgents.forEach((agent) => {
        if (allSelected) next.delete(agent.id);
        else next.add(agent.id);
      });
      return next;
    });
  }, [allSelected, pagedAgents]);

  const executeDelete = async (ids) => {
    const results = await Promise.allSettled(ids.map((id) => api.deleteAgent(id)));
    const ok = results.filter((result) => result.status === 'fulfilled').length;
    toast(`Removed ${ok}/${ids.length} agents`, ok === ids.length ? 'success' : 'warning');
    setSelected(new Set());
    if (selectedAgent && ids.includes(selectedAgent)) {
      setSelectedAgent(null);
      setAgentDetail(null);
    }
    setConfirmState(null);
    rAgents();
  };

  const activeViewId = SAVED_VIEWS.find(
    (view) =>
      view.filters.status === statusFilter &&
      view.filters.os === osFilter &&
      view.filters.q === query,
  )?.id;

  return (
    <div>
      <div className="tabs">
        {['fleet', 'agents', 'events', 'updates', 'swarm'].map((item) => (
          <button
            key={item}
            className={`tab ${tab === item ? 'active' : ''}`}
            onClick={() => handleTabChange(item)}
          >
            {item.charAt(0).toUpperCase() + item.slice(1)}
          </button>
        ))}
      </div>

      {tab === 'fleet' && (
        <>
          <div className="card-grid">
            <div className="card metric">
              <div className="metric-label">Total Agents</div>
              <div className="metric-value">{dash?.total_agents ?? dash?.agents ?? '—'}</div>
              <div className="metric-sub">Coverage across the current workspace</div>
            </div>
            <div className="card metric">
              <div className="metric-label">Offline Now</div>
              <div className="metric-value">{queueHealth.offline}</div>
              <div className="metric-sub">Endpoints that need recovery attention</div>
            </div>
            <div className="card metric">
              <div className="metric-label">Stale Heartbeats</div>
              <div className="metric-value">{queueHealth.stale}</div>
              <div className="metric-sub">Agents quiet for more than 30 minutes</div>
            </div>
            <div className="card metric">
              <div className="metric-label">Platform</div>
              <div className="metric-value">{plat?.os ?? plat?.platform ?? '—'}</div>
              <div className="metric-sub">Primary host environment</div>
            </div>
          </div>
          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>
              System Status
            </div>
            <SummaryGrid data={fleetSt} limit={12} />
          </div>
          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>
              Fleet Dashboard
            </div>
            <SummaryGrid data={dash} limit={12} />
            <JsonDetails data={dash} label="Fleet metrics breakdown" />
          </div>
        </>
      )}

      {tab === 'agents' && (
        <div className="triage-layout">
          <section className="triage-list card">
            <div className="card-header">
              <span className="card-title">Registered Agents ({filteredAgents.length})</span>
              <div className="btn-group">
                <button
                  className="btn btn-sm"
                  onClick={() => {
                    rAgents();
                    rFleet();
                  }}
                >
                  Refresh
                </button>
                <button
                  className="btn btn-sm btn-danger"
                  disabled={selected.size === 0}
                  onClick={() => setConfirmState({ type: 'bulk-delete' })}
                >
                  Delete {selected.size || ''} selected
                </button>
              </div>
            </div>

            <div className="triage-toolbar">
              <div className="triage-toolbar-group">
                {SAVED_VIEWS.map((view) => (
                  <button
                    key={view.id}
                    type="button"
                    className={`btn btn-sm ${activeViewId === view.id ? 'btn-primary' : ''}`}
                    onClick={() => {
                      setQuery(view.filters.q);
                      setStatusFilter(view.filters.status);
                      setOsFilter(view.filters.os);
                      setPage(0);
                      setFleetQueryState({
                        q: view.filters.q,
                        status: view.filters.status,
                        os: view.filters.os,
                      });
                    }}
                  >
                    {view.label}
                  </button>
                ))}
              </div>
              <div className="triage-toolbar-group triage-toolbar-group-right">
                <label className="sr-only" htmlFor="fleet-agent-query">
                  Search agents
                </label>
                <input
                  id="fleet-agent-query"
                  className="form-input triage-search"
                  placeholder="Search hostname, ID, OS, or version…"
                  value={query}
                  onChange={(event) => {
                    const value = event.target.value;
                    setQuery(value);
                    setPage(0);
                    setFleetQueryState({ q: value });
                  }}
                />
                <label className="sr-only" htmlFor="fleet-status-filter">
                  Filter by status
                </label>
                <select
                  id="fleet-status-filter"
                  className="form-select"
                  value={statusFilter}
                  onChange={(event) => {
                    const value = event.target.value;
                    setStatusFilter(value);
                    setPage(0);
                    setFleetQueryState({ status: value });
                  }}
                >
                  {statusOptions.map((status) => (
                    <option key={status} value={status}>
                      {status === 'all' ? 'All statuses' : status}
                    </option>
                  ))}
                </select>
                <label className="sr-only" htmlFor="fleet-os-filter">
                  Filter by OS
                </label>
                <select
                  id="fleet-os-filter"
                  className="form-select"
                  value={osFilter}
                  onChange={(event) => {
                    const value = event.target.value;
                    setOsFilter(value);
                    setPage(0);
                    setFleetQueryState({ os: value });
                  }}
                >
                  {osOptions.map((os) => (
                    <option key={os} value={os}>
                      {os === 'all' ? 'All platforms' : os}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="summary-grid triage-summary-grid">
              <div className="summary-card">
                <div className="summary-label">Filtered Fleet</div>
                <div className="summary-value">{filteredAgents.length}</div>
                <div className="summary-meta">Endpoints still in the current operator scope</div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Offline Over 1h</div>
                <div className="summary-value">{queueHealth.offline}</div>
                <div className="summary-meta">Saved views keep lagging endpoints visible</div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Stale Heartbeats</div>
                <div className="summary-value">{queueHealth.stale}</div>
                <div className="summary-meta">Likely needs recovery or rollout validation</div>
              </div>
              <div className="summary-card">
                <div className="summary-label">Selected</div>
                <div className="summary-value">{selected.size}</div>
                <div className="summary-meta">Endpoint records pinned for bulk actions</div>
              </div>
            </div>

            <div className="active-filter-chips">
              {statusFilter !== 'all' && <span className="scope-chip">Status: {statusFilter}</span>}
              {osFilter !== 'all' && <span className="scope-chip">OS: {osFilter}</span>}
              {query && <span className="scope-chip">Query: {query}</span>}
              {hasFleetFilters && (
                <button className="filter-chip-button" onClick={clearFleetFilters}>
                  Reset filters
                </button>
              )}
            </div>
            <div className="triage-meta-bar">
              <div className="hint">
                Showing {pagedAgents.length} agent{pagedAgents.length === 1 ? '' : 's'} on page{' '}
                {page + 1} of {totalPages}. {queueHealth.offline} endpoints are currently offline.
              </div>
              {hasFleetFilters && (
                <button className="btn btn-sm" onClick={clearFleetFilters}>
                  Clear Scope
                </button>
              )}
            </div>

            {filteredAgents.length === 0 ? (
              <TriageEmptyState
                title="No agents match the current view"
                description="The fleet is available, but the current search and platform filters narrowed this view to zero endpoints. Clear the scope or switch a saved view to continue operating."
                actionLabel={hasFleetFilters ? 'Clear Filters' : null}
                onAction={hasFleetFilters ? clearFleetFilters : null}
              />
            ) : (
              <>
                <div className="split-list-table">
                  <div className="desktop-table-only">
                    <table>
                      <thead>
                        <tr>
                          <th style={{ width: 32 }}>
                            <input
                              type="checkbox"
                              checked={allSelected}
                              onChange={toggleAll}
                              aria-label="Select all visible agents"
                            />
                          </th>
                          <th>Host</th>
                          <th>Status</th>
                          <th>OS</th>
                          <th>Version</th>
                          <th>Last Seen</th>
                        </tr>
                      </thead>
                      <tbody>
                        {pagedAgents.map((agent) => {
                          const isActive =
                            (selectedAgent && selectedAgent === agent.id) ||
                            hoveredAgent?.id === agent.id;
                          return (
                            <tr
                              key={agent.id}
                              className={isActive ? 'row-active' : ''}
                              onMouseEnter={() => setHoveredAgent(agent)}
                              onFocus={() => setHoveredAgent(agent)}
                              onClick={() => openAgent(agent)}
                              tabIndex={0}
                            >
                              <td onClick={(event) => event.stopPropagation()}>
                                <input
                                  type="checkbox"
                                  checked={selected.has(agent.id)}
                                  onChange={() => toggleSelect(agent.id)}
                                  aria-label={`Select ${agent.hostname}`}
                                />
                              </td>
                              <td>
                                <div className="row-primary">{agent.hostname}</div>
                                <div className="row-secondary">{agent.id}</div>
                              </td>
                              <td>
                                <span
                                  className={`badge ${agent.status === 'online' ? 'badge-ok' : agent.status === 'offline' ? 'badge-err' : 'badge-warn'}`}
                                >
                                  {agent.status}
                                </span>
                              </td>
                              <td>{agent.os}</td>
                              <td>{agent.version}</td>
                              <td>
                                <div className="row-primary">
                                  {formatRelativeTime(agent.lastSeen)}
                                </div>
                                <div className="row-secondary">
                                  {formatDateTime(agent.lastSeen)}
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                  <div className="mobile-stack">
                    {pagedAgents.map((agent) => {
                      const isActive =
                        (selectedAgent && selectedAgent === agent.id) ||
                        hoveredAgent?.id === agent.id;
                      return (
                        <MobileAgentCard
                          key={agent.id}
                          agent={agent}
                          active={isActive}
                          onOpen={openAgent}
                          onCopy={copyRow}
                        />
                      );
                    })}
                  </div>
                </div>
                {totalPages > 1 && (
                  <div className="triage-pagination">
                    <button
                      className="btn btn-sm"
                      disabled={page === 0}
                      onClick={() => setPage((current) => current - 1)}
                    >
                      Previous
                    </button>
                    <span>
                      {page + 1} / {totalPages}
                    </span>
                    <button
                      className="btn btn-sm"
                      disabled={page >= totalPages - 1}
                      onClick={() => setPage((current) => current + 1)}
                    >
                      Next
                    </button>
                  </div>
                )}
              </>
            )}
          </section>

          <aside className="triage-detail card">
            <div className="card-header">
              <span className="card-title">
                {currentPreview ? currentPreview.hostname : 'Agent Preview'}
              </span>
              {currentPreview && (
                <div className="btn-group">
                  <button className="btn btn-sm" onClick={() => copyRow(currentPreview)}>
                    Copy
                  </button>
                  <button
                    className="btn btn-sm btn-danger"
                    onClick={() =>
                      setConfirmState({
                        type: 'single-delete',
                        id: currentPreview.id,
                        hostname: currentPreview.hostname,
                      })
                    }
                  >
                    Remove
                  </button>
                </div>
              )}
            </div>
            {currentPreview ? (
              <>
                <div className="triage-detail-nav">
                  <span className="scope-chip">
                    {currentPreviewIndex + 1} of {filteredAgents.length}
                  </span>
                  <div className="btn-group">
                    <button
                      className="btn btn-sm"
                      onClick={() =>
                        currentPreviewIndex > 0 &&
                        openAgent(filteredAgents[currentPreviewIndex - 1])
                      }
                      disabled={currentPreviewIndex <= 0}
                    >
                      Previous
                    </button>
                    <button
                      className="btn btn-sm"
                      onClick={() =>
                        currentPreviewIndex < filteredAgents.length - 1 &&
                        openAgent(filteredAgents[currentPreviewIndex + 1])
                      }
                      disabled={currentPreviewIndex >= filteredAgents.length - 1}
                    >
                      Next
                    </button>
                    {!selectedAgent && (
                      <button
                        className="btn btn-sm btn-primary"
                        onClick={() => openAgent(currentPreview)}
                      >
                        Pin Preview
                      </button>
                    )}
                  </div>
                </div>
                <div className="detail-hero">
                  <div>
                    <div className="detail-hero-title">{currentPreview.hostname}</div>
                    <div className="detail-hero-copy">
                      {currentPreview.status === 'offline'
                        ? 'Needs operator attention'
                        : 'Healthy endpoint context available'}
                    </div>
                  </div>
                  <span
                    className={`badge ${currentPreview.status === 'online' ? 'badge-ok' : currentPreview.status === 'offline' ? 'badge-err' : 'badge-warn'}`}
                  >
                    {currentPreview.status}
                  </span>
                </div>
                <div className="summary-grid" style={{ marginTop: 16 }}>
                  <div className="summary-card">
                    <div className="summary-label">Agent ID</div>
                    <div className="summary-value">{currentPreview.id}</div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Operating System</div>
                    <div className="summary-value">{currentPreview.os}</div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Version</div>
                    <div className="summary-value">{currentPreview.version}</div>
                  </div>
                  <div className="summary-card">
                    <div className="summary-label">Last Seen</div>
                    <div className="summary-value">
                      {formatRelativeTime(currentPreview.lastSeen)}
                    </div>
                    <div className="summary-meta">
                      <div>{formatDateTime(currentPreview.lastSeen)}</div>
                    </div>
                  </div>
                </div>
                <div className="detail-callout" style={{ marginTop: 16 }}>
                  {currentPreview.status === 'offline'
                    ? 'This endpoint is offline. Review recent heartbeat time and recovery readiness before rolling out changes.'
                    : 'This endpoint is healthy. Use this panel to verify version, platform, and detailed inventory quickly.'}
                </div>
                <JsonDetails
                  data={agentDetail || currentPreview.raw}
                  label="Detailed endpoint context"
                />
              </>
            ) : (
              <TriageEmptyState
                title="No agent preview yet"
                description="Hover a row on desktop or tap a card on mobile to inspect endpoint details without losing list position."
              />
            )}
          </aside>
        </div>
      )}

      {tab === 'events' && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Events ({eventArr.length})</span>
            <div className="btn-group">
              <button className="btn btn-sm" onClick={rEvents}>
                Refresh
              </button>
              <button
                className="btn btn-sm"
                onClick={async () => {
                  try {
                    const data = await api.eventsExport();
                    const blob = new Blob(
                      [typeof data === 'string' ? data : JSON.stringify(data)],
                      { type: 'application/json' },
                    );
                    const url = URL.createObjectURL(blob);
                    const link = document.createElement('a');
                    link.href = url;
                    link.download = 'events.json';
                    link.click();
                    setTimeout(() => URL.revokeObjectURL(url), 1000);
                    toast('Events exported', 'success');
                  } catch {
                    toast('Export failed', 'error');
                  }
                }}
              >
                Export
              </button>
            </div>
          </div>
          {evtSum && (
            <div style={{ marginBottom: 16 }}>
              <SummaryGrid data={evtSum} limit={10} />
              <JsonDetails data={evtSum} />
            </div>
          )}
          {eventArr.length === 0 ? (
            <div className="empty">No events</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Type</th>
                    <th>Source</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {eventArr.slice(0, 100).map((event, index) => (
                    <tr key={index}>
                      <td
                        style={{
                          whiteSpace: 'nowrap',
                          fontSize: 12,
                          fontFamily: 'var(--font-mono)',
                        }}
                      >
                        {event.timestamp || event.time || '—'}
                      </td>
                      <td>{event.event_type || event.type || '—'}</td>
                      <td>{event.source || '—'}</td>
                      <td>
                        {event.message || event.description || JSON.stringify(event).slice(0, 100)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === 'updates' && (
        <>
          {releases && (
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>
                Available Releases
              </div>
              <SummaryGrid data={releases} limit={12} />
              <JsonDetails data={releases} />
            </div>
          )}
          <div className="card-grid">
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                Rollout Config
              </div>
              <SummaryGrid data={rollout} limit={10} />
              <JsonDetails data={rollout} />
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>
                Policy History
              </div>
              <SummaryGrid data={policyHist} limit={10} />
              <JsonDetails data={policyHist} />
            </div>
          </div>
        </>
      )}

      {tab === 'swarm' && (
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>
              Swarm Posture
            </div>
            <SummaryGrid data={swarm} limit={12} />
            <JsonDetails data={swarm} />
          </div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>
              Swarm Intel
            </div>
            <SummaryGrid data={swarmIntelData} limit={12} />
            <JsonDetails data={swarmIntelData} />
          </div>
        </>
      )}

      <ConfirmDialog
        open={Boolean(confirmState)}
        title={
          confirmState?.type === 'bulk-delete' ? 'Delete selected agents?' : 'Remove this agent?'
        }
        message={
          confirmState?.type === 'bulk-delete'
            ? `This will remove ${selected.size} agent records from the console. Use this only when the endpoints have been decommissioned.`
            : `This will remove ${confirmState?.hostname || 'the selected agent'} from the console and can disrupt operator context if used accidentally.`
        }
        confirmLabel={confirmState?.type === 'bulk-delete' ? 'Delete Agents' : 'Remove Agent'}
        onCancel={() => setConfirmState(null)}
        onConfirm={() =>
          executeDelete(confirmState?.type === 'bulk-delete' ? [...selected] : [confirmState.id])
        }
      />
    </div>
  );
}
