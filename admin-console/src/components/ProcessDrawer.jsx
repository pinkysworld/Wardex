import { useMemo } from 'react';
import { useApi, useApiGroup, useToast } from '../hooks.jsx';
import * as api from '../api.js';
import { JsonDetails, SideDrawer, SummaryGrid } from './operator.jsx';
import { downloadData } from './operatorUtils.js';
import { useConfirm } from './useConfirm.jsx';

function requestSeverity(detail) {
  const risk = (detail?.risk_level || '').toLowerCase();
  if (risk === 'critical') return 'critical';
  if (risk === 'severe') return 'high';
  if (risk === 'elevated') return 'medium';
  return 'low';
}

function buildSnapshotDetail(pid, snapshot) {
  if (!snapshot) return null;
  const name = snapshot.name || snapshot.display_name || `PID ${pid}`;
  const displayName = snapshot.display_name || String(name).split('/').pop() || `PID ${pid}`;
  const riskLevel = snapshot.risk_level || 'nominal';
  const finding = snapshot.reason
    ? {
        pid,
        name,
        user: snapshot.user || 'unknown',
        risk_level: riskLevel,
        reason: snapshot.reason,
        cpu_percent: snapshot.cpu_percent ?? 0,
        mem_percent: snapshot.mem_percent ?? 0,
      }
    : null;
  const findings = Array.isArray(snapshot.findings) ? snapshot.findings : finding ? [finding] : [];
  const recommendations = snapshot.analysis?.recommendations?.length
    ? snapshot.analysis.recommendations
    : [
        'This process exited before Wardex could collect a full live inspection.',
        'The fields below come from the last visible snapshot in the process table.',
      ];
  return {
    pid,
    ppid: snapshot.ppid ?? null,
    name,
    display_name: displayName,
    user: snapshot.user || 'unknown',
    group: snapshot.group || '—',
    cpu_percent: snapshot.cpu_percent ?? 0,
    mem_percent: snapshot.mem_percent ?? 0,
    hostname: snapshot.hostname || 'Local host',
    platform: snapshot.platform || 'macos',
    cmd_line: snapshot.cmd_line || name,
    exe_path: snapshot.exe_path || (String(name).includes('/') ? name : null),
    cwd: snapshot.cwd || null,
    start_time: snapshot.start_time || null,
    elapsed: snapshot.elapsed || null,
    risk_level: riskLevel,
    findings,
    network_activity: snapshot.network_activity || [],
    code_signature: snapshot.code_signature || null,
    analysis: {
      self_process: Boolean(snapshot.analysis?.self_process),
      listener_count: snapshot.analysis?.listener_count ?? 0,
      recommendations,
      exited_before_inspection: true,
    },
  };
}

function processDisplayName(process) {
  const name = process?.display_name || process?.name || `PID ${process?.pid || 'unknown'}`;
  return String(name).split('/').pop() || `PID ${process?.pid || 'unknown'}`;
}

function processParentPid(process) {
  const parentPid = process?.ppid ?? process?.parent_pid ?? null;
  return parentPid == null ? null : Number(parentPid);
}

function normalizeProcessNodes(treeData) {
  const items = Array.isArray(treeData?.processes)
    ? treeData.processes
    : Array.isArray(treeData?.nodes)
      ? treeData.nodes
      : [];
  return items
    .map((process) => ({
      ...process,
      pid: Number(process.pid),
      ppid: processParentPid(process),
    }))
    .filter((process) => Number.isFinite(process.pid));
}

function normalizeDeepChains(chainData) {
  const items = Array.isArray(chainData?.deep_chains)
    ? chainData.deep_chains
    : Array.isArray(chainData?.chains)
      ? chainData.chains
      : [];

  return items.map((chain, index) => {
    if (Array.isArray(chain?.chain)) {
      return {
        pid: chain.pid != null ? Number(chain.pid) : null,
        depth: chain.depth ?? chain.chain.length,
        summary: chain.chain.join(' → '),
        name: chain.name || chain.chain.at(-1) || `Chain ${index + 1}`,
        cmd_line: chain.cmd_line || null,
      };
    }

    return {
      ...chain,
      pid: chain?.pid != null ? Number(chain.pid) : null,
      depth: chain?.depth ?? null,
      summary:
        chain?.summary ||
        [chain?.name, chain?.cmd_line].filter(Boolean).join(' · ') ||
        `Suspicious chain ${index + 1}`,
    };
  });
}

function normalizeThreadItems(items) {
  return (Array.isArray(items) ? items : [])
    .map((thread, index) => ({
      ...thread,
      thread_id: Number(thread.thread_id ?? thread.os_thread_id ?? index + 1),
      os_thread_id: thread.os_thread_id ?? null,
      cpu_percent: Number(thread.cpu_percent ?? 0),
      state: thread.state || 'unknown',
      state_label: thread.state_label || 'unknown',
      wait_reason: thread.wait_reason || null,
    }))
    .filter((thread) => Number.isFinite(thread.thread_id));
}

function normalizeProcessThreads(threadData) {
  return normalizeThreadItems(threadData?.threads);
}

function buildProcessGraphContext(detail, nodes, chains) {
  const pid = Number(detail?.pid || 0);
  if (!pid) {
    return {
      current: null,
      parent: null,
      lineage: [],
      children: [],
      siblings: [],
      suspiciousChain: null,
    };
  }

  const byPid = new Map(nodes.map((node) => [Number(node.pid), node]));
  const current = byPid.get(pid) || {
    pid,
    ppid: processParentPid(detail),
    name: detail?.name || detail?.display_name || `PID ${pid}`,
    cmd_line: detail?.cmd_line || null,
    user: detail?.user || 'unknown',
    hostname: detail?.hostname || 'Local host',
  };
  const parentPid = processParentPid(current);
  const parent = parentPid ? byPid.get(parentPid) || null : null;
  const lineage = [];
  const seen = new Set();
  let cursor = current;

  while (cursor && !seen.has(Number(cursor.pid))) {
    lineage.unshift(cursor);
    seen.add(Number(cursor.pid));
    const nextParentPid = processParentPid(cursor);
    cursor = nextParentPid ? byPid.get(nextParentPid) || null : null;
  }

  const children = nodes.filter((node) => processParentPid(node) === pid).slice(0, 6);
  const siblings = parentPid
    ? nodes.filter((node) => node.pid !== pid && processParentPid(node) === parentPid).slice(0, 6)
    : [];
  const suspiciousChain =
    chains.find((chain) => chain.pid != null && Number(chain.pid) === pid) || null;

  return {
    current,
    parent,
    lineage,
    children,
    siblings,
    suspiciousChain,
  };
}

function ProcessRelationPanel({ title, items, onSelectProcess }) {
  if (!items?.length) return null;

  return (
    <div>
      <div className="metric-label" style={{ marginBottom: 8 }}>
        {title}
      </div>
      <div style={{ display: 'grid', gap: 8 }}>
        {items.map((process) => (
          <div
            key={`${title}-${process.pid}`}
            className="card"
            style={{
              padding: 12,
              display: 'flex',
              justifyContent: 'space-between',
              gap: 12,
              alignItems: 'center',
            }}
          >
            <div>
              <div className="row-primary">{processDisplayName(process)}</div>
              <div className="row-secondary">
                PID {process.pid}
                {process.user ? ` · ${process.user}` : ''}
                {process.cmd_line ? ` · ${process.cmd_line}` : ''}
              </div>
            </div>
            {onSelectProcess && (
              <button className="btn btn-sm" onClick={() => onSelectProcess(process)}>
                Inspect {processDisplayName(process)}
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

export default function ProcessDrawer({
  pid,
  snapshot,
  onClose,
  onUpdated,
  onSelectProcess,
  onPrevious,
  onNext,
  canPrevious = false,
  canNext = false,
  positionLabel = null,
}) {
  const toast = useToast();
  const [confirm, confirmUI] = useConfirm();
  const {
    data: detail,
    loading,
    error,
    reload,
  } = useApi(() => api.processDetail(pid), [pid], { skip: !pid });
  const { data: processContextData, reload: reloadProcessContext } = useApiGroup(
    {
      processTree: api.processTree,
      deepChains: api.deepChains,
      processThreads: () => api.processThreads(pid),
    },
    [pid],
    { skip: !pid },
  );
  const processGone = error?.status === 404;
  const snapshotDetail = useMemo(() => buildSnapshotDetail(pid, snapshot), [pid, snapshot]);
  const usingSnapshotFallback = Boolean(snapshotDetail) && !detail && Boolean(error);
  const activeDetail = detail || (usingSnapshotFallback ? snapshotDetail : null);
  const processNodes = useMemo(
    () => normalizeProcessNodes(processContextData.processTree),
    [processContextData.processTree],
  );
  const suspiciousChains = useMemo(
    () => normalizeDeepChains(processContextData.deepChains),
    [processContextData.deepChains],
  );
  const processThreads = useMemo(
    () => normalizeProcessThreads(processContextData.processThreads),
    [processContextData.processThreads],
  );
  const graphContext = useMemo(
    () => buildProcessGraphContext(activeDetail, processNodes, suspiciousChains),
    [activeDetail, processNodes, suspiciousChains],
  );
  const threadSummary = useMemo(() => {
    const threadData = processContextData.processThreads || {};
    const hotThreads = normalizeThreadItems(threadData.hot_threads);
    const blockedThreads = normalizeThreadItems(threadData.blocked_threads);
    const runningCount =
      threadData.running_count ??
      processThreads.filter((thread) => thread.state_label === 'running').length;
    const sleepingCount =
      threadData.sleeping_count ??
      processThreads.filter((thread) => ['sleeping', 'idle'].includes(thread.state_label)).length;
    const blockedCount =
      threadData.blocked_count ??
      processThreads.filter((thread) => ['blocked', 'stopped'].includes(thread.state_label)).length;
    const topCpuPercent =
      threadData.top_cpu_percent ??
      processThreads.reduce(
        (maxCpu, thread) => Math.max(maxCpu, Number(thread.cpu_percent || 0)),
        0,
      );
    const waitReasonCount =
      threadData.wait_reason_count ??
      processThreads.filter((thread) => Boolean(thread.wait_reason)).length;

    return {
      threadCount: threadData.thread_count ?? processThreads.length,
      runningCount,
      sleepingCount,
      blockedCount,
      hotThreadCount:
        threadData.hot_thread_count ??
        processThreads.filter((thread) => Number(thread.cpu_percent || 0) >= 5).length,
      identifierType: threadData.identifier_type || null,
      note: threadData.note || null,
      message: threadData.message || null,
      topCpuPercent,
      waitReasonCount,
      hotThreads:
        hotThreads.length > 0
          ? hotThreads
          : [...processThreads]
              .sort((left, right) => Number(right.cpu_percent || 0) - Number(left.cpu_percent || 0))
              .slice(0, 3),
      blockedThreads:
        blockedThreads.length > 0
          ? blockedThreads
          : processThreads
              .filter((thread) => ['blocked', 'stopped'].includes(thread.state_label))
              .slice(0, 4),
    };
  }, [processContextData.processThreads, processThreads]);

  const summary = useMemo(() => {
    if (!activeDetail) return null;
    return {
      pid: activeDetail.pid,
      ppid: activeDetail.ppid,
      user: activeDetail.user,
      group: activeDetail.group,
      cpu_percent: activeDetail.cpu_percent,
      mem_percent: activeDetail.mem_percent,
      hostname: activeDetail.hostname,
      platform: activeDetail.platform,
      start_time: activeDetail.start_time,
      elapsed: activeDetail.elapsed,
      risk_level: activeDetail.risk_level,
    };
  }, [activeDetail]);

  if (!pid) return null;

  const queueAction = async (body, label) => {
    try {
      const result = await api.responseRequest(body);
      const status = result?.request?.status || result?.status || 'submitted';
      toast(`${label} request ${String(status).toLowerCase()}`, 'success');
      onUpdated?.();
    } catch {
      toast(`${label} request failed`, 'error');
    }
  };

  const queueKill = async () => {
    if (!detail) return;
    const procLabel = detail.display_name || detail.name;
    const ok = await confirm({
      title: `Queue kill for PID ${detail.pid}?`,
      message: `Wardex will send a kill request for ${procLabel} on ${detail.hostname}. This is auditable and reversible only by re-launching the process.`,
      confirmLabel: 'Queue kill',
      cancelLabel: 'Cancel',
      tone: 'danger',
    });
    if (!ok) return;
    await queueAction(
      {
        action: 'kill_process',
        pid: detail.pid,
        process_name: procLabel,
        hostname: detail.hostname,
        severity: requestSeverity(detail),
        reason: `Operator-requested kill for ${procLabel} via admin console`,
      },
      'Kill',
    );
  };

  const queueIsolate = async () => {
    if (!detail) return;
    const ok = await confirm({
      title: `Isolate ${detail.hostname}?`,
      message: `Host isolation quarantines the endpoint from the network except for Wardex control. Services on the host will become unreachable.`,
      confirmLabel: 'Isolate host',
      cancelLabel: 'Cancel',
      tone: 'warning',
    });
    if (!ok) return;
    await queueAction(
      {
        action: 'isolate',
        hostname: detail.hostname,
        severity: requestSeverity(detail),
        reason: `Operator-requested host isolation while investigating PID ${detail.pid}`,
      },
      'Isolation',
    );
  };

  return (
    <>
      <SideDrawer
        open={!!pid}
        onClose={onClose}
        title={activeDetail?.display_name || activeDetail?.name || `PID ${pid}`}
        subtitle={
          activeDetail ? `${activeDetail.platform} · ${activeDetail.hostname}` : `PID ${pid}`
        }
        actions={
          <>
            {(onPrevious || onNext || positionLabel) && (
              <div className="drawer-nav">
                {positionLabel && <span className="scope-chip">{positionLabel}</span>}
                {onPrevious && (
                  <button className="btn btn-sm" onClick={onPrevious} disabled={!canPrevious}>
                    Previous
                  </button>
                )}
                {onNext && (
                  <button className="btn btn-sm" onClick={onNext} disabled={!canNext}>
                    Next
                  </button>
                )}
              </div>
            )}
            <button
              className="btn btn-sm"
              onClick={() => {
                reload();
                reloadProcessContext();
              }}
            >
              Refresh
            </button>
            {activeDetail && (
              <button
                className="btn btn-sm"
                onClick={() => downloadData(activeDetail, `process-${activeDetail.pid}.json`)}
              >
                Export
              </button>
            )}
            <button
              className="btn btn-sm"
              disabled={!detail || detail?.analysis?.self_process}
              onClick={queueKill}
            >
              Queue Kill
            </button>
            <button className="btn btn-sm btn-primary" disabled={!detail} onClick={queueIsolate}>
              Queue Isolate
            </button>
          </>
        }
      >
        {loading && (
          <div className="loading">
            <div className="spinner" />
          </div>
        )}
        {processGone && usingSnapshotFallback && (
          <div className="error-box">
            This process exited before Wardex could complete a live inspection. Showing the last
            known snapshot from the process table.
          </div>
        )}
        {error && !processGone && usingSnapshotFallback && (
          <div className="error-box">
            Live inspection is temporarily unavailable. Showing the last known snapshot from the
            process table while Wardex retries this PID.
          </div>
        )}
        {error && !usingSnapshotFallback && (
          <div className="error-box">Failed to load process detail.</div>
        )}
        {activeDetail && (
          <>
            <SummaryGrid data={summary} limit={10} />

            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 8 }}>
                Investigation Context
              </div>
              <div className="drawer-copy-grid">
                <div>
                  <div className="metric-label">Lineage depth</div>
                  <div style={{ fontSize: 22, fontWeight: 700 }}>
                    {graphContext.lineage.length || '—'}
                  </div>
                  <div className="row-secondary">
                    {graphContext.lineage.length > 0
                      ? `${graphContext.lineage.length - 1} parent hop${graphContext.lineage.length === 2 ? '' : 's'} to the root context.`
                      : 'No current process tree context was published for this PID.'}
                  </div>
                </div>
                <div>
                  <div className="metric-label">Suspicious chain</div>
                  <div style={{ fontSize: 22, fontWeight: 700 }}>
                    {graphContext.suspiciousChain?.depth || '—'}
                  </div>
                  <div className="row-secondary">
                    {graphContext.suspiciousChain
                      ? `Matched a deep process chain with depth ${graphContext.suspiciousChain.depth}.`
                      : 'No deep-chain match currently associated with this process.'}
                  </div>
                </div>
                <div>
                  <div className="metric-label">Related processes</div>
                  <div style={{ fontSize: 22, fontWeight: 700 }}>
                    {Number(Boolean(graphContext.parent)) +
                      graphContext.children.length +
                      graphContext.siblings.length}
                  </div>
                  <div className="row-secondary">
                    {graphContext.parent ? 'Parent available' : 'No parent'}
                    {graphContext.children.length > 0
                      ? ` · ${graphContext.children.length} child`
                      : ''}
                    {graphContext.children.length > 1 ? 'ren' : ''}
                    {graphContext.siblings.length > 0
                      ? ` · ${graphContext.siblings.length} sibling`
                      : ''}
                    {graphContext.siblings.length > 1 ? 's' : ''}
                  </div>
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <div className="metric-label" style={{ marginBottom: 8 }}>
                    Lineage
                  </div>
                  {graphContext.lineage.length > 0 ? (
                    <div className="chip-row">
                      {graphContext.lineage.map((process) => (
                        <span key={`lineage-${process.pid}`} className="scope-chip">
                          {processDisplayName(process)} (PID {process.pid})
                        </span>
                      ))}
                    </div>
                  ) : (
                    <div className="hint">
                      Wardex has not published the current lineage for this PID yet. Refresh when
                      the live process tree updates.
                    </div>
                  )}
                </div>
                {graphContext.suspiciousChain && (
                  <div style={{ gridColumn: '1 / -1' }}>
                    <div className="metric-label">Deep-chain summary</div>
                    <div className="hint" style={{ marginTop: 6 }}>
                      {graphContext.suspiciousChain.summary}
                    </div>
                  </div>
                )}
              </div>

              {(graphContext.parent ||
                graphContext.children.length > 0 ||
                graphContext.siblings.length > 0) && (
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                    gap: 12,
                    marginTop: 16,
                  }}
                >
                  <ProcessRelationPanel
                    title="Parent Process"
                    items={graphContext.parent ? [graphContext.parent] : []}
                    onSelectProcess={onSelectProcess}
                  />
                  <ProcessRelationPanel
                    title="Child Processes"
                    items={graphContext.children}
                    onSelectProcess={onSelectProcess}
                  />
                  <ProcessRelationPanel
                    title="Sibling Processes"
                    items={graphContext.siblings}
                    onSelectProcess={onSelectProcess}
                  />
                </div>
              )}
            </div>

            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 8 }}>
                Execution Context
              </div>
              <div className="drawer-copy-grid">
                <div>
                  <div className="metric-label">Executable</div>
                  <div
                    style={{ fontFamily: 'var(--font-mono)', fontSize: 12, wordBreak: 'break-all' }}
                  >
                    {activeDetail.exe_path || 'Unavailable'}
                  </div>
                </div>
                <div>
                  <div className="metric-label">Working Directory</div>
                  <div
                    style={{ fontFamily: 'var(--font-mono)', fontSize: 12, wordBreak: 'break-all' }}
                  >
                    {activeDetail.cwd || 'Unavailable'}
                  </div>
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <div className="metric-label">Command Line</div>
                  <div
                    style={{ fontFamily: 'var(--font-mono)', fontSize: 12, wordBreak: 'break-all' }}
                  >
                    {activeDetail.cmd_line || 'Unavailable'}
                  </div>
                </div>
              </div>
            </div>

            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title" style={{ marginBottom: 8 }}>
                Thread Activity
              </div>
              <div className="drawer-copy-grid">
                <div>
                  <div className="metric-label">Threads</div>
                  <div style={{ fontSize: 22, fontWeight: 700 }}>{threadSummary.threadCount}</div>
                  <div className="row-secondary">
                    {threadSummary.identifierType === 'row_slot'
                      ? 'macOS row-slot identifiers from the live ps thread view'
                      : 'OS thread identifiers captured for this process'}
                  </div>
                </div>
                <div>
                  <div className="metric-label">Running / Hot</div>
                  <div style={{ fontSize: 22, fontWeight: 700 }}>
                    {threadSummary.runningCount} / {threadSummary.hotThreadCount}
                  </div>
                  <div className="row-secondary">
                    {threadSummary.hotThreadCount > 0
                      ? `${threadSummary.hotThreadCount} thread${threadSummary.hotThreadCount === 1 ? '' : 's'} above 5% CPU.`
                      : 'No thread currently exceeds 5% CPU.'}
                  </div>
                </div>
                <div>
                  <div className="metric-label">Sleeping / Blocked</div>
                  <div style={{ fontSize: 22, fontWeight: 700 }}>
                    {threadSummary.sleepingCount} / {threadSummary.blockedCount}
                  </div>
                  <div className="row-secondary">
                    {threadSummary.waitReasonCount > 0
                      ? `${threadSummary.waitReasonCount} thread${threadSummary.waitReasonCount === 1 ? '' : 's'} exposed a wait reason at collection time.`
                      : 'Use these counts to separate normal wait states from stuck or suspended workers.'}
                  </div>
                </div>
                <div>
                  <div className="metric-label">Peak Thread CPU</div>
                  <div style={{ fontSize: 22, fontWeight: 700 }}>
                    {Number(threadSummary.topCpuPercent || 0).toFixed(1)}%
                  </div>
                  <div className="row-secondary">
                    Highest per-thread CPU share at collection time.
                  </div>
                </div>
              </div>
              {threadSummary.note && (
                <div className="detail-callout" style={{ marginTop: 12 }}>
                  {threadSummary.note}
                </div>
              )}
              {threadSummary.hotThreads.length > 0 && (
                <div className="hint" style={{ marginTop: 12 }}>
                  Hottest threads:{' '}
                  {threadSummary.hotThreads
                    .map(
                      (thread) =>
                        `T${thread.thread_id} ${Number(thread.cpu_percent || 0).toFixed(1)}%`,
                    )
                    .join(' · ')}
                </div>
              )}
              {threadSummary.blockedThreads.length > 0 && (
                <div className="detail-callout" style={{ marginTop: 12 }}>
                  Blocked threads:{' '}
                  {threadSummary.blockedThreads
                    .map((thread) =>
                      thread.wait_reason
                        ? `T${thread.thread_id} waiting on ${thread.wait_reason}`
                        : `T${thread.thread_id} ${thread.state_label}`,
                    )
                    .join(' · ')}
                </div>
              )}
              {threadSummary.message ? (
                <div className="hint" style={{ marginTop: 12 }}>
                  {threadSummary.message}
                </div>
              ) : processThreads.length > 0 ? (
                <div className="table-wrap" style={{ marginTop: 12 }}>
                  <table>
                    <thead>
                      <tr>
                        <th>Thread</th>
                        <th>State</th>
                        <th>CPU</th>
                        <th>Priority</th>
                        <th>Wait</th>
                        <th>Runtime</th>
                      </tr>
                    </thead>
                    <tbody>
                      {processThreads.slice(0, 10).map((thread) => (
                        <tr key={`thread-${thread.thread_id}`}>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                            {thread.thread_id}
                            {thread.os_thread_id != null && thread.os_thread_id !== thread.thread_id
                              ? ` / ${thread.os_thread_id}`
                              : ''}
                          </td>
                          <td>
                            <span className="scope-chip">
                              {thread.state_label || thread.state || 'unknown'}
                            </span>
                          </td>
                          <td>{Number(thread.cpu_percent || 0).toFixed(1)}%</td>
                          <td>{thread.priority || '—'}</td>
                          <td
                            style={{
                              fontFamily: 'var(--font-mono)',
                              fontSize: 12,
                              wordBreak: 'break-all',
                            }}
                          >
                            {thread.wait_reason || '—'}
                          </td>
                          <td>
                            {thread.cpu_time ||
                              [thread.system_time, thread.user_time].filter(Boolean).join(' / ') ||
                              '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="hint" style={{ marginTop: 12 }}>
                  Wardex did not capture per-thread rows for this process yet. Refresh the drawer to
                  retry the live thread snapshot.
                </div>
              )}
            </div>

            {activeDetail.findings?.length > 0 && (
              <div className="card" style={{ marginTop: 16 }}>
                <div className="card-title" style={{ marginBottom: 8 }}>
                  Behavioural Findings
                </div>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Risk</th>
                        <th>Reason</th>
                        <th>CPU</th>
                        <th>Memory</th>
                      </tr>
                    </thead>
                    <tbody>
                      {activeDetail.findings.map((finding, index) => (
                        <tr key={`${finding.pid}-${index}`}>
                          <td>
                            <span className={`sev-${finding.risk_level}`}>
                              {finding.risk_level}
                            </span>
                          </td>
                          <td>{finding.reason}</td>
                          <td>{finding.cpu_percent?.toFixed?.(1) ?? finding.cpu_percent}</td>
                          <td>{finding.mem_percent?.toFixed?.(1) ?? finding.mem_percent}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {activeDetail.analysis?.recommendations?.length > 0 && (
              <div className="card" style={{ marginTop: 16 }}>
                <div className="card-title" style={{ marginBottom: 8 }}>
                  Analyst Guidance
                </div>
                <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7 }}>
                  {activeDetail.analysis.recommendations.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            )}

            {activeDetail.network_activity?.length > 0 && (
              <div className="card" style={{ marginTop: 16 }}>
                <div className="card-title" style={{ marginBottom: 8 }}>
                  Network Activity
                </div>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Protocol</th>
                        <th>Endpoint</th>
                        <th>State</th>
                      </tr>
                    </thead>
                    <tbody>
                      {activeDetail.network_activity.map((entry, index) => (
                        <tr key={`${entry.endpoint}-${index}`}>
                          <td>{entry.protocol}</td>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                            {entry.endpoint}
                          </td>
                          <td>{entry.state || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {activeDetail.code_signature && (
              <div className="card" style={{ marginTop: 16 }}>
                <div className="card-title" style={{ marginBottom: 8 }}>
                  Code Signature
                </div>
                <SummaryGrid data={activeDetail.code_signature} limit={6} />
              </div>
            )}

            <JsonDetails data={activeDetail} label="Deep inspection fields" />
          </>
        )}
      </SideDrawer>
      {confirmUI}
    </>
  );
}
