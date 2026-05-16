export function statusBadge(ok, pending = false) {
  if (pending) return { className: 'badge-warn', label: 'Needs review' };
  return ok
    ? { className: 'badge-ok', label: 'Ready' }
    : { className: 'badge-warn', label: 'Pending' };
}

export function signalBadge(status) {
  const normalized = String(status || 'unknown').toLowerCase();
  if (['ready', 'pass', 'trusted', 'healthy', 'clear'].includes(normalized)) {
    return { className: 'badge-ok', label: normalized };
  }
  if (['blocked', 'fail', 'risk', 'attention'].includes(normalized)) {
    return { className: 'badge-err', label: normalized };
  }
  return { className: 'badge-warn', label: normalized };
}

export function isReadyStatus(status) {
  return ['ready', 'pass', 'passed', 'trusted', 'healthy', 'clear', 'ok', 'current'].includes(
    String(status || '').toLowerCase(),
  );
}

export function isBlockingStatus(status) {
  return ['blocked', 'fail', 'failed', 'risk', 'attention', 'stale', 'error', 'degraded'].includes(
    String(status || '').toLowerCase(),
  );
}

export function evidenceFreshness(value) {
  return value?.evidence_freshness || value?.evidenceFreshness || null;
}

export function evidenceNeedsAttention(value) {
  const evidence = evidenceFreshness(value);
  if (!evidence?.critical) return false;
  return String(evidence.status || 'unknown').toLowerCase() !== 'fresh';
}

export function evidenceBadge(value) {
  const evidence = evidenceFreshness(value);
  const status = String(evidence?.status || 'unknown').toLowerCase();
  if (status === 'fresh') return { className: 'badge-ok', label: 'fresh proof' };
  if (['stale', 'unknown'].includes(status) && evidence?.critical) {
    return { className: 'badge-err', label: `${status} proof` };
  }
  return { className: 'badge-warn', label: `${status} proof` };
}

export function evidenceMode(value) {
  const evidence = evidenceFreshness(value);
  return String(evidence?.mode || 'pending').replaceAll('_', ' ');
}

export function freshnessDetail(detail, value) {
  const evidence = evidenceFreshness(value);
  if (!evidence) return `${detail} - evidence pending`;
  const mode = String(evidence.mode || 'evidence').replaceAll('_', ' ');
  return `${detail} - ${evidence.status || 'unknown'} ${mode}`;
}

export function freshnessStatusBadge(status) {
  const normalized = String(status || 'unknown').toLowerCase();
  if (['fresh', 'available', 'ready', 'current'].includes(normalized)) {
    return { className: 'badge-ok', label: normalized.replaceAll('_', ' ') };
  }
  if (['stale', 'missing', 'failed', 'error'].includes(normalized)) {
    return { className: 'badge-err', label: normalized.replaceAll('_', ' ') };
  }
  return { className: 'badge-warn', label: normalized.replaceAll('_', ' ') };
}
