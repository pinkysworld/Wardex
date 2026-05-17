import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as api from '../api.js';

// Stub global fetch
const mockFetch = vi.fn();
globalThis.fetch = mockFetch;

beforeEach(() => {
  mockFetch.mockReset();
  api.setToken('');
  api.setBaseUrl('');
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ── Token management ─────────────────────────────────────────

describe('token management', () => {
  it('setToken/getToken round-trips', () => {
    api.setToken('abc123');
    expect(api.getToken()).toBe('abc123');
  });

  it('setBaseUrl prepends to requests', async () => {
    api.setBaseUrl('http://localhost:9999');
    mockFetch.mockResolvedValueOnce({
      ok: true,
      headers: { get: () => 'application/json' },
      json: async () => ({ status: 'ok' }),
    });

    await api.health();
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(mockFetch.mock.calls[0][0]).toBe('http://localhost:9999/api/health');
  });
});

// ── Request helper ───────────────────────────────────────────

describe('request helper', () => {
  it('sends Bearer token when set', async () => {
    api.setToken('secret-token');
    mockFetch.mockResolvedValueOnce({
      ok: true,
      headers: { get: () => 'application/json' },
      json: async () => ({ status: 'ok' }),
    });

    await api.health();
    const headers = mockFetch.mock.calls[0][1].headers;
    expect(headers['Authorization']).toBe('Bearer secret-token');
  });

  it('omits Authorization header when no token', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      headers: { get: () => 'application/json' },
      json: async () => ({}),
    });

    await api.health();
    const headers = mockFetch.mock.calls[0][1].headers;
    expect(headers['Authorization']).toBeUndefined();
  });

  it('throws on non-ok response with status', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
      headers: { get: () => null },
      text: async () => 'invalid token',
    });

    try {
      await api.health();
      expect.fail('should have thrown');
    } catch (err) {
      expect(err.status).toBe(401);
      expect(err.body).toBe('invalid token');
    }
  });

  it('extracts structured API error messages', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 422,
      statusText: 'Unprocessable Entity',
      headers: { get: () => 'application/json' },
      text: async () => JSON.stringify({ error: { message: 'preflight blocked' } }),
    });

    await expect(api.health()).rejects.toMatchObject({
      status: 422,
      message: 'preflight blocked',
    });
  });

  it('retries retryable GET failures once', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: false,
        status: 503,
        statusText: 'Service Unavailable',
        headers: { get: () => null },
        text: async () => 'busy',
      })
      .mockResolvedValueOnce({
        ok: true,
        headers: { get: () => 'application/json' },
        json: async () => ({ status: 'ok' }),
      });

    await expect(api.health()).resolves.toEqual({ status: 'ok' });
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('captures the X-Request-Id header on thrown errors', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        headers: { get: () => null },
        text: async () => '{"error":"retry me"}',
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        headers: {
          get: (name) => (name.toLowerCase() === 'x-request-id' ? 'req-abc-123' : null),
        },
        text: async () => '{"error":"boom"}',
      });

    try {
      await api.health();
      expect.fail('should have thrown');
    } catch (err) {
      expect(err.status).toBe(500);
      expect(err.requestId).toBe('req-abc-123');
    }
  });

  it('returns text for non-json responses', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      headers: { get: () => 'text/plain' },
      text: async () => 'plain response',
    });

    const result = await api.metrics();
    expect(result).toBe('plain response');
  });
});

// ── GET endpoints ────────────────────────────────────────────

describe('GET endpoints', () => {
  const jsonOk = (data) => ({
    ok: true,
    headers: { get: () => 'application/json' },
    json: async () => data,
  });

  it('health() calls /api/health', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ status: 'ok' }));
    const result = await api.health();
    expect(result).toEqual({ status: 'ok' });
    expect(mockFetch.mock.calls[0][0]).toBe('/api/health');
  });

  it('alerts() calls /api/alerts', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk([]));
    const result = await api.alerts();
    expect(result).toEqual([]);
    expect(mockFetch.mock.calls[0][0]).toBe('/api/alerts');
  });

  it('agents() calls /api/agents', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk([{ agent_id: 'a1' }]));
    const result = await api.agents();
    expect(result).toEqual([{ agent_id: 'a1' }]);
  });

  it('cases() calls /api/cases', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ cases: [], total: 0 }));
    await api.cases();
    expect(mockFetch.mock.calls[0][0]).toBe('/api/cases');
  });

  it('malwareStats() calls /api/malware/stats', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ database: 'active' }));
    const result = await api.malwareStats();
    expect(result.database).toBe('active');
  });

  it('exportAlerts() includes format param', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ format: 'cef', data: '' }));
    await api.exportAlerts('cef');
    expect(mockFetch.mock.calls[0][0]).toBe('/api/export/alerts?format=cef');
  });

  it('complianceReport() with framework param', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ framework: 'nist-csf-2' }));
    await api.complianceReport('nist-csf-2');
    expect(mockFetch.mock.calls[0][0]).toContain('framework=nist-csf-2');
  });

  it('complianceReport() without framework', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({}));
    await api.complianceReport();
    expect(mockFetch.mock.calls[0][0]).toBe('/api/compliance/report');
  });

  it('reportRuns() calls /api/report-runs', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ runs: [] }));
    await api.reportRuns();
    expect(mockFetch.mock.calls[0][0]).toBe('/api/report-runs');
  });

  it('reportRuns() includes scope filter query params', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ runs: [] }));
    await api.reportRuns({
      caseId: '42',
      incidentId: '7',
      investigationId: 'inv-7',
      source: 'case',
      scope: 'scoped',
    });
    expect(mockFetch.mock.calls[0][0]).toBe(
      '/api/report-runs?case_id=42&incident_id=7&investigation_id=inv-7&source=case&scope=scoped',
    );
  });

  it('reportTemplates() includes scope filter query params', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ templates: [] }));
    await api.reportTemplates({
      caseId: '42',
      incidentId: '7',
      investigationId: 'inv-7',
      source: 'case',
      scope: 'scoped',
    });
    expect(mockFetch.mock.calls[0][0]).toBe(
      '/api/report-templates?case_id=42&incident_id=7&investigation_id=inv-7&source=case&scope=scoped',
    );
  });

  it('reportSchedules() includes scope filter query params', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ schedules: [] }));
    await api.reportSchedules({
      caseId: '42',
      incidentId: '7',
      investigationId: 'inv-7',
      source: 'case',
      scope: 'scoped',
    });
    expect(mockFetch.mock.calls[0][0]).toBe(
      '/api/report-schedules?case_id=42&incident_id=7&investigation_id=inv-7&source=case&scope=scoped',
    );
  });

  it('reports() includes scope filter query params', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ reports: [] }));
    await api.reports({
      caseId: '42',
      incidentId: '7',
      investigationId: 'inv-7',
      source: 'case',
      scope: 'scoped',
    });
    expect(mockFetch.mock.calls[0][0]).toBe(
      '/api/reports?case_id=42&incident_id=7&investigation_id=inv-7&source=case&scope=scoped',
    );
  });

  it('inbox() calls /api/inbox', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ items: [] }));
    await api.inbox();
    expect(mockFetch.mock.calls[0][0]).toBe('/api/inbox');
  });

  it('hardening helpers call product hardening routes', async () => {
    mockFetch.mockResolvedValue(jsonOk({ ok: true }));
    await api.streamReadiness();
    await api.streamReliabilityLab();
    await api.operationalSnapshots({ kind: 'stream_readiness', limit: 3 });
    await api.operationalSnapshotPolicy();
    await api.verifyOperationalSnapshot({ digest: 'abc' });
    await api.releaseDoctor();
    await api.releaseObservabilityGates();
    await api.releaseProvenance();
    await api.releaseUpgradeRehearsal({ targetVersion: '1.0.13' });
    await api.cleanReleaseCut();
    await api.containerReleaseParity();
    await api.releaseVerificationCenter();
    await api.selfHostedDeploymentWizard();
    await api.dataQualityDashboard();
    await api.performanceScaleBaseline();
    await api.clusterFailoverExecution();
    await api.secretsRotationOperations();
    await api.operatorTaskAutomation();
    await api.detectionValidationPacks();
    await api.workflowPreflight({ workflow: 'release' });
    await api.tenantIsolationProof();
    await api.threadDetectionProof();
    await api.supportBundle();
    await api.alertHistogram({ window: '24h', bucket: '1h', severity: 'high' });
    await api.alertsPage({ cursor: 10, limit: 5 });
    await api.eventsPage({ cursor: 2, limit: 4, q: 'login', severity: 'high' });
    await api.auditLogPage({ cursor: 6, limit: 3, status: '2xx' });
    await api.resumeSubscription({ subscriptionId: 'sub-1', cursor: 7, limit: 2 });

    expect(mockFetch.mock.calls[0][0]).toBe('/api/stream/readiness');
    expect(mockFetch.mock.calls[1][0]).toBe('/api/stream/reliability-lab');
    expect(mockFetch.mock.calls[2][0]).toBe(
      '/api/operational/snapshots?kind=stream_readiness&limit=3',
    );
    expect(mockFetch.mock.calls[3][0]).toBe('/api/operational/snapshots/policy');
    expect(mockFetch.mock.calls[4][0]).toBe('/api/operational/snapshots/verify?digest=abc');
    expect(mockFetch.mock.calls[5][0]).toBe('/api/release/doctor');
    expect(mockFetch.mock.calls[6][0]).toBe('/api/release/observability-gates');
    expect(mockFetch.mock.calls[7][0]).toBe('/api/release/provenance');
    expect(mockFetch.mock.calls[8][0]).toBe('/api/release/upgrade-rehearsal?target_version=1.0.13');
    expect(mockFetch.mock.calls[9][0]).toBe('/api/release/clean-cut');
    expect(mockFetch.mock.calls[10][0]).toBe('/api/containers/release-parity');
    expect(mockFetch.mock.calls[11][0]).toBe('/api/release/verification-center');
    expect(mockFetch.mock.calls[12][0]).toBe('/api/deployment/self-hosted-wizard');
    expect(mockFetch.mock.calls[13][0]).toBe('/api/data-quality/dashboard');
    expect(mockFetch.mock.calls[14][0]).toBe('/api/performance/scale-baseline');
    expect(mockFetch.mock.calls[15][0]).toBe('/api/cluster/failover-execution');
    expect(mockFetch.mock.calls[16][0]).toBe('/api/secrets/rotation-operations');
    expect(mockFetch.mock.calls[17][0]).toBe('/api/operator/task-automation');
    expect(mockFetch.mock.calls[18][0]).toBe('/api/detection/validation-packs');
    expect(mockFetch.mock.calls[19][0]).toBe('/api/workflows/preflight?workflow=release');
    expect(mockFetch.mock.calls[20][0]).toBe('/api/tenants/isolation-proof');
    expect(mockFetch.mock.calls[21][0]).toBe('/api/processes/thread-proof');
    expect(mockFetch.mock.calls[22][0]).toBe('/api/support/bundle');
    expect(mockFetch.mock.calls[23][0]).toBe(
      '/api/alerts/histogram?window=24h&bucket=1h&severity=high',
    );
    expect(mockFetch.mock.calls[24][0]).toBe('/api/alerts/page?cursor=10&limit=5');
    expect(mockFetch.mock.calls[25][0]).toBe(
      '/api/events/page?cursor=2&limit=4&q=login&severity=high',
    );
    expect(mockFetch.mock.calls[26][0]).toBe('/api/audit/log/page?limit=3&status=2xx&cursor=6');
    expect(mockFetch.mock.calls[27][0]).toBe(
      '/api/subscriptions/resume?subscription_id=sub-1&cursor=7&limit=2',
    );
  });
});

// ── POST endpoints ───────────────────────────────────────────

describe('POST endpoints', () => {
  const jsonOk = (data) => ({
    ok: true,
    headers: { get: () => 'application/json' },
    json: async () => data,
  });

  it('hunt() sends query in body', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ hits: 0 }));
    await api.hunt('process == cmd.exe');
    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.query).toBe('process == cmd.exe');
  });

  it('scanBuffer() posts to /api/scan/buffer', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ verdict: 'clean' }));
    await api.scanBuffer({ data: 'base64data', filename: 'test.exe' });
    expect(mockFetch.mock.calls[0][0]).toBe('/api/scan/buffer');
    expect(mockFetch.mock.calls[0][1].method).toBe('POST');
  });

  it('runPlaybook() posts to /api/playbooks/run', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ execution_id: 'e1' }));
    await api.runPlaybook({ playbook_id: 'isolate-host' });
    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.playbook_id).toBe('isolate-host');
  });

  it('resumePlaybook() posts to /api/playbooks/resume', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ execution_id: 'e1', status: 'succeeded' }));
    await api.resumePlaybook({ execution_id: 'e1', feedback: 'approved' });
    expect(mockFetch.mock.calls[0][0]).toBe('/api/playbooks/resume');
    expect(JSON.parse(mockFetch.mock.calls[0][1].body)).toEqual({
      execution_id: 'e1',
      feedback: 'approved',
    });
  });

  it('playbookRun() routes named playbooks through /api/playbooks/run', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ execution_id: 'e2' }));
    await api.playbookRun('credential-storm-playbook');
    expect(mockFetch.mock.calls[0][0]).toBe('/api/playbooks/run');
    expect(JSON.parse(mockFetch.mock.calls[0][1].body)).toEqual({
      playbook_id: 'credential-storm-playbook',
    });
  });

  it('contentRuleTest() posts to the rule test endpoint', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ status: 'tested' }));
    await api.contentRuleTest('rule-1');
    expect(mockFetch.mock.calls[0][0]).toBe('/api/content/rules/rule-1/test');
  });

  it('contentRulePreflight() posts to the rule preflight endpoint', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ status: 'ready' }));
    await api.contentRulePreflight('rule-1', { target_status: 'canary' });
    expect(mockFetch.mock.calls[0][0]).toBe('/api/content/rules/rule-1/preflight');
    expect(JSON.parse(mockFetch.mock.calls[0][1].body)).toEqual({ target_status: 'canary' });
  });

  it('pruneOperationalSnapshots() defaults to dry-run pruning', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ status: 'preview' }));
    await api.pruneOperationalSnapshots();
    expect(mockFetch.mock.calls[0][0]).toBe('/api/operational/snapshots/prune');
    expect(JSON.parse(mockFetch.mock.calls[0][1].body)).toEqual({ dry_run: true });
  });

  it('createReportRun() posts report run payload', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ status: 'created' }));
    await api.createReportRun({ kind: 'executive_status', scope: 'global' });
    expect(mockFetch.mock.calls[0][0]).toBe('/api/report-runs');
    expect(JSON.parse(mockFetch.mock.calls[0][1].body).kind).toBe('executive_status');
  });

  it('annotateReportContext() posts scope to the report context endpoint', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ status: 'updated' }));
    await api.annotateReportContext(101, { case_id: '42', source: 'case' });
    expect(mockFetch.mock.calls[0][0]).toBe('/api/reports/101/context');
    expect(JSON.parse(mockFetch.mock.calls[0][1].body)).toEqual(
      expect.objectContaining({ case_id: '42', source: 'case' }),
    );
  });

  it('executeRemediationRollback() posts to the review rollback endpoint', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ status: 'rollback_recorded' }));
    await api.executeRemediationRollback('review-1', { dry_run: true, platform: 'linux' });
    expect(mockFetch.mock.calls[0][0]).toBe('/api/remediation/change-reviews/review-1/rollback');
    expect(JSON.parse(mockFetch.mock.calls[0][1].body)).toEqual({
      dry_run: true,
      platform: 'linux',
    });
  });

  it('createSubscription() posts subscription filters', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ subscription: { subscription_id: 'sub-1' } }));
    await api.createSubscription({ lanes: ['alerts'], filters: { severity: 'high' } });
    expect(mockFetch.mock.calls[0][0]).toBe('/api/subscriptions');
    expect(JSON.parse(mockFetch.mock.calls[0][1].body)).toEqual({
      lanes: ['alerts'],
      filters: { severity: 'high' },
    });
  });
});
