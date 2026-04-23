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

  it('contentRuleTest() posts to the rule test endpoint', async () => {
    mockFetch.mockResolvedValueOnce(jsonOk({ status: 'tested' }));
    await api.contentRuleTest('rule-1');
    expect(mockFetch.mock.calls[0][0]).toBe('/api/content/rules/rule-1/test');
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
});
