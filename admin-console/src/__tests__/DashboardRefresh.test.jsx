import { describe, it, expect, beforeEach, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Dashboard from '../components/Dashboard.jsx';
import { AuthProvider, RoleProvider, ThemeProvider, ToastProvider } from '../hooks.jsx';

function jsonOk(data) {
  return {
    ok: true,
    status: 200,
    headers: { get: (header) => (header === 'content-type' ? 'application/json' : null) },
    json: async () => data,
    text: async () => JSON.stringify(data),
  };
}

function renderWithProviders(node, route = '/') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <AuthProvider>
        <RoleProvider>
          <ThemeProvider>
            <ToastProvider>{node}</ToastProvider>
          </ThemeProvider>
        </RoleProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe('Dashboard refresh', () => {
  beforeEach(() => {
    localStorage.clear();
    localStorage.setItem('wardex_token', 'dashboard-token');
  });

  it('refreshes grouped dashboard signal data from the overview header', async () => {
    const callCounts = {
      status: 0,
      fleetDashboard: 0,
      alerts: 0,
      telemetryCurrent: 0,
      collectorsStatus: 0,
      health: 0,
      detectionSummary: 0,
      threatIntelStatus: 0,
      queueStats: 0,
      responseStats: 0,
      processesAnalysis: 0,
      malwareStats: 0,
      coverageGaps: 0,
      quarantineStats: 0,
      lifecycleStats: 0,
      feedStats: 0,
      managerQueueDigest: 0,
      dnsThreatSummary: 0,
    };

    vi.stubGlobal(
      'fetch',
      vi.fn(async (url, options = {}) => {
        const href = String(url);
        const method = options?.method || 'GET';

        if (href.includes('/api/auth/check')) return jsonOk({ authenticated: true });
        if (href.includes('/api/auth/session')) {
          return jsonOk({
            authenticated: true,
            role: 'analyst',
            user_id: 'analyst-1',
            groups: ['soc-analysts'],
            source: 'session',
          });
        }
        if (href.includes('/api/user/preferences') && method === 'GET') {
          return jsonOk({ dashboard_presets: [], active_dashboard_preset: '', updated_at: null });
        }
        if (href.includes('/api/status')) {
          callCounts.status += 1;
          return jsonOk({ version: '0.53.5', uptime_secs: 3600 });
        }
        if (href.includes('/api/fleet/dashboard')) {
          callCounts.fleetDashboard += 1;
          return jsonOk({ total_agents: 2, fleet: { status_counts: { online: 2 } } });
        }
        if (href.includes('/api/alerts')) {
          callCounts.alerts += 1;
          return jsonOk({ alerts: [] });
        }
        if (href.includes('/api/telemetry/current')) {
          callCounts.telemetryCurrent += 1;
          return jsonOk({ eps: 12, drops: 0 });
        }
        if (href.includes('/api/collectors/status')) {
          callCounts.collectorsStatus += 1;
          return jsonOk({
            collectors: [
              {
                name: 'aws_cloudtrail',
                label: 'AWS CloudTrail',
                lane: 'cloud',
                enabled: true,
                freshness: 'stale',
                lag_seconds: 900,
                retry_count: 2,
                backoff_seconds: 60,
                events_ingested: 120,
                last_success_at: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
                route_targets: ['Infrastructure', 'Attack Graph'],
                lifecycle_analytics: {
                  success_rate: 0.75,
                  events_last_24h: 120,
                  recent_failure_streak: 2,
                },
                timeline: [
                  {
                    stage: 'Configuration',
                    status: 'ready',
                    title: 'Collector enabled',
                    detail: 'AWS CloudTrail is configured with a 300 second polling cadence.',
                  },
                  {
                    stage: 'Validation',
                    status: 'warning',
                    title: 'Validation review',
                    detail: 'Review access scope before the next polling cycle.',
                  },
                ],
                ingestion_evidence: {
                  pivots: [
                    {
                      href: '/soc?collector=aws_cloudtrail&lane=cloud',
                      label: 'Open SOC collector context',
                    },
                    {
                      href: '/infrastructure?tab=observability&collector=aws_cloudtrail',
                      label: 'Open infrastructure evidence',
                    },
                  ],
                },
              },
            ],
          });
        }
        if (href.includes('/api/health')) {
          callCounts.health += 1;
          return jsonOk({ status: 'ok' });
        }
        if (href.includes('/api/detection/profile')) {
          return jsonOk({ profile: 'balanced' });
        }
        if (href.includes('/api/host/info')) {
          return jsonOk({
            hostname: 'dashboard-host.local',
            platform: 'macOS',
            os_version: '14',
            arch: 'arm64',
          });
        }
        if (href.includes('/api/telemetry/history')) {
          return jsonOk({ samples: [] });
        }
        if (href.includes('/api/detection/summary')) {
          callCounts.detectionSummary += 1;
          return jsonOk({ total_rules: 3, active_rules: 2 });
        }
        if (href.includes('/api/threat-intel/status')) {
          callCounts.threatIntelStatus += 1;
          return jsonOk({ ioc_count: 4, active_feeds: 2 });
        }
        if (href.includes('/api/queue/stats')) {
          callCounts.queueStats += 1;
          return jsonOk({ pending: 5, assigned: 2 });
        }
        if (href.includes('/api/response/stats')) {
          callCounts.responseStats += 1;
          return jsonOk({ total: 4, pending: 1 });
        }
        if (href.includes('/api/processes/analysis')) {
          callCounts.processesAnalysis += 1;
          return jsonOk({ process_count: 1, total: 1, status: 'review', findings: [] });
        }
        if (href.includes('/api/malware/stats')) {
          callCounts.malwareStats += 1;
          return jsonOk({
            database: { total_entries: 10 },
            scanner: { total_scans: 2, malicious_count: 1 },
            yara_rules: 5,
          });
        }
        if (href.includes('/api/coverage/gaps')) {
          callCounts.coverageGaps += 1;
          return jsonOk({ total_gaps: 2, critical_gaps: 1, gaps: [] });
        }
        if (href.includes('/api/quarantine/stats')) {
          callCounts.quarantineStats += 1;
          return jsonOk({ total: 1, pending_review: 1 });
        }
        if (href.includes('/api/lifecycle/stats')) {
          callCounts.lifecycleStats += 1;
          return jsonOk({ active: 3, stale: 1, offline: 1, archived: 0, decommissioned: 0 });
        }
        if (href.includes('/api/feeds/stats')) {
          callCounts.feedStats += 1;
          return jsonOk({
            total_sources: 2,
            active_sources: 2,
            total_iocs_ingested: 100,
            total_hashes_imported: 50,
          });
        }
        if (href.includes('/api/manager/queue-digest')) {
          callCounts.managerQueueDigest += 1;
          return jsonOk({
            queue: { pending: 5, sla_breached: 1 },
            stale_cases: 2,
            degraded_collectors: 1,
            pending_dry_run_approvals: 1,
            ready_to_execute: 1,
            changes_since_last_shift: [],
            noisy_reasons: [],
          });
        }
        if (href.includes('/api/dns-threat/summary')) {
          callCounts.dnsThreatSummary += 1;
          return jsonOk({
            domains_analyzed: 20,
            threats_detected: 1,
            dga_suspects: 1,
            tunnel_suspects: 0,
            fast_flux_suspects: 0,
          });
        }

        return jsonOk({});
      }),
    );

    renderWithProviders(<Dashboard />);

    const refreshButton = await screen.findByRole('button', { name: '↻ Refresh' });
    expect(await screen.findByText('Collector Health')).toBeInTheDocument();
    expect(screen.getByText('Readiness timeline')).toBeInTheDocument();
    expect(screen.getByText('Collector enabled')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Open infrastructure evidence' })).toBeInTheDocument();

    await waitFor(() => {
      expect(callCounts.status).toBeGreaterThan(0);
      expect(callCounts.fleetDashboard).toBeGreaterThan(0);
      expect(callCounts.alerts).toBeGreaterThan(0);
      expect(callCounts.telemetryCurrent).toBeGreaterThan(0);
      expect(callCounts.collectorsStatus).toBeGreaterThan(0);
      expect(callCounts.health).toBeGreaterThan(0);
      expect(callCounts.detectionSummary).toBeGreaterThan(0);
      expect(callCounts.threatIntelStatus).toBeGreaterThan(0);
      expect(callCounts.queueStats).toBeGreaterThan(0);
      expect(callCounts.responseStats).toBeGreaterThan(0);
      expect(callCounts.processesAnalysis).toBeGreaterThan(0);
      expect(callCounts.malwareStats).toBeGreaterThan(0);
      expect(callCounts.coverageGaps).toBeGreaterThan(0);
      expect(callCounts.quarantineStats).toBeGreaterThan(0);
      expect(callCounts.lifecycleStats).toBeGreaterThan(0);
      expect(callCounts.feedStats).toBeGreaterThan(0);
      expect(callCounts.managerQueueDigest).toBeGreaterThan(0);
      expect(callCounts.dnsThreatSummary).toBeGreaterThan(0);
    });

    const initialCounts = { ...callCounts };

    fireEvent.click(refreshButton);

    await waitFor(() => {
      expect(callCounts.status).toBe(initialCounts.status + 1);
      expect(callCounts.fleetDashboard).toBe(initialCounts.fleetDashboard + 1);
      expect(callCounts.alerts).toBe(initialCounts.alerts + 1);
      expect(callCounts.telemetryCurrent).toBe(initialCounts.telemetryCurrent + 1);
      expect(callCounts.collectorsStatus).toBe(initialCounts.collectorsStatus + 1);
      expect(callCounts.health).toBe(initialCounts.health + 1);
      expect(callCounts.detectionSummary).toBe(initialCounts.detectionSummary + 1);
      expect(callCounts.threatIntelStatus).toBe(initialCounts.threatIntelStatus + 1);
      expect(callCounts.queueStats).toBe(initialCounts.queueStats + 1);
      expect(callCounts.responseStats).toBe(initialCounts.responseStats + 1);
      expect(callCounts.processesAnalysis).toBe(initialCounts.processesAnalysis + 1);
      expect(callCounts.malwareStats).toBe(initialCounts.malwareStats + 1);
      expect(callCounts.coverageGaps).toBe(initialCounts.coverageGaps + 1);
      expect(callCounts.quarantineStats).toBe(initialCounts.quarantineStats + 1);
      expect(callCounts.lifecycleStats).toBe(initialCounts.lifecycleStats + 1);
      expect(callCounts.feedStats).toBe(initialCounts.feedStats + 1);
      expect(callCounts.managerQueueDigest).toBe(initialCounts.managerQueueDigest + 1);
      expect(callCounts.dnsThreatSummary).toBe(initialCounts.dnsThreatSummary + 1);
    });
  });
});
