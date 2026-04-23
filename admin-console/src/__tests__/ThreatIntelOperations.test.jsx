import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ToastProvider } from '../hooks.jsx';
import ThreatIntelOperations from '../components/ThreatIntelOperations.jsx';

globalThis.fetch = vi.fn();

function jsonOk(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    headers: {
      get: (name) => (String(name || '').toLowerCase() === 'content-type' ? 'application/json' : ''),
    },
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

function mapPostedIocType(value) {
  switch (value) {
    case 'ip':
      return 'IpAddress';
    case 'domain':
      return 'Domain';
    case 'hash':
      return 'FileHash';
    case 'process':
      return 'ProcessName';
    case 'network_signature':
      return 'NetworkSignature';
    case 'registry_key':
      return 'RegistryKey';
    case 'certificate':
      return 'Certificate';
    default:
      return 'BehaviorPattern';
  }
}

function buildThreatStats(libraryState) {
  const iocs = Array.isArray(libraryState.iocs) ? libraryState.iocs : [];
  const byType = {};
  const bySeverity = {};
  const bySource = {};
  let totalConfidence = 0;

  iocs.forEach((ioc) => {
    byType[ioc.ioc_type] = (byType[ioc.ioc_type] || 0) + 1;
    bySeverity[ioc.severity] = (bySeverity[ioc.severity] || 0) + 1;
    bySource[ioc.source] = (bySource[ioc.source] || 0) + 1;
    totalConfidence += Number(ioc.confidence) || 0;
  });

  return {
    total_iocs: iocs.length,
    by_type: byType,
    by_severity: bySeverity,
    by_source: bySource,
    avg_confidence: iocs.length > 0 ? totalConfidence / iocs.length : 0,
    active_feeds: libraryState.feeds.filter((feed) => feed.active).length,
    total_feeds: libraryState.feeds.length,
    match_history_size: libraryState.recent_matches.length,
  };
}

function buildLibraryPayload(libraryState) {
  return {
    count: libraryState.iocs.length,
    indicators: libraryState.iocs,
    feeds: libraryState.feeds,
    recent_matches: libraryState.recent_matches,
    recent_sightings: libraryState.recent_sightings,
    stats: buildThreatStats(libraryState),
  };
}

function renderThreatOps() {
  return render(
    <ToastProvider>
      <ThreatIntelOperations />
    </ToastProvider>,
  );
}

describe('ThreatIntelOperations', () => {
  let libraryState;
  let connectorsState;
  let deceptionState;
  let connectorCounter;
  let decoyCounter;

  beforeEach(() => {
    vi.clearAllMocks();
    connectorCounter = 2;
    decoyCounter = 2;
    libraryState = {
      iocs: [
        {
          ioc_type: 'Domain',
          value: 'MALWARE.BAD',
          confidence: 0.94,
          severity: 'high',
          source: 'feed:otx',
          first_seen: '2026-04-18T08:00:00Z',
          last_seen: '2026-04-20T10:00:00Z',
          tags: ['phishing'],
          related_iocs: [],
          metadata: {
            normalized_value: 'malware.bad',
            ttl_days: 90,
            source_weight: 1.2,
            confidence_decay: 0.98,
            last_sighting: '2026-04-20T10:03:00Z',
            sightings: 3,
          },
          sightings: [
            {
              timestamp: '2026-04-20T10:03:00Z',
              source: 'match',
              context: 'matched Domain indicator: malware.bad',
              weight: 1.2,
            },
          ],
        },
        {
          ioc_type: 'IpAddress',
          value: '198.51.100.22',
          confidence: 0.61,
          severity: 'medium',
          source: 'api',
          first_seen: '2025-01-01T00:00:00Z',
          last_seen: '2025-01-01T00:00:00Z',
          tags: [],
          related_iocs: [],
          metadata: {
            normalized_value: '198.51.100.22',
            ttl_days: 30,
            source_weight: 0.8,
            confidence_decay: 0.96,
            last_sighting: null,
            sightings: 0,
          },
          sightings: [],
        },
      ],
      feeds: [
        {
          feed_id: 'feed-1',
          name: 'OTX Daily',
          url: 'https://otx.example.test/export',
          format: 'jsonl',
          last_updated: '2026-04-20T09:00:00Z',
          ioc_count: 120,
          active: true,
        },
      ],
      recent_matches: [
        {
          matched: true,
          match_type: 'exact',
          context: 'matched Domain indicator: malware.bad',
          ioc: {
            ioc_type: 'Domain',
            value: 'malware.bad',
          },
        },
      ],
      recent_sightings: [
        {
          ioc_type: 'Domain',
          value: 'malware.bad',
          severity: 'high',
          confidence: 0.94,
          timestamp: '2026-04-20T10:03:00Z',
          source: 'match',
          context: 'matched Domain indicator: malware.bad',
          weight: 1.2,
        },
        {
          ioc_type: 'IpAddress',
          value: '198.51.100.22',
          severity: 'medium',
          confidence: 0.61,
          timestamp: '2026-04-19T09:00:00Z',
          source: 'scan:deep',
          context: 'seen during malware deep scan correlation',
          weight: 0.8,
        },
      ],
    };
    connectorsState = [
      {
        id: 'conn-1',
        kind: 'virustotal',
        display_name: 'VirusTotal Primary',
        endpoint: 'https://www.virustotal.example/api',
        auth_mode: 'api_key',
        enabled: true,
        status: 'ready',
        timeout_secs: 10,
        last_sync_at: '2026-04-20T10:00:00Z',
        last_error: null,
        metadata: { tenant: 'secops' },
      },
    ];
    deceptionState = {
      total_decoys: 1,
      active_decoys: 1,
      total_interactions: 4,
      high_threat_interactions: 2,
      attacker_profiles: [
        {
          source_id: '198.51.100.77',
          interaction_count: 2,
          decoys_touched: ['edge-honeypot-01'],
          first_seen: '2026-04-20T10:00:00Z',
          last_seen: '2026-04-20T11:00:00Z',
          threat_score: 8.5,
        },
      ],
      decoys: [
        {
          id: 'decoy-1',
          decoy_type: 'honeypot',
          name: 'edge-honeypot-01',
          description: 'SSH decoy in the edge segment.',
          deployed: true,
          interaction_count: 4,
          avg_threat_score: 7.8,
          fingerprint: 'fp-001',
          last_interaction: {
            timestamp: '2026-04-20T11:00:00Z',
            source_info: '198.51.100.77',
            action: 'login_attempt',
            detail: 'credential guessing',
            threat_score: 8.5,
          },
        },
      ],
    };

    globalThis.fetch.mockImplementation(async (url, options = {}) => {
      const method = options.method || 'GET';
      const parsed = new URL(String(url), 'http://localhost');
      const path = parsed.pathname;

      if (path === '/api/threat-intel/library/v2' && method === 'GET') {
        return jsonOk(buildLibraryPayload(libraryState));
      }
      if (path === '/api/threat-intel/sightings' && method === 'GET') {
        return jsonOk({
          count: libraryState.recent_sightings.length,
          items: libraryState.recent_sightings,
        });
      }
      if (path === '/api/enrichments/connectors' && method === 'GET') {
        return jsonOk({ connectors: connectorsState, count: connectorsState.length });
      }
      if (path === '/api/deception/status' && method === 'GET') {
        return jsonOk(deceptionState);
      }
      if (path === '/api/threat-intel/ioc' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        libraryState = {
          ...libraryState,
          iocs: [
            {
              ioc_type: mapPostedIocType(body.ioc_type),
              value: body.value,
              confidence: body.confidence,
              severity: 'medium',
              source: 'api',
              first_seen: '2026-04-21T12:00:00Z',
              last_seen: '2026-04-21T12:00:00Z',
              tags: [],
              related_iocs: [],
              metadata: {
                normalized_value: body.value.toLowerCase(),
                ttl_days: 90,
                source_weight: 1.0,
                confidence_decay: 0.98,
                last_sighting: null,
                sightings: 0,
              },
              sightings: [],
            },
            ...libraryState.iocs,
          ],
        };
        return jsonOk({ status: 'added', value: body.value });
      }
      if (path === '/api/threat-intel/purge' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        libraryState = {
          ...libraryState,
          iocs: libraryState.iocs.filter((ioc) =>
            body.ttl_days >= 365 ? true : ioc.last_seen >= '2026-01-01T00:00:00Z',
          ),
        };
        return jsonOk({ purged: 1, ttl_days: body.ttl_days });
      }
      if (path === '/api/enrichments/connectors' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        const connector = {
          id: body.id || `conn-${connectorCounter++}`,
          kind: body.kind,
          display_name: body.display_name,
          endpoint: body.endpoint || null,
          auth_mode: body.auth_mode || null,
          enabled: body.enabled !== false,
          status: body.enabled === false ? 'disabled' : 'ready',
          timeout_secs: body.timeout_secs,
          last_sync_at: null,
          last_error: null,
          metadata: body.metadata || {},
        };
        connectorsState = connectorsState.some((entry) => entry.id === connector.id)
          ? connectorsState.map((entry) => (entry.id === connector.id ? connector : entry))
          : [...connectorsState, connector];
        return jsonOk({ status: 'saved', connector });
      }
      if (path === '/api/deception/deploy' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        const decoy = {
          id: `decoy-${decoyCounter++}`,
          decoy_type: body.decoy_type,
          name: body.name,
          description: body.description || '',
          deployed: true,
          interaction_count: 0,
          avg_threat_score: 0,
          fingerprint: 'fp-new',
          last_interaction: null,
        };
        deceptionState = {
          ...deceptionState,
          total_decoys: deceptionState.total_decoys + 1,
          active_decoys: deceptionState.active_decoys + 1,
          decoys: [...deceptionState.decoys, decoy],
        };
        return jsonOk({ status: 'deployed', decoy_id: decoy.id });
      }

      return jsonOk({});
    });
  });

  it('adds indicators and updates the visible library', async () => {
    const user = userEvent.setup();
    renderThreatOps();

    expect(await screen.findByText('Threat Ops Workspace')).toBeInTheDocument();
    await user.type(screen.getByLabelText('Indicator value'), 'evil.example');
    await user.click(screen.getByRole('button', { name: 'Add Indicator' }));

    await waitFor(() => {
      const call = globalThis.fetch.mock.calls.find(
        ([url, options]) => String(url) === '/api/threat-intel/ioc' && options?.method === 'POST',
      );
      expect(call).toBeTruthy();
      expect(JSON.parse(call[1].body)).toEqual({
        value: 'evil.example',
        ioc_type: 'domain',
        confidence: 0.8,
      });
    });

    expect((await screen.findAllByText('evil.example')).length).toBeGreaterThan(0);
  });

  it('renders normalized provenance and recent sightings from the v2 intel payload', async () => {
    renderThreatOps();

    expect(await screen.findByText('Indicator Library')).toBeInTheDocument();
    expect(await screen.findByText('Normalized malware.bad')).toBeInTheDocument();
    expect(await screen.findByText('TTL 90d · Weight 1.2')).toBeInTheDocument();
    expect((await screen.findAllByText('Recent sightings')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('matched Domain indicator: malware.bad')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('seen during malware deep scan correlation')).length).toBeGreaterThan(0);
  });

  it('purges expired indicators using the selected ttl', async () => {
    const user = userEvent.setup();
    renderThreatOps();

    expect(await screen.findByText('Indicator Library')).toBeInTheDocument();
    expect(within(await screen.findByRole('table')).getByText('198.51.100.22')).toBeInTheDocument();

    await user.clear(screen.getByLabelText('Purge TTL days'));
    await user.type(screen.getByLabelText('Purge TTL days'), '30');
    await user.click(screen.getByRole('button', { name: 'Purge Expired' }));

    await waitFor(() => {
      const call = globalThis.fetch.mock.calls.find(
        ([url, options]) => String(url) === '/api/threat-intel/purge' && options?.method === 'POST',
      );
      expect(call).toBeTruthy();
      expect(JSON.parse(call[1].body)).toEqual({ ttl_days: 30 });
    });

    await waitFor(() => {
      expect(within(screen.getByRole('table')).queryByText('198.51.100.22')).not.toBeInTheDocument();
    });
  });

  it('creates enrichment connectors through the structured editor', async () => {
    const user = userEvent.setup();
    renderThreatOps();

    await user.click(screen.getByRole('button', { name: 'Connectors' }));
    expect(await screen.findByText('Enrichment Connectors')).toBeInTheDocument();

    await user.type(screen.getByLabelText('Connector display name'), 'MISP Primary');
    await user.selectOptions(screen.getByLabelText('Connector kind'), 'misp');
    await user.type(screen.getByLabelText('Endpoint'), 'https://misp.example.test');
    await user.selectOptions(screen.getByLabelText('Auth mode'), 'bearer');
    await user.clear(screen.getByLabelText('Timeout seconds'));
    await user.type(screen.getByLabelText('Timeout seconds'), '25');
    await user.type(screen.getByLabelText('Metadata'), 'tenant=secops');
    await user.click(screen.getByRole('button', { name: 'Save Connector' }));

    await waitFor(() => {
      const call = globalThis.fetch.mock.calls.find(
        ([url, options]) =>
          String(url) === '/api/enrichments/connectors' && options?.method === 'POST',
      );
      expect(call).toBeTruthy();
      expect(JSON.parse(call[1].body)).toEqual({
        kind: 'misp',
        display_name: 'MISP Primary',
        endpoint: 'https://misp.example.test',
        auth_mode: 'bearer',
        enabled: true,
        timeout_secs: 25,
        metadata: { tenant: 'secops' },
      });
    });

    expect((await screen.findAllByText('MISP Primary')).length).toBeGreaterThan(0);
  });

  it('deploys decoys from the threat ops workspace', async () => {
    const user = userEvent.setup();
    renderThreatOps();

    await user.click(screen.getByRole('button', { name: 'Deception' }));
    expect(await screen.findByText('Deception Coverage')).toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText('Decoy type'), 'honeyfile');
    await user.type(screen.getByLabelText('Decoy name'), 'finance-honeyfile-02');
    await user.type(screen.getByLabelText('Description'), 'Payroll share decoy');
    await user.click(screen.getByRole('button', { name: 'Deploy Decoy' }));

    await waitFor(() => {
      const call = globalThis.fetch.mock.calls.find(
        ([url, options]) => String(url) === '/api/deception/deploy' && options?.method === 'POST',
      );
      expect(call).toBeTruthy();
      expect(JSON.parse(call[1].body)).toEqual({
        decoy_type: 'honeyfile',
        name: 'finance-honeyfile-02',
        description: 'Payroll share decoy',
      });
    });

    expect((await screen.findAllByText('finance-honeyfile-02')).length).toBeGreaterThan(0);
  });
});
