import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import SecurityPolicy from '../components/SecurityPolicy.jsx';
import { ToastProvider } from '../hooks.jsx';

const jsonOk = (data) => ({
  ok: true,
  status: 200,
  headers: { get: (header) => (header === 'content-type' ? 'application/json' : null) },
  json: async () => data,
  text: async () => JSON.stringify(data),
});

const fetchMock = vi.fn();

vi.stubGlobal('fetch', fetchMock);

function renderSecurityPolicy() {
  return render(
    <ToastProvider>
      <SecurityPolicy />
    </ToastProvider>,
  );
}

describe('SecurityPolicy', () => {
  let deceptionState;
  let enforcementState;
  let quantumState;

  beforeEach(() => {
    deceptionState = {
      total_decoys: 1,
      active_decoys: 1,
      total_interactions: 3,
      high_threat_interactions: 1,
      attacker_profiles: [
        {
          source_id: '10.0.0.5',
          interaction_count: 3,
          decoys_touched: ['ssh-canary-01'],
          threat_score: 8.7,
        },
      ],
      decoys: [
        {
          id: 'decoy-1',
          decoy_type: 'Honeypot',
          name: 'ssh-canary-01',
          description: 'SSH decoy',
          deployed: true,
          interaction_count: 3,
          avg_threat_score: 7.5,
          last_interaction: { timestamp: '2026-04-21T09:00:00Z' },
        },
      ],
    };
    enforcementState = {
      process_enforcer: 'active',
      network_enforcer: 'active',
      filesystem_enforcer: 'active',
      tpm: { state: 'ready', pcrs: 8 },
      topology_nodes: 4,
      history_len: 1,
      recent_history: [
        {
          action: 'observe(test-device)',
          success: true,
          detail: 'monitoring test-device, no enforcement action',
          rollback_command: null,
        },
      ],
    };
    quantumState = { current_epoch: 4, total_epochs: 12 };

    fetchMock.mockReset();
    fetchMock.mockImplementation(async (url, options = {}) => {
      const parsed = new URL(String(url), 'http://localhost');
      const path = parsed.pathname;
      const method = options.method || 'GET';

      if (path === '/api/compliance/status' && method === 'GET') {
        return jsonOk({ score: 92, framework: 'IEC62443' });
      }
      if (path === '/api/attestation/status' && method === 'GET') {
        return jsonOk({ status: 'ready', attestations: 4 });
      }
      if (path === '/api/privacy/budget' && method === 'GET') {
        return jsonOk({ budget_remaining: 0.82, is_exhausted: false });
      }
      if (path === '/api/quantum/key-status' && method === 'GET') {
        return jsonOk(quantumState);
      }
      if (path === '/api/quantum/rotate' && method === 'POST') {
        quantumState = { current_epoch: quantumState.current_epoch + 1, total_epochs: 12 };
        return jsonOk({ status: 'rotated', new_epoch: quantumState.current_epoch });
      }
      if (path === '/api/policy/current' && method === 'GET') {
        return jsonOk({ mode: 'balanced', default_action: 'Observe' });
      }
      if (path === '/api/policy/compose' && method === 'POST') {
        return jsonOk({
          result: { level: 'High', action: 'Quarantine' },
          conflict: null,
        });
      }
      if (path === '/api/digital-twin/status' && method === 'GET') {
        return jsonOk({
          twin_count: 1,
          devices: [
            {
              device_id: 'lab-edge-01',
              state: 'Normal',
              cpu_load: 21,
              threat_score: 0,
              processes: 33,
            },
          ],
        });
      }
      if (path === '/api/digital-twin/simulate' && method === 'POST') {
        return jsonOk({
          device_id: 'lab-edge-01',
          event_type: 'cpu_spike',
          seeded_device: false,
          ticks_simulated: 1,
          alerts: 1,
          transitions: 1,
          twin_count: 1,
          final_state: {
            device_id: 'lab-edge-01',
            state: 'Degraded',
            cpu_load: 95,
            processes: 33,
            threat_score: 0,
          },
          alerts_generated: [
            {
              alert_type: 'cpu_critical',
              message: 'CPU at 95.0%',
              severity: 9.5,
            },
          ],
          state_transitions: [
            {
              device_id: 'lab-edge-01',
              from: 'Normal',
              to: 'Degraded',
              reason: 'CPU overload',
            },
          ],
        });
      }
      if (path === '/api/harness/run' && method === 'POST') {
        return jsonOk({
          config: { traces_per_strategy: 10, trace_length: 60, evasion_threshold: 1.5 },
          evasion_rate: 0.3,
          coverage_ratio: 0.7,
          transition_count: 11,
          total_count: 30,
          evasion_count: 9,
          score_buckets: [1, 0, 2, 3, 4, 5, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
          strategies: [
            { strategy: 'SlowDrip', total: 10, evaded: 2, detected: 8, avg_max_score: 1.9 },
            { strategy: 'BurstMask', total: 10, evaded: 4, detected: 6, avg_max_score: 1.4 },
            { strategy: 'DriftInject', total: 10, evaded: 3, detected: 7, avg_max_score: 1.7 },
          ],
        });
      }
      if (path === '/api/deception/status' && method === 'GET') {
        return jsonOk(deceptionState);
      }
      if (path === '/api/deception/deploy' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        deceptionState = {
          ...deceptionState,
          total_decoys: deceptionState.total_decoys + 1,
          active_decoys: deceptionState.active_decoys + 1,
          decoys: [
            ...deceptionState.decoys,
            {
              id: 'decoy-2',
              decoy_type: body.decoy_type,
              name: body.name,
              description: body.description || '',
              deployed: true,
              interaction_count: 0,
              avg_threat_score: 0,
              last_interaction: null,
            },
          ],
        };
        return jsonOk({ status: 'deployed', decoy_id: 'decoy-2' });
      }
      if (path === '/api/enforcement/status' && method === 'GET') {
        return jsonOk(enforcementState);
      }
      if (path === '/api/enforcement/quarantine' && method === 'POST') {
        const body = JSON.parse(options.body || '{}');
        enforcementState = {
          ...enforcementState,
          history_len: enforcementState.history_len + 2,
          recent_history: [
            {
              action: 'rate_limit',
              success: true,
              detail: `throttled ${body.target}`,
              rollback_command: 'restore-rate-limit',
            },
            {
              action: 'quarantine_path',
              success: true,
              detail: `isolated ${body.target}`,
              rollback_command: null,
            },
            ...enforcementState.recent_history,
          ].slice(0, 8),
        };
        return jsonOk({
          target: body.target,
          actions: 2,
          results: [
            { action: 'rate_limit', success: true, detail: `throttled ${body.target}` },
            { action: 'quarantine_path', success: true, detail: `isolated ${body.target}` },
          ],
        });
      }

      return jsonOk({});
    });
  });

  it('submits a structured policy composition payload', async () => {
    const user = userEvent.setup();
    renderSecurityPolicy();

    await user.click(screen.getByRole('button', { name: 'Policy' }));
    await user.click(screen.getByRole('button', { name: 'Compose and Preview' }));

    await waitFor(() => expect(screen.getByText('Resolved Level')).toBeInTheDocument());

    const composeCall = fetchMock.mock.calls.find(([url]) =>
      String(url).endsWith('/api/policy/compose'),
    );
    expect(composeCall).toBeTruthy();
    expect(JSON.parse(composeCall[1].body)).toEqual({
      operator: 'max',
      score_a: 0.8,
      battery_a: 42,
      score_b: 0.35,
      battery_b: 88,
    });
  });

  it('runs a digital twin simulation with the server payload shape', async () => {
    const user = userEvent.setup();
    renderSecurityPolicy();

    await user.click(screen.getByRole('button', { name: 'Digital twin' }));
    await user.click(screen.getByRole('button', { name: 'Run Simulation' }));

    await waitFor(() => expect(screen.getByText('Final Twin State')).toBeInTheDocument());

    const simulateCall = fetchMock.mock.calls.find(([url]) =>
      String(url).endsWith('/api/digital-twin/simulate'),
    );
    expect(simulateCall).toBeTruthy();
    expect(JSON.parse(simulateCall[1].body)).toEqual({
      device_id: 'lab-edge-01',
      event_type: 'cpu_spike',
    });
  });

  it('runs the harness with configurable inputs and renders strategy results', async () => {
    const user = userEvent.setup();
    renderSecurityPolicy();

    await user.click(screen.getByRole('button', { name: 'Harness' }));
    const traceLength = screen.getByLabelText('Harness trace length');
    await user.clear(traceLength);
    await user.type(traceLength, '60');
    await user.click(screen.getByRole('button', { name: 'Run Harness' }));

    await waitFor(() => expect(screen.getByText('Strategy Breakdown')).toBeInTheDocument());
    expect(screen.getAllByText('SlowDrip').length).toBeGreaterThan(0);

    const harnessCall = fetchMock.mock.calls.find(([url]) =>
      String(url).endsWith('/api/harness/run'),
    );
    expect(harnessCall).toBeTruthy();
    expect(JSON.parse(harnessCall[1].body)).toEqual({
      traces_per_strategy: 10,
      trace_length: 60,
      evasion_threshold: 1.5,
    });
  });

  it('deploys decoys through the structured deception form', async () => {
    const user = userEvent.setup();
    renderSecurityPolicy();

    await user.click(screen.getByRole('button', { name: 'Deception' }));
    const decoyName = screen.getByLabelText('Decoy name');
    await user.clear(decoyName);
    await user.type(decoyName, 'finance-canary-02');
    await user.click(screen.getByRole('button', { name: 'Deploy Decoy' }));

    await waitFor(() => expect(screen.getByText('Last Deploy Status')).toBeInTheDocument());

    const deployCall = fetchMock.mock.calls.find(([url]) =>
      String(url).endsWith('/api/deception/deploy'),
    );
    expect(deployCall).toBeTruthy();
    expect(JSON.parse(deployCall[1].body)).toEqual({
      decoy_type: 'honeypot',
      name: 'finance-canary-02',
      description: 'SSH decoy on the engineering subnet.',
    });
  });

  it('renders structured attacker profiles and recent decoy interactions', async () => {
    const user = userEvent.setup();
    renderSecurityPolicy();

    await user.click(screen.getByRole('button', { name: 'Deception' }));

    expect((await screen.findAllByText('Attacker Profiles')).length).toBeGreaterThan(0);
    expect(await screen.findByText('Recent Decoy Interactions')).toBeInTheDocument();
    expect(screen.getAllByText('10.0.0.5').length).toBeGreaterThan(0);
    expect(screen.getAllByText('ssh-canary-01').length).toBeGreaterThan(0);
    expect(screen.getByText('8.7')).toBeInTheDocument();
  });

  it('quarantines a target through the enforcement workflow', async () => {
    const user = userEvent.setup();
    renderSecurityPolicy();

    await user.click(screen.getByRole('button', { name: 'Enforcement' }));
    const target = screen.getByLabelText('Enforcement target');
    await user.clear(target);
    await user.type(target, 'malware-host-07');
    await user.click(screen.getByRole('button', { name: 'Quarantine Target' }));

    await waitFor(() => expect(screen.getByText('Last Quarantine Result')).toBeInTheDocument());
    expect(screen.getAllByText('throttled malware-host-07').length).toBeGreaterThan(0);

    const quarantineCall = fetchMock.mock.calls.find(([url]) =>
      String(url).endsWith('/api/enforcement/quarantine'),
    );
    expect(quarantineCall).toBeTruthy();
    expect(JSON.parse(quarantineCall[1].body)).toEqual({ target: 'malware-host-07' });
  });
});
