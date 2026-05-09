import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider } from '../hooks.jsx';
import OperatorLaunchpad from '../components/OperatorLaunchpad.jsx';

const fetchMock = vi.fn();
vi.stubGlobal('fetch', fetchMock);

function jsonOk(data) {
  return {
    ok: true,
    status: 200,
    headers: { get: () => 'application/json' },
    json: async () => data,
    text: async () => JSON.stringify(data),
  };
}

function renderLaunchpad() {
  return render(
    <MemoryRouter>
      <ToastProvider>
        <OperatorLaunchpad />
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe('OperatorLaunchpad', () => {
  beforeEach(() => {
    fetchMock.mockReset();
    fetchMock.mockImplementation(async (url, options = {}) => {
      const path = new URL(String(url), 'http://localhost').pathname;
      if (path === '/api/health') return jsonOk({ status: 'ok', version: '1.0.8' });
      if (path === '/api/status') return jsonOk({ version: '1.0.8', mode: 'local' });
      if (path === '/api/onboarding/readiness') {
        return jsonOk({
          checks: [
            { key: 'first_agent_online', label: 'Collector connected', ready: true },
            { key: 'telemetry_flowing', label: 'Telemetry flowing', ready: true },
            { key: 'first_alert_visible', label: 'First alert visible', ready: false },
          ],
        });
      }
      if (path === '/api/support/readiness-evidence') return jsonOk({ evidence: [] });
      if (path === '/api/support/bundle') {
        return jsonOk({
          status: 'redacted',
          digest: 'support-digest',
          redaction: { redacted_count: 2 },
        });
      }
      if (path === '/api/system/health/dependencies') {
        return jsonOk({ dependencies: [{ name: 'storage', status: 'ok' }] });
      }
      if (path === '/api/auth/sso/config') {
        return jsonOk({ providers: [{ id: 'idp-1', display_name: 'Corporate SSO' }] });
      }
      if (path === '/api/siem/status') return jsonOk({ enabled: true, pending: 0 });
      if (path === '/api/collectors/status') {
        return jsonOk({ collectors: [{ enabled: true, freshness: 'fresh', label: 'Syslog' }] });
      }
      if (path === '/api/updates/releases') {
        return jsonOk([{ version: '1.0.8', latest: true, published_at: '2026-05-09T12:00:00Z' }]);
      }
      if (path === '/api/launchpad/release-diff') {
        return jsonOk({
          status: 'current',
          current_version: '1.0.8',
          latest_version: '1.0.8',
          changed_rules: [{ rule_id: 'rule-1', title: 'Suspicious PowerShell' }],
          operator_summary: 'Runtime and release catalog are aligned.',
        });
      }
      if (path === '/api/release/doctor') {
        return jsonOk({
          status: 'ready',
          checks: [{ id: 'contract_parity', status: 'pass', detail: '0 endpoint drift items.' }],
          warn_count: 0,
          fail_count: 0,
          next_action: 'Release acceptance signals are ready.',
        });
      }
      if (path === '/api/release/clean-cut') {
        return jsonOk({ status: 'ready', target_version: '1.0.8', fail_count: 0, warn_count: 0 });
      }
      if (path === '/api/containers/release-parity') {
        return jsonOk({ status: 'ready', fail_count: 0, warn_count: 0 });
      }
      if (path === '/api/release/verification-center') {
        return jsonOk({
          status: 'ready',
          fail_count: 0,
          warn_count: 0,
          verification_rows: [{ artifact: 'wardex-macos-aarch64.tar.gz', status: 'ready' }],
        });
      }
      if (path === '/api/deployment/self-hosted-wizard') {
        return jsonOk({
          status: 'ready',
          preflight: { storage_ready: true },
          install_plans: [{ id: 'docker', title: 'Docker single-node' }],
        });
      }
      if (path === '/api/data-quality/dashboard') {
        return jsonOk({
          status: 'ready',
          metrics: { dead_letter_events: 0 },
          slo_summary: { score: 100, passing: 4, total: 4 },
        });
      }
      if (path === '/api/performance/scale-baseline') {
        return jsonOk({
          status: 'ready',
          metrics: { request_rate_per_min: 12 },
          load_gate: [{ id: 'launchpad_fanout', status: 'pass' }],
        });
      }
      if (path === '/api/cluster/failover-execution') {
        return jsonOk({ status: 'ready', mode: 'cluster_ready' });
      }
      if (path === '/api/secrets/rotation-operations') {
        return jsonOk({ status: 'ready', fail_count: 0, warn_count: 0 });
      }
      if (path === '/api/operator/task-automation') {
        return jsonOk({
          status: 'ready',
          automation_count: 2,
          action_blueprints: [{ action: 'assign_owner' }, { action: 'create_ticket' }],
        });
      }
      if (path === '/api/detection/validation-packs') {
        return jsonOk({ status: 'ready', pack_count: 5, executable_pack_count: 5 });
      }
      if (path === '/api/operational/snapshots') {
        return jsonOk({
          count: 1,
          verified_count: 1,
          snapshots: [
            {
              kind: 'release_doctor',
              digest: 'snapshot-digest-1',
              storage_key: 'operational_snapshots/release_doctor/1.json',
              verified: true,
            },
          ],
        });
      }
      if (path === '/api/launchpad/demo-status') {
        return jsonOk({
          status: 'available',
          sample_alerts: 0,
          scenarios: ['credential_storm', 'benign_baseline'],
        });
      }
      if (path === '/api/launchpad/evidence-pack') {
        return jsonOk({ evidence: { current_version: '1.0.8' }, digest: 'digest-1' });
      }
      if (path === '/api/launchpad/demo-reset' && options.method === 'POST') {
        return jsonOk({ status: 'reset_recorded', removed_transient_alerts: 0 });
      }
      if (path === '/api/response/stats') return jsonOk({ pending_approval: 1, executed: 4 });
      if (path === '/api/response/approval-overview') {
        return jsonOk({ pending_response_approvals: 1, pending_playbook_approvals: 1 });
      }
      if (path === '/api/remediation/safety') return jsonOk({ status: 'dry_run_only' });
      if (path === '/api/sdk/contract-status') return jsonOk({ status: 'tracked', drift_count: 0 });
      if (path === '/api/stream/readiness') {
        return jsonOk({ status: 'ready', score: 96, promotion_guard: 'clear' });
      }
      if (path === '/api/alerts/histogram') return jsonOk({ total: 3, buckets: [] });
      if (path === '/api/audit/verify') return jsonOk({ ok: true });
      if (path === '/api/privacy/budget') return jsonOk({ remaining: 99 });
      if (path === '/api/attestation/status') return jsonOk({ status: 'verified' });
      if (path === '/api/alerts/count') return jsonOk({ count: 3 });
      if (path === '/api/fleet/health') return jsonOk({ online: 1 });
      if (path === '/api/detection/summary') return jsonOk({ active_rules: 40 });
      if (path === '/api/detection/replay-corpus') return jsonOk({ status: 'ready' });
      if (path === '/api/fp-feedback/stats') return jsonOk({ false_positive_rate: 0.18 });
      if (path === '/api/processes/analysis') {
        return jsonOk({ findings: [{ kind: 'thread_anomaly', reason: 'hot thread' }] });
      }
      if (path === '/api/threads/status') return jsonOk({ status: 'active' });
      if (path === '/api/demo/lab' && options.method === 'POST') return jsonOk({ ok: true });
      return jsonOk({});
    });
  });

  it('surfaces readiness, release trust, integrations, evidence, and demo actions', async () => {
    renderLaunchpad();

    expect(await screen.findByText('Operator Launchpad')).toBeInTheDocument();
    expect(screen.getByText('Run the first incident with confidence')).toBeInTheDocument();
    expect(screen.getAllByText('2/5').length).toBeGreaterThan(0);
    expect(screen.getAllByText('1.0.8').length).toBeGreaterThan(0);
    expect(screen.getByText('External systems')).toBeInTheDocument();
    expect(screen.getByText('Promotion confidence')).toBeInTheDocument();
    expect(screen.getByText('Acceptance readiness')).toBeInTheDocument();
    expect(screen.getByText('Release verification')).toBeInTheDocument();
    expect(screen.getByText('Clean release and deployment')).toBeInTheDocument();
    expect(screen.getByText('Container parity')).toBeInTheDocument();
    expect(screen.getAllByText('Validation packs').length).toBeGreaterThan(0);
    expect(screen.getByText('Artifact rows')).toBeInTheDocument();
    expect(screen.getByText('Install plans')).toBeInTheDocument();
    expect(screen.getByText('Quality score')).toBeInTheDocument();
    expect(screen.getByText('Dry-run actions')).toBeInTheDocument();
    expect(screen.getByText('Promotion guard')).toBeInTheDocument();
    expect(screen.getByText('Process evidence')).toBeInTheDocument();
    expect(screen.getByText('Approvals and dry-runs')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Evidence Pack' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Support Bundle' })).toBeEnabled();
    expect(screen.getByText('Runtime and release catalog are aligned.')).toBeInTheDocument();
    expect(screen.getByText('Release acceptance signals are ready.')).toBeInTheDocument();
    expect(screen.getByText('dry_run_only')).toBeInTheDocument();
    expect(screen.getByText('What changed').closest('.operator-lane-card')).toHaveAttribute(
      'id',
      'release-trust',
    );
    expect(screen.getByText('Evaluation scenarios').closest('.operator-lane-card')).toHaveAttribute(
      'id',
      'demo-mode',
    );
    expect(
      screen.getByText('Approvals and dry-runs').closest('.operator-lane-card'),
    ).not.toHaveAttribute('id', 'demo-mode');

    await userEvent.click(screen.getByRole('button', { name: 'Evidence Pack' }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith('/api/launchpad/evidence-pack', expect.any(Object));
    });

    await userEvent.click(screen.getByRole('button', { name: 'Support Bundle' }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith('/api/support/bundle', expect.any(Object));
    });

    await userEvent.click(screen.getByRole('button', { name: 'Reset' }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/launchpad/demo-reset',
        expect.objectContaining({ method: 'POST' }),
      );
    });

    await userEvent.click(screen.getByRole('button', { name: 'Start' }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/demo/lab',
        expect.objectContaining({ method: 'POST' }),
      );
    });
  });
});
