import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import {
  DetectionLab,
  IntegrationsMarketplace,
  MalwareTrustCenter,
  OperationsHealth,
  ResponseSafety,
} from '../components/OperatorTrustWorkspace.jsx';

vi.mock('../api.js', () => ({
  withSignal: vi.fn((_signal, fn) => fn()),
  detectionLabStatus: vi.fn().mockResolvedValue({
    modes: [{ id: 'replay', label: 'Replay sample telemetry', status: 'ready' }],
    expected_vs_observed: {
      expected_detections: 3,
      observed_detections: 2,
      missed_techniques: 1,
      duplicate_or_noisy_candidates: 4,
    },
    recommendations: [
      { rule_id: 'r1', rule_name: 'Noisy rule', action: 'review', detail: 'Review threshold.' },
    ],
    history: [
      {
        id: 'latest',
        mode: 'replay',
        dataset: 'fixtures',
        target_platform: 'linux',
        outcome: 'ready',
      },
    ],
  }),
  runDetectionLab: vi.fn().mockResolvedValue({ status: 'completed' }),
  responseSafety: vi.fn().mockResolvedValue({
    overview: {
      pending_response_approvals: 1,
      ready_to_execute: 0,
      total_response_requests: 1,
      pending_playbook_approvals: 0,
      status: 'approval_required',
    },
    available_actions: [{ action: 'block_ip', destructive: true }],
    requests: [
      { request: { action_label: 'Block IP', target_hostname: 'edge-01', status: 'Pending' } },
    ],
  }),
  responsePreview: vi.fn().mockResolvedValue({ status: 'preview_ready' }),
  integrationsMarketplace: vi.fn().mockResolvedValue({
    connectors: [
      {
        id: 'generic_syslog',
        label: 'Generic Syslog',
        lane: 'syslog',
        health_score: 60,
        freshness: 'stale',
        next_fix: 'Validate credentials.',
        impact: ['SIEM correlation'],
      },
    ],
  }),
  validateIntegration: vi.fn().mockResolvedValue({ status: 'preview_ready' }),
  operationsHealth: vi.fn().mockResolvedValue({
    slo_cards: [
      {
        id: 'queue_lag',
        value: 0,
        status: 'pass',
        recommended_action: 'No action needed.',
      },
    ],
  }),
  operationsHealthSnapshot: vi.fn().mockResolvedValue({ status: 'snapshot_saved' }),
  malwareExplain: vi.fn().mockResolvedValue({
    summary: { total_scans: 2, malicious: 1, suspicious: 0, yara_rules: 12 },
    presets: [
      {
        id: 'open-source-av-baseline',
        label: 'Open-source AV baseline',
        operator_opt_in: true,
        sources: ['ClamAV HDB/HSB'],
      },
    ],
    target_presets: ['single_file', 'folder', 'whole_system'],
    scan_diff: { status: 'available_after_repeated_scans' },
  }),
  malwareScanDiff: vi.fn().mockResolvedValue({
    comparison: { rootkit_delta: 'no repeated scan selected' },
    next_action: 'Run two scans.',
  }),
}));

function renderWorkspace(ui) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

describe('Operator trust workspaces', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders detection validation evidence and action', async () => {
    renderWorkspace(<DetectionLab />);
    expect(await screen.findByRole('heading', { name: /Detection Lab/i })).toBeInTheDocument();
    expect(screen.getByText(/Expected detections/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Run validation/i }));
    await waitFor(() => expect(screen.getByText(/completed/i)).toBeInTheDocument());
  });

  it('renders response safety previews', async () => {
    renderWorkspace(<ResponseSafety />);
    expect(await screen.findByText(/Pending approvals/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Preview block IP/i })).toBeInTheDocument();
  });

  it('renders connector marketplace impact', async () => {
    renderWorkspace(<IntegrationsMarketplace />);
    expect(await screen.findByText(/Generic Syslog/i)).toBeInTheDocument();
    expect(screen.getByText(/SIEM correlation/i)).toBeInTheDocument();
  });

  it('renders operations health cards', async () => {
    renderWorkspace(<OperationsHealth />);
    expect(await screen.findByRole('heading', { name: /Operations Health/i })).toBeInTheDocument();
    expect(screen.getByText(/queue_lag/i)).toBeInTheDocument();
  });

  it('renders malware transparency presets and scan diff', async () => {
    renderWorkspace(<MalwareTrustCenter />);
    expect(await screen.findByText(/Open-source AV baseline/i)).toBeInTheDocument();
    expect(screen.getByText(/whole_system/i)).toBeInTheDocument();
    expect(screen.getByText(/Run two scans/i)).toBeInTheDocument();
  });
});
