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
        setup_status: 'configured',
        freshness: 'stale',
        next_fix: 'Validate credentials.',
        validation: { status: 'review' },
        destination: 'Legacy syslog listener',
        sample_event: { event_type: 'syslog.auth' },
        impact: ['SIEM correlation'],
        required_permissions: ['syslog listener'],
      },
      {
        id: 'splunk_hec',
        label: 'Splunk HEC Export',
        lane: 'siem_export',
        health_score: 95,
        setup_status: 'configured',
        freshness: 'fresh',
        next_fix: 'Splunk HEC export is configured; keep token scope and index routing current.',
        validation: { status: 'ready' },
        destination: 'security_events / wardex:xdr',
        sample_event: { event_type: 'splunk.hec.alert' },
        summary_line:
          'https://splunk.example/services/collector -> security_events / wardex:xdr',
        secondary_line: '17 event(s) pushed, 0 pending',
        impact: ['SIEM export', 'external correlation'],
        required_permissions: ['HEC token write', 'HTTPS egress'],
        action_href: '/settings?tab=integrations',
        action_label: 'Open Settings',
      },
      {
        id: 'servicenow',
        label: 'ServiceNow Case Sync',
        lane: 'ticketing',
        health_score: 86,
        setup_status: 'configured',
        freshness: 'fresh',
        next_fix: 'Review queue mapping and continue outbound case sync coverage.',
        validation: { status: 'ready' },
        destination: 'SECOPS',
        sample_event: { event_type: 'ticket.case.sync' },
        summary_line: 'Last sync INC0012345 for case #42',
        secondary_line: '2 sync(s) recorded; latest queue SECOPS',
        impact: ['case sync', 'status visibility'],
        required_permissions: ['incident write', 'API credentials'],
        action_href: '/soc#cases',
        action_label: 'Open SOC Cases',
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

  it('renders connector marketplace impact and outbound paths', async () => {
    renderWorkspace(<IntegrationsMarketplace />);
    expect(await screen.findByText(/Generic Syslog/i)).toBeInTheDocument();
    expect(screen.getByText(/SIEM correlation/i)).toBeInTheDocument();
    expect(screen.getByText(/Splunk HEC Export/i)).toBeInTheDocument();
    expect(screen.getAllByText(/security_events \/ wardex:xdr/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/splunk\.hec\.alert/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Open Settings/i })).toHaveAttribute(
      'href',
      '/settings?tab=integrations',
    );
    expect(screen.getByText(/ServiceNow Case Sync/i)).toBeInTheDocument();
    expect(screen.getByText(/Last sync INC0012345 for case #42/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Open SOC Cases/i })).toHaveAttribute(
      'href',
      '/soc#cases',
    );

    fireEvent.click(screen.getByRole('button', { name: /Validate Splunk HEC/i }));
    await waitFor(() => expect(screen.getByText(/preview_ready/i)).toBeInTheDocument());
  });

  it('renders operations health cards', async () => {
    renderWorkspace(<OperationsHealth />);
    expect(await screen.findByRole('heading', { name: /Operations Health/i })).toBeInTheDocument();
    expect(screen.getByText(/Current operations focus/i)).toBeInTheDocument();
    expect(screen.getByText(/Operations SLOs are steady/i)).toBeInTheDocument();
    expect(screen.getByText(/queue_lag/i)).toBeInTheDocument();
  });

  it('renders malware transparency presets and scan diff', async () => {
    renderWorkspace(<MalwareTrustCenter />);
    expect(await screen.findByText(/Open-source AV baseline/i)).toBeInTheDocument();
    expect(screen.getByText(/whole_system/i)).toBeInTheDocument();
    expect(screen.getByText(/Run two scans/i)).toBeInTheDocument();
  });
});
