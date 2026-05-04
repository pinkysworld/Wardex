import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { ToastProvider } from '../hooks.jsx';
import ReportsExports from '../components/ReportsExports.jsx';
import { downloadData } from '../components/operatorUtils.js';

vi.mock('../components/operatorUtils.js', async () => {
  const actual = await vi.importActual('../components/operatorUtils.js');
  return {
    ...actual,
    downloadData: vi.fn(),
  };
});

globalThis.fetch = vi.fn();

function LocationProbe() {
  const location = useLocation();
  return (
    <div data-testid="location-probe">{`${location.pathname}${location.search}${location.hash}`}</div>
  );
}

const complianceReports = [
  {
    framework_id: 'cis-v8',
    framework_name: 'CIS Controls',
    generated_at: '2026-04-21T12:00:00Z',
    total_controls: 18,
    passed: 16,
    failed: 1,
    not_applicable: 0,
    manual_review: 1,
    score_percent: 88.9,
    findings: [
      {
        control_id: 'CIS-1.1',
        title: 'Enterprise Asset Inventory',
        status: 'pass',
        evidence: 'Fleet inventory covers 98% of enrolled endpoints.',
        remediation: '',
      },
      {
        control_id: 'CIS-8.2',
        title: 'Audit Log Retention',
        status: 'fail',
        evidence: 'Audit exports only cover 90 days of retention.',
        remediation: 'Increase audit retention to 365 days and reissue evidence.',
      },
      {
        control_id: 'CIS-12.4',
        title: 'Third-Party Assurance Review',
        status: 'manual_review',
        evidence: 'Awaiting vendor attestation package.',
        remediation: '',
      },
    ],
  },
  {
    framework_id: 'pci-dss-v4',
    framework_name: 'PCI DSS',
    generated_at: '2026-04-21T12:00:00Z',
    total_controls: 12,
    passed: 10,
    failed: 1,
    not_applicable: 0,
    manual_review: 1,
    score_percent: 83.3,
    findings: [
      {
        control_id: 'PCI-3.1',
        title: 'Protect Stored Account Data',
        status: 'pass',
        evidence: 'Encryption at rest enabled for sensitive tables.',
        remediation: '',
      },
    ],
  },
];

const complianceSummary = {
  generated_at: '2026-04-21T12:00:00Z',
  overall_score: 86.1,
  frameworks: [
    { framework: 'CIS Controls', score: 88.9, passed: 16, failed: 1, total: 18 },
    { framework: 'PCI DSS', score: 83.3, passed: 10, failed: 1, total: 12 },
  ],
};

const privacyBudget = {
  budget_remaining: 7.5,
  is_exhausted: false,
};

const attestationStatus = {
  passed: false,
  checks: [
    {
      name: 'attestation_loaded',
      passed: false,
      detail: 'no manifest loaded; use the attest CLI to generate one',
    },
    {
      name: 'signature_verified',
      passed: true,
      detail: 'signature verified',
    },
  ],
};

const responsePending = {
  pending: [
    {
      id: 'resp-1',
      action: 'Isolate',
      action_label: 'Isolate host',
      target: { hostname: 'finance-admin-01', agent_uid: 'agent-42' },
      target_hostname: 'finance-admin-01',
      target_agent_uid: 'agent-42',
      status: 'Pending',
      requested_by: 'analyst-1',
      dry_run: false,
    },
  ],
};

const responseRequests = {
  requests: [
    {
      id: 'resp-1',
      action: 'Isolate',
      action_label: 'Isolate host',
      target: { hostname: 'finance-admin-01', agent_uid: 'agent-42' },
      target_hostname: 'finance-admin-01',
      target_agent_uid: 'agent-42',
      status: 'Approved',
      requested_by: 'analyst-1',
      dry_run: false,
    },
    {
      id: 'resp-2',
      action: 'Alert',
      action_label: 'Alert',
      target: { hostname: 'dev-workstation-07', agent_uid: 'agent-7' },
      target_hostname: 'dev-workstation-07',
      target_agent_uid: 'agent-7',
      status: 'Pending',
      requested_by: 'analyst-2',
      dry_run: true,
    },
  ],
};

const responseAudit = {
  audit_log: [
    {
      request_id: 'resp-1',
      action: 'Isolate',
      target: 'finance-admin-01',
      target_hostname: 'finance-admin-01',
      outcome: 'Executed',
      timestamp: '2026-04-21T12:20:00Z',
      approvers: ['analyst-1'],
    },
    {
      request_id: 'resp-2',
      action: 'Alert',
      target: 'dev-workstation-07',
      target_hostname: 'dev-workstation-07',
      outcome: 'Denied',
      timestamp: '2026-04-21T12:25:00Z',
      approvers: ['analyst-2'],
    },
  ],
};

const responseStats = {
  pending: 1,
  pending_approval: 1,
  ready_to_execute: 1,
  total_requests: 2,
  denied: 1,
  protected_assets: 3,
};

const scopedCases = [
  {
    id: 42,
    title: 'Credential misuse on finance admin',
    status: 'open',
    priority: 'high',
  },
];

const scopedIncident = {
  id: 7,
  title: 'Suspicious PowerShell delivery chain',
  severity: 'high',
};

const scopedInvestigations = {
  items: [
    {
      id: 'inv-7',
      workflow_name: 'Credential theft and lateral movement',
      case_id: 42,
    },
  ],
};

const storedRunArtifacts = [
  {
    id: 'run-1',
    name: 'Incident package for finance admin',
    kind: 'incident_package',
    scope: 'incidents',
    format: 'json',
    last_run_at: '2026-04-21T12:05:00Z',
    next_run_at: null,
    status: 'completed',
    audience: 'analyst',
    summary: 'Scoped case handoff package',
    size_bytes: 256,
    execution_context: {
      case_id: '42',
      incident_id: '7',
      investigation_id: 'inv-7',
      source: 'case',
    },
    preview: { generated_at: '2026-04-21T12:05:00Z', ok: true },
  },
  {
    id: 'run-2',
    name: 'Global executive snapshot',
    kind: 'executive_status',
    scope: 'global',
    format: 'json',
    last_run_at: '2026-04-21T10:00:00Z',
    next_run_at: null,
    status: 'completed',
    audience: 'executive',
    summary: 'Global posture overview',
    size_bytes: 128,
    execution_context: null,
    preview: { generated_at: '2026-04-21T10:00:00Z', ok: true },
  },
];

const storedSchedules = [
  {
    id: 'sched-1',
    name: 'Scoped incident package delivery',
    kind: 'incident_package',
    scope: 'incidents',
    format: 'json',
    last_run_at: '2026-04-21T12:15:00Z',
    next_run_at: '2026-04-22T12:15:00Z',
    status: 'active',
    cadence: 'daily',
    target: 'analysts@wardex.local',
    execution_context: {
      case_id: '42',
      incident_id: '7',
      investigation_id: 'inv-7',
      source: 'case',
    },
  },
  {
    id: 'sched-2',
    name: 'Global executive digest',
    kind: 'executive_status',
    scope: 'global',
    format: 'json',
    last_run_at: '2026-04-21T09:00:00Z',
    next_run_at: '2026-04-22T09:00:00Z',
    status: 'active',
    cadence: 'daily',
    target: 'exec@wardex.local',
    execution_context: null,
  },
];

const legacyReportDetail = {
  id: 101,
  generated_at: '2026-04-21T12:00:00Z',
  report_type: 'legacy_runtime_report',
  report: {
    generated_at: '2026-04-21T12:00:00Z',
    summary: {
      total_samples: 5,
      alert_count: 2,
      critical_count: 1,
      average_score: 72.4,
      max_score: 98.1,
    },
    samples: [],
  },
};

function jsonResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    headers: { get: (name) => (name?.toLowerCase() === 'content-type' ? 'application/json' : '') },
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

function textResponse(body, status = 200, contentType = 'text/plain') {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    headers: { get: (name) => (name?.toLowerCase() === 'content-type' ? contentType : '') },
    json: async () => JSON.parse(body),
    text: async () => body,
  };
}

function renderWithProviders(route = '/reports') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <LocationProbe />
      <ToastProvider>
        <ReportsExports />
      </ToastProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  const currentRunArtifacts = structuredClone(storedRunArtifacts);
  const currentSchedules = structuredClone(storedSchedules);
  const currentTemplates = [
    {
      id: 'tpl-1',
      name: 'Executive Status',
      kind: 'executive_status',
      scope: 'global',
      format: 'json',
      status: 'ready',
      audience: 'executive',
      description: 'Leadership snapshot',
      execution_context: null,
    },
    {
      id: 'tpl-audit-export',
      name: 'Audit Export',
      kind: 'audit_export',
      scope: 'global',
      format: 'csv',
      status: 'ready',
      audience: 'compliance',
      description: 'Filtered API audit trail export',
      execution_context: null,
    },
    {
      id: 'tpl-compliance-snapshot',
      name: 'Compliance Snapshot',
      kind: 'compliance_snapshot',
      scope: 'global',
      format: 'json',
      status: 'ready',
      audience: 'compliance',
      description: 'Framework snapshot for audits',
      execution_context: null,
    },
    {
      id: 'tpl-failover-drill-history',
      name: 'Control-plane Failover Drill History',
      kind: 'control_plane_failover_history',
      scope: 'control_plane',
      format: 'json',
      status: 'ready',
      audience: 'audit',
      description: 'Persisted control-plane failover drill history with cluster posture.',
      execution_context: null,
    },
  ];
  const currentStoredReports = [
    {
      id: 101,
      generated_at: '2026-04-21T12:00:00Z',
      report_type: 'legacy_runtime_report',
      alert_count: 2,
      execution_context: null,
    },
  ];
  globalThis.fetch.mockImplementation(async (url, options = {}) => {
    const parsed = new URL(String(url), 'http://localhost');
    const { pathname, searchParams } = parsed;
    const method = options.method || 'GET';

    if (pathname === '/api/reports/executive-summary') {
      return jsonResponse({ total_reports: 4, generated_at: '2026-04-21T12:00:00Z' });
    }
    if (pathname === '/api/reports') {
      const scopedReports = currentStoredReports.filter((report) => {
        const scope = searchParams.get('scope');
        if (scope === 'unscoped') {
          return !report.execution_context;
        }
        if (scope === 'scoped') {
          if (!report.execution_context) return false;
          const fieldPairs = [
            ['case_id', report.execution_context.case_id],
            ['incident_id', report.execution_context.incident_id],
            ['investigation_id', report.execution_context.investigation_id],
            ['source', report.execution_context.source],
          ];
          return fieldPairs.every(([key, value]) => {
            const expected = searchParams.get(key);
            return !expected || expected === value;
          });
        }
        return true;
      });
      return jsonResponse({ reports: scopedReports });
    }
    if (pathname === '/api/reports/101') {
      return jsonResponse(legacyReportDetail);
    }
    if (pathname === '/api/reports/101/context' && method === 'POST') {
      const payload = JSON.parse(options.body || '{}');
      currentStoredReports[0] = {
        ...currentStoredReports[0],
        execution_context: {
          case_id: payload.case_id || null,
          incident_id: payload.incident_id || null,
          investigation_id: payload.investigation_id || null,
          source: payload.source || null,
        },
      };
      return jsonResponse({ status: 'updated', report: currentStoredReports[0] });
    }
    if (pathname === '/api/report-templates') {
      if (method === 'POST') {
        const payload = JSON.parse(options.body || '{}');
        currentTemplates.unshift({
          id: `tpl-scoped-${currentTemplates.length + 1}`,
          name: payload.name || 'Scoped Template',
          kind: payload.kind || 'executive_status',
          scope: payload.scope || 'global',
          format: payload.format || 'json',
          status: payload.status || 'ready',
          audience: payload.audience || 'operations',
          description: payload.description || 'Reusable report template',
          execution_context: {
            case_id: payload.case_id || null,
            incident_id: payload.incident_id || null,
            investigation_id: payload.investigation_id || null,
            source: payload.source || null,
          },
        });
        return jsonResponse({ status: 'saved', template: currentTemplates[0] }, 201);
      }
      const templates = currentTemplates.filter((template) => {
        const scope = searchParams.get('scope');
        if (scope === 'unscoped') {
          return !template.execution_context;
        }
        if (scope === 'scoped') {
          if (!template.execution_context) return false;
          const fieldPairs = [
            ['case_id', template.execution_context.case_id],
            ['incident_id', template.execution_context.incident_id],
            ['investigation_id', template.execution_context.investigation_id],
            ['source', template.execution_context.source],
          ];
          return fieldPairs.every(([key, value]) => {
            const expected = searchParams.get(key);
            return !expected || expected === value;
          });
        }
        return true;
      });
      return jsonResponse({ templates });
    }
    if (pathname === '/api/report-runs') {
      if (method === 'POST') {
        const payload = JSON.parse(options.body || '{}');
        currentRunArtifacts.unshift({
          id: `run-${currentRunArtifacts.length + 1}`,
          name: payload.name || 'Republished run',
          kind: payload.kind || 'legacy_runtime_report',
          scope: payload.scope || 'case',
          format: payload.format || 'json',
          last_run_at: '2026-04-21T13:00:00Z',
          next_run_at: null,
          status: payload.status || 'completed',
          audience: payload.audience || 'analyst',
          summary: payload.summary || '',
          size_bytes: JSON.stringify(payload.preview_override || {}).length,
          execution_context: {
            case_id: payload.case_id || null,
            incident_id: payload.incident_id || null,
            investigation_id: payload.investigation_id || null,
            source: payload.source || null,
          },
          preview: payload.preview_override || {},
        });
        return jsonResponse({ status: 'created' });
      }
      const runs = currentRunArtifacts.filter((run) => {
        const scope = searchParams.get('scope');
        if (scope === 'unscoped') {
          return !run.execution_context;
        }
        if (scope === 'scoped') {
          if (!run.execution_context) return false;
          const fieldPairs = [
            ['case_id', run.execution_context.case_id],
            ['incident_id', run.execution_context.incident_id],
            ['investigation_id', run.execution_context.investigation_id],
            ['source', run.execution_context.source],
          ];
          return fieldPairs.every(([key, value]) => {
            const expected = searchParams.get(key);
            return !expected || expected === value;
          });
        }
        return true;
      });
      return jsonResponse({ runs });
    }
    if (pathname === '/api/report-schedules') {
      if (method === 'POST') {
        const payload = JSON.parse(options.body || '{}');
        currentSchedules.unshift({
          id: `sched-${currentSchedules.length + 1}`,
          name: payload.name || 'Scheduled report',
          kind: payload.kind || 'incident_package',
          scope: payload.scope || 'incidents',
          format: payload.format || 'json',
          last_run_at: null,
          next_run_at: payload.next_run_at || '2026-04-22T12:15:00Z',
          status: payload.status || 'active',
          cadence: payload.cadence || 'weekly',
          target: payload.target || 'ops@wardex.local',
          execution_context: {
            case_id: payload.case_id || null,
            incident_id: payload.incident_id || null,
            investigation_id: payload.investigation_id || null,
            source: payload.source || null,
          },
        });
        return jsonResponse({ status: 'saved' });
      }
      const schedules = currentSchedules.filter((schedule) => {
        const scope = searchParams.get('scope');
        if (scope === 'unscoped') {
          return !schedule.execution_context;
        }
        if (scope === 'scoped') {
          if (!schedule.execution_context) return false;
          const fieldPairs = [
            ['case_id', schedule.execution_context.case_id],
            ['incident_id', schedule.execution_context.incident_id],
            ['investigation_id', schedule.execution_context.investigation_id],
            ['source', schedule.execution_context.source],
          ];
          return fieldPairs.every(([key, value]) => {
            const expected = searchParams.get(key);
            return !expected || expected === value;
          });
        }
        return true;
      });
      return jsonResponse({ schedules });
    }
    if (pathname === '/api/cases') {
      return jsonResponse({ cases: scopedCases });
    }
    if (pathname === '/api/incidents/7') {
      return jsonResponse(scopedIncident);
    }
    if (pathname === '/api/investigations/active') {
      return jsonResponse(scopedInvestigations);
    }
    if (pathname === '/api/compliance/summary') {
      return jsonResponse(complianceSummary);
    }
    if (pathname === '/api/compliance/report') {
      return jsonResponse(complianceReports);
    }
    if (pathname === '/api/privacy/budget') {
      return jsonResponse(privacyBudget);
    }
    if (pathname === '/api/attestation/status') {
      return jsonResponse(attestationStatus);
    }
    if (pathname === '/api/response/pending') {
      return jsonResponse(responsePending);
    }
    if (pathname === '/api/response/requests') {
      return jsonResponse(responseRequests);
    }
    if (pathname === '/api/response/audit') {
      return jsonResponse(responseAudit);
    }
    if (pathname === '/api/response/stats') {
      return jsonResponse(responseStats);
    }
    if (pathname === '/api/export/alerts') {
      const format = searchParams.get('format');
      if (format === 'cef') {
        return textResponse(
          'CEF:0|Wardex|Wardex|1.0|alert-1|Credential storm|8|src=203.0.113.42',
          200,
          'text/plain',
        );
      }
      return jsonResponse([{ id: 'alert-1', severity: 'high' }]);
    }
    if (pathname === '/api/audit/log/export') {
      return textResponse(
        'timestamp,method,path,status_code,auth_used\n2026-04-21T12:00:00Z,GET,/api/auth/check,401,false\n',
        200,
        'text/csv',
      );
    }
    if (pathname === '/api/pii/scan' && method === 'POST') {
      return jsonResponse({
        has_pii: true,
        finding_count: 2,
        categories: ['email', 'ip_address'],
      });
    }
    if (pathname.startsWith('/api/gdpr/forget/') && method === 'DELETE') {
      const entityId = decodeURIComponent(pathname.split('/').pop() || '');
      return jsonResponse({
        status: 'completed',
        entity_id: entityId,
        records_purged: 3,
        timestamp: '2026-04-21T12:10:00Z',
      });
    }
    return jsonResponse({});
  });
});

describe('ReportsExports', () => {
  it('renders framework findings and downloads an evidence bundle', async () => {
    renderWithProviders('/reports?tab=compliance');

    expect(await screen.findByText('Compliance Snapshot')).toBeInTheDocument();
    expect((await screen.findAllByText('CIS Controls')).length).toBeGreaterThan(0);
    const priorityTable = await screen.findByRole('table', {
      name: 'Priority compliance findings',
    });
    expect(within(priorityTable).getByText('CIS-8.2')).toBeInTheDocument();
    expect(within(priorityTable).getByText('CIS-12.4')).toBeInTheDocument();
    expect(within(priorityTable).queryByText('CIS-1.1')).not.toBeInTheDocument();
    expect(
      within(priorityTable).getByText('Collect operator-supplied evidence before export.'),
    ).toBeInTheDocument();
    expect(await screen.findByText('Controls Requiring Remediation')).toBeInTheDocument();
    expect((await screen.findAllByText('Audit Log Retention')).length).toBeGreaterThan(0);

    fireEvent.click(screen.getByText('Download Evidence Bundle'));

    expect(downloadData).toHaveBeenCalledWith(
      expect.objectContaining({
        bundle_type: 'compliance_evidence',
        framework_id: 'cis-v8',
      }),
      'cis-v8-evidence-bundle.json',
    );
  });

  it('downloads backend alert exports in the selected text format', async () => {
    renderWithProviders('/reports?tab=evidence');

    expect(await screen.findByText('Alert Export Formats')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Export Format'), { target: { value: 'cef' } });
    fireEvent.click(screen.getByText('Download Alert Export'));

    await waitFor(() => {
      expect(downloadData).toHaveBeenCalledWith(
        'CEF:0|Wardex|Wardex|1.0|alert-1|Credential storm|8|src=203.0.113.42',
        'alerts-cef.cef',
        'text/plain;charset=utf-8',
      );
    });

    expect(globalThis.fetch).toHaveBeenCalledWith(
      '/api/export/alerts?format=cef',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('refreshes grouped evidence context data from the evidence workspace', async () => {
    const callCounts = {
      complianceSummary: 0,
      complianceReport: 0,
      privacyBudget: 0,
      attestationStatus: 0,
    };
    const defaultImplementation = globalThis.fetch.getMockImplementation();

    globalThis.fetch.mockImplementation(async (url, options = {}) => {
      const parsed = new URL(String(url), 'http://localhost');
      const { pathname } = parsed;

      if (pathname === '/api/compliance/summary') {
        callCounts.complianceSummary += 1;
      }
      if (pathname === '/api/compliance/report') {
        callCounts.complianceReport += 1;
      }
      if (pathname === '/api/privacy/budget') {
        callCounts.privacyBudget += 1;
      }
      if (pathname === '/api/attestation/status') {
        callCounts.attestationStatus += 1;
      }

      return defaultImplementation(url, options);
    });

    renderWithProviders('/reports?tab=evidence');

    expect(await screen.findByText('Alert Export Formats')).toBeInTheDocument();

    await waitFor(() => {
      expect(callCounts.complianceSummary).toBeGreaterThan(0);
      expect(callCounts.complianceReport).toBeGreaterThan(0);
      expect(callCounts.privacyBudget).toBeGreaterThan(0);
      expect(callCounts.attestationStatus).toBeGreaterThan(0);
    });

    const initialCounts = { ...callCounts };

    fireEvent.click(screen.getByRole('button', { name: 'Refresh Context' }));

    await waitFor(() => {
      expect(callCounts.complianceSummary).toBe(initialCounts.complianceSummary + 1);
      expect(callCounts.complianceReport).toBe(initialCounts.complianceReport + 1);
      expect(callCounts.privacyBudget).toBe(initialCounts.privacyBudget + 1);
      expect(callCounts.attestationStatus).toBe(initialCounts.attestationStatus + 1);
    });
  });

  it('persists compliance markdown artifacts and re-downloads the original payload from run history', async () => {
    renderWithProviders(
      '/reports?tab=compliance&case=42&incident=7&investigation=inv-7&source=case',
    );

    expect(await screen.findByText('Compliance Snapshot')).toBeInTheDocument();
    const frameworkButton = (await screen.findAllByText('CIS Controls'))
      .map((element) => element.closest('button'))
      .find(Boolean);
    expect(frameworkButton).toBeTruthy();
    fireEvent.click(frameworkButton);
    fireEvent.click(screen.getByRole('button', { name: 'Save Markdown Artifact' }));

    await waitFor(() => {
      const markdownArtifactRequest = globalThis.fetch.mock.calls.find(([url, options]) => {
        if (String(url) !== '/api/report-runs' || options?.method !== 'POST') return false;
        const payload = JSON.parse(options.body || '{}');
        return payload.kind === 'compliance_markdown';
      });
      expect(markdownArtifactRequest).toBeTruthy();
      expect(JSON.parse(markdownArtifactRequest[1].body)).toEqual(
        expect.objectContaining({
          case_id: '42',
          incident_id: '7',
          investigation_id: 'inv-7',
          source: 'case',
          kind: 'compliance_markdown',
          format: 'markdown',
        }),
      );
      expect(JSON.parse(markdownArtifactRequest[1].body).preview_override).toEqual(
        expect.objectContaining({
          download_name: 'cis-v8-compliance-report.md',
          content_type: 'text/markdown;charset=utf-8',
          payload: expect.stringContaining('# Compliance Report: CIS Controls v8'),
        }),
      );
    });

    fireEvent.click(screen.getByRole('tab', { name: 'Runs' }));
    const runHistoryCard = screen.getByText('Run History').closest('.card');
    expect(runHistoryCard).toBeTruthy();
    const artifactRow = (
      await within(runHistoryCard).findByText('CIS Controls Compliance Markdown')
    ).closest('tr');
    expect(artifactRow).toBeTruthy();

    fireEvent.click(within(artifactRow).getByRole('button', { name: 'Download' }));

    expect(downloadData).toHaveBeenCalledWith(
      expect.stringContaining('# Compliance Report: CIS Controls v8'),
      'cis-v8-compliance-report.md',
      'text/markdown;charset=utf-8',
    );
  });

  it('persists backend-native alert exports as scoped artifacts', async () => {
    renderWithProviders('/reports?tab=evidence&case=42&incident=7&investigation=inv-7&source=case');

    expect(await screen.findByText('Alert Export Formats')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Export Format'), { target: { value: 'cef' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save Alert Artifact' }));

    await waitFor(() => {
      expect(
        globalThis.fetch.mock.calls.some(
          ([url, options]) =>
            String(url) === '/api/export/alerts?format=cef' && (options?.method || 'GET') === 'GET',
        ),
      ).toBe(true);
    });

    await waitFor(() => {
      const alertArtifactRequest = globalThis.fetch.mock.calls.find(([url, options]) => {
        if (String(url) !== '/api/report-runs' || options?.method !== 'POST') return false;
        const payload = JSON.parse(options.body || '{}');
        return payload.kind === 'alert_export';
      });
      expect(alertArtifactRequest).toBeTruthy();
      expect(JSON.parse(alertArtifactRequest[1].body)).toEqual(
        expect.objectContaining({
          case_id: '42',
          incident_id: '7',
          investigation_id: 'inv-7',
          source: 'case',
          kind: 'alert_export',
          format: 'cef',
        }),
      );
      expect(JSON.parse(alertArtifactRequest[1].body).preview_override).toEqual(
        expect.objectContaining({
          download_name: 'alerts-cef.cef',
          content_type: 'text/plain;charset=utf-8',
          payload: 'CEF:0|Wardex|Wardex|1.0|alert-1|Credential storm|8|src=203.0.113.42',
          metadata: expect.objectContaining({
            export_format: 'cef',
            export_label: 'CEF',
          }),
        }),
      );
    });
  });

  it('persists a response approval snapshot scoped to the active response target', async () => {
    renderWithProviders(
      '/reports?tab=delivery&case=42&incident=7&investigation=inv-7&source=investigation&target=finance-admin-01',
    );

    const responseCard = (await screen.findByText('Response Approval Snapshot')).closest('.card');
    expect(responseCard).toBeTruthy();
    expect((await within(responseCard).findAllByText('finance-admin-01')).length).toBeGreaterThan(
      0,
    );
    expect((await within(responseCard).findAllByText('Isolate host')).length).toBeGreaterThan(0);
    expect(await within(responseCard).findByText('Recent Response Audit')).toBeInTheDocument();
    const responseAuditTable = within(responseCard).getByRole('table', {
      name: 'Recent response audit entries',
    });
    expect(within(responseAuditTable).getByText('resp-1')).toBeInTheDocument();
    expect(within(responseAuditTable).getByText('Executed')).toBeInTheDocument();
    expect(within(responseCard).queryByText('dev-workstation-07')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Save Response Artifact' }));

    await waitFor(() => {
      const responseArtifactRequest = globalThis.fetch.mock.calls.find(([url, options]) => {
        if (String(url) !== '/api/report-runs' || options?.method !== 'POST') return false;
        const payload = JSON.parse(options.body || '{}');
        return payload.kind === 'response_approval_snapshot';
      });
      expect(responseArtifactRequest).toBeTruthy();
      expect(JSON.parse(responseArtifactRequest[1].body)).toEqual(
        expect.objectContaining({
          case_id: '42',
          incident_id: '7',
          investigation_id: 'inv-7',
          source: 'investigation',
          kind: 'response_approval_snapshot',
        }),
      );
      expect(JSON.parse(responseArtifactRequest[1].body).preview_override).toEqual(
        expect.objectContaining({
          download_name: 'response-approval-snapshot.json',
          metadata: expect.objectContaining({
            response_target: 'finance-admin-01',
            pending_approvals: 1,
            request_count: 1,
          }),
          payload: expect.objectContaining({
            response_target: 'finance-admin-01',
            requests: [
              expect.objectContaining({
                target_hostname: 'finance-admin-01',
              }),
            ],
          }),
        }),
      );
    });
  });

  it('refreshes grouped response delivery data from the delivery workspace', async () => {
    const callCounts = {
      responsePending: 0,
      responseRequests: 0,
      responseAudit: 0,
      responseStats: 0,
    };
    const defaultImplementation = globalThis.fetch.getMockImplementation();

    globalThis.fetch.mockImplementation(async (url, options = {}) => {
      const parsed = new URL(String(url), 'http://localhost');
      const { pathname } = parsed;

      if (pathname === '/api/response/pending') {
        callCounts.responsePending += 1;
      }
      if (pathname === '/api/response/requests') {
        callCounts.responseRequests += 1;
      }
      if (pathname === '/api/response/audit') {
        callCounts.responseAudit += 1;
      }
      if (pathname === '/api/response/stats') {
        callCounts.responseStats += 1;
      }

      return defaultImplementation(url, options);
    });

    renderWithProviders('/reports?tab=delivery&target=finance-admin-01');

    const responseCard = (await screen.findByText('Response Approval Snapshot')).closest('.card');
    expect(responseCard).toBeTruthy();

    await waitFor(() => {
      expect(callCounts.responsePending).toBeGreaterThan(0);
      expect(callCounts.responseRequests).toBeGreaterThan(0);
      expect(callCounts.responseAudit).toBeGreaterThan(0);
      expect(callCounts.responseStats).toBeGreaterThan(0);
    });

    const initialCounts = { ...callCounts };

    fireEvent.click(within(responseCard).getByRole('button', { name: 'Refresh Response' }));

    await waitFor(() => {
      expect(callCounts.responsePending).toBe(initialCounts.responsePending + 1);
      expect(callCounts.responseRequests).toBe(initialCounts.responseRequests + 1);
      expect(callCounts.responseAudit).toBe(initialCounts.responseAudit + 1);
      expect(callCounts.responseStats).toBe(initialCounts.responseStats + 1);
    });
  });

  it('refreshes grouped report history data from the runs workspace', async () => {
    const callCounts = {
      reportRuns: 0,
      reportSchedules: 0,
    };
    const defaultImplementation = globalThis.fetch.getMockImplementation();

    globalThis.fetch.mockImplementation(async (url, options = {}) => {
      const parsed = new URL(String(url), 'http://localhost');
      const { pathname } = parsed;

      if (pathname === '/api/report-runs') {
        callCounts.reportRuns += 1;
      }
      if (pathname === '/api/report-schedules') {
        callCounts.reportSchedules += 1;
      }

      return defaultImplementation(url, options);
    });

    renderWithProviders('/reports?tab=runs');

    const runHistoryCard = (await screen.findByText('Run History')).closest('.card');
    expect(runHistoryCard).toBeTruthy();

    await waitFor(() => {
      expect(callCounts.reportRuns).toBeGreaterThan(0);
      expect(callCounts.reportSchedules).toBeGreaterThan(0);
    });

    const initialCounts = { ...callCounts };

    fireEvent.click(within(runHistoryCard).getByRole('button', { name: 'Refresh' }));

    await waitFor(() => {
      expect(callCounts.reportRuns).toBe(initialCounts.reportRuns + 1);
      expect(callCounts.reportSchedules).toBe(initialCounts.reportSchedules + 1);
    });
  });

  it('refreshes grouped report inventory data after republishing a legacy backend report', async () => {
    const callCounts = {
      baseReports: 0,
      scopedReports: 0,
    };
    const defaultImplementation = globalThis.fetch.getMockImplementation();

    globalThis.fetch.mockImplementation(async (url, options = {}) => {
      const parsed = new URL(String(url), 'http://localhost');
      const { pathname, searchParams } = parsed;

      if (pathname === '/api/reports') {
        if (searchParams.get('scope') === 'scoped') {
          callCounts.scopedReports += 1;
        } else {
          callCounts.baseReports += 1;
        }
      }

      return defaultImplementation(url, options);
    });

    renderWithProviders('/reports?tab=runs&case=42&incident=7&investigation=inv-7&source=case');

    expect(await screen.findByText('Stored Report Artifacts')).toBeInTheDocument();

    await waitFor(() => {
      expect(callCounts.baseReports).toBeGreaterThan(1);
    });

    const initialCounts = { ...callCounts };

    fireEvent.click(screen.getByRole('button', { name: 'Republish To Scope' }));

    await waitFor(() => {
      expect(
        globalThis.fetch.mock.calls.some(
          ([url, options]) => String(url) === '/api/report-runs' && options?.method === 'POST',
        ),
      ).toBe(true);
    });

    await waitFor(() => {
      expect(callCounts.baseReports).toBe(initialCounts.baseReports + 1);
      expect(callCounts.scopedReports).toBe(initialCounts.scopedReports + 1);
    });
  });

  it('refreshes grouped template workspace data after saving a scoped template', async () => {
    const callCounts = {
      executiveSummary: 0,
      baseTemplates: 0,
      scopedTemplates: 0,
    };
    const defaultImplementation = globalThis.fetch.getMockImplementation();

    globalThis.fetch.mockImplementation(async (url, options = {}) => {
      const parsed = new URL(String(url), 'http://localhost');
      const { pathname, searchParams } = parsed;
      const method = options.method || 'GET';

      if (pathname === '/api/reports/executive-summary') {
        callCounts.executiveSummary += 1;
      }
      if (pathname === '/api/report-templates' && method === 'GET') {
        if (searchParams.get('scope') === 'scoped') {
          callCounts.scopedTemplates += 1;
        } else {
          callCounts.baseTemplates += 1;
        }
      }

      return defaultImplementation(url, options);
    });

    renderWithProviders(
      '/reports?tab=templates&case=42&incident=7&investigation=inv-7&source=case',
    );

    expect(await screen.findByText('Reusable Templates')).toBeInTheDocument();

    await waitFor(() => {
      expect(callCounts.executiveSummary).toBeGreaterThan(0);
      expect(callCounts.baseTemplates).toBeGreaterThan(0);
    });

    const initialCounts = { ...callCounts };

    fireEvent.click(screen.getByRole('button', { name: 'Save As Scoped Template' }));

    await waitFor(() => {
      expect(
        globalThis.fetch.mock.calls.some(
          ([url, options]) => String(url) === '/api/report-templates' && options?.method === 'POST',
        ),
      ).toBe(true);
    });

    await waitFor(() => {
      expect(callCounts.executiveSummary).toBe(initialCounts.executiveSummary + 1);
      expect(callCounts.baseTemplates).toBe(initialCounts.baseTemplates);
      expect(callCounts.scopedTemplates).toBe(initialCounts.scopedTemplates + 1);
    });
  });

  it('keeps case and investigation handoff context attached to the reporting workspace', async () => {
    renderWithProviders('/reports?tab=evidence&case=42&incident=7&investigation=inv-7&source=case');

    expect(await screen.findByText('Active report scope')).toBeInTheDocument();
    expect(await screen.findByText('#42 Credential misuse on finance admin')).toBeInTheDocument();
    expect(await screen.findByText('Suspicious PowerShell delivery chain')).toBeInTheDocument();
    expect(await screen.findByText('Credential theft and lateral movement')).toBeInTheDocument();

    expect(screen.getByRole('link', { name: 'Open Case Drawer' })).toHaveAttribute(
      'href',
      '/soc?case=42&incident=7&investigation=inv-7&source=case&drawer=case-workspace&casePanel=summary#cases',
    );
    expect(screen.getByRole('link', { name: 'Open Incident Drawer' })).toHaveAttribute(
      'href',
      '/soc?case=42&incident=7&investigation=inv-7&source=case&drawer=incident-detail&incidentPanel=summary#cases',
    );
    expect(screen.getByRole('link', { name: 'Open Investigation' })).toHaveAttribute(
      'href',
      '/soc?case=42&investigation=inv-7&source=case#investigations',
    );
    expect(screen.getByRole('link', { name: 'Ask Assistant' })).toHaveAttribute(
      'href',
      '/assistant?case=42&incident=7&investigation=inv-7&source=case',
    );

    fireEvent.click(screen.getByRole('tab', { name: 'Delivery' }));

    expect(await screen.findByText('Create Delivery Schedule')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open Case Drawer' })).toHaveAttribute(
      'href',
      '/soc?case=42&incident=7&investigation=inv-7&source=case&drawer=case-workspace&casePanel=summary#cases',
    );
  });

  it('includes scoped handoff context when creating report runs and schedules', async () => {
    renderWithProviders(
      '/reports?tab=templates&case=42&incident=7&investigation=inv-7&source=case',
    );

    expect(await screen.findByText('Reusable Templates')).toBeInTheDocument();
    const templateButton = (await screen.findAllByText('Executive Status'))
      .map((element) => element.closest('button'))
      .find(Boolean);
    expect(templateButton).toBeTruthy();
    fireEvent.click(templateButton);
    fireEvent.click(screen.getByRole('button', { name: 'Save As Scoped Template' }));

    await waitFor(() => {
      const templateRequest = globalThis.fetch.mock.calls.find(
        ([url, options]) => String(url) === '/api/report-templates' && options?.method === 'POST',
      );
      expect(templateRequest).toBeTruthy();
      expect(JSON.parse(templateRequest[1].body)).toEqual(
        expect.objectContaining({
          case_id: '42',
          incident_id: '7',
          investigation_id: 'inv-7',
          source: 'case',
        }),
      );
    });

    fireEvent.click(screen.getByRole('button', { name: 'Current Scope' }));
    await waitFor(() => {
      expect(
        globalThis.fetch.mock.calls.some(
          ([url]) =>
            String(url) ===
            '/api/report-templates?case_id=42&incident_id=7&investigation_id=inv-7&source=case&scope=scoped',
        ),
      ).toBe(true);
    });
    expect(
      (await screen.findAllByText('Executive Status for #42 Credential misuse on finance admin'))
        .length,
    ).toBeGreaterThan(0);
    fireEvent.click(
      (
        await screen.findAllByText('Executive Status for #42 Credential misuse on finance admin')
      )[0],
    );

    const previewScopeSection = (await screen.findByText('Preview Scope')).parentElement;
    expect(previewScopeSection).toBeTruthy();
    expect(within(previewScopeSection).getByText('Case #42')).toBeInTheDocument();
    expect(within(previewScopeSection).getByText('Incident #7')).toBeInTheDocument();
    expect(within(previewScopeSection).getByText('Investigation inv-7')).toBeInTheDocument();
    expect(within(previewScopeSection).getByText('Case')).toBeInTheDocument();

    fireEvent.click(screen.getByText('Create Run'));

    await waitFor(() => {
      const reportRunRequest = globalThis.fetch.mock.calls.find(
        ([url, options]) => String(url) === '/api/report-runs' && options?.method === 'POST',
      );
      expect(reportRunRequest).toBeTruthy();
      expect(JSON.parse(reportRunRequest[1].body)).toEqual(
        expect.objectContaining({
          case_id: '42',
          incident_id: '7',
          investigation_id: 'inv-7',
          source: 'case',
        }),
      );
    });

    fireEvent.click(screen.getByRole('tab', { name: 'Delivery' }));
    expect(await screen.findByText('Create Delivery Schedule')).toBeInTheDocument();
    fireEvent.click(screen.getByText('Save Schedule'));

    await waitFor(() => {
      const scheduleRequest = globalThis.fetch.mock.calls.find(
        ([url, options]) => String(url) === '/api/report-schedules' && options?.method === 'POST',
      );
      expect(scheduleRequest).toBeTruthy();
      expect(JSON.parse(scheduleRequest[1].body)).toEqual(
        expect.objectContaining({
          case_id: '42',
          incident_id: '7',
          investigation_id: 'inv-7',
          source: 'case',
        }),
      );
    });
  });

  it('prefills delivery scheduling from the control-plane failover history template', async () => {
    renderWithProviders('/reports?tab=templates');

    expect(await screen.findByText('Reusable Templates')).toBeInTheDocument();
    const templateButton = (await screen.findAllByText('Control-plane Failover Drill History'))
      .map((element) => element.closest('button'))
      .find(Boolean);
    expect(templateButton).toBeTruthy();

    fireEvent.click(templateButton);
    fireEvent.click(screen.getByRole('button', { name: 'Schedule Delivery' }));

    expect(await screen.findByText('Create Delivery Schedule')).toBeInTheDocument();
    expect(screen.getByLabelText('Schedule Name')).toHaveValue(
      'Weekly Control-plane Failover Drill History',
    );
    expect(screen.getByLabelText('Template Kind')).toHaveValue('control_plane_failover_history');

    fireEvent.click(screen.getByRole('button', { name: 'Save Schedule' }));

    await waitFor(() => {
      const scheduleRequest = globalThis.fetch.mock.calls.find(
        ([url, options]) => String(url) === '/api/report-schedules' && options?.method === 'POST',
      );
      expect(scheduleRequest).toBeTruthy();
      expect(JSON.parse(scheduleRequest[1].body)).toEqual(
        expect.objectContaining({
          name: 'Weekly Control-plane Failover Drill History',
          kind: 'control_plane_failover_history',
          scope: 'control_plane',
          format: 'json',
          cadence: 'weekly',
        }),
      );
    });
  });

  it('filters stored artifacts by the active execution scope while keeping legacy reports visible', async () => {
    renderWithProviders('/reports?tab=runs&case=42&incident=7&investigation=inv-7&source=case');

    expect(await screen.findByText('Stored Report Artifacts')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Current Scope' }));

    const artifactCard = screen.getByText('Stored Report Artifacts').closest('.card');
    expect(artifactCard).toBeTruthy();
    expect(within(artifactCard).getByText('Scoped Artifact Library')).toBeInTheDocument();
    expect(
      within(artifactCard).getByText('Incident package for finance admin'),
    ).toBeInTheDocument();
    expect(within(artifactCard).queryByText('Global executive snapshot')).not.toBeInTheDocument();
    expect(await screen.findByText('Legacy Backend Reports')).toBeInTheDocument();
    expect(screen.getByText(/do not carry execution context yet/i)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Artifact Search'), {
      target: { value: '101' },
    });

    expect(
      await within(artifactCard).findByText(
        'No persisted report-run artifacts match the current investigation scope yet.',
      ),
    ).toBeInTheDocument();
    expect(
      await within(artifactCard).findByText('No legacy backend reports match the current search.'),
    ).toBeInTheDocument();
    expect(within(artifactCard).queryByText('101')).not.toBeInTheDocument();
  });

  it('requests scoped run and schedule history when an investigation scope is active', async () => {
    renderWithProviders('/reports?tab=runs&case=42&incident=7&investigation=inv-7&source=case');

    expect(await screen.findByText('Run History')).toBeInTheDocument();
    const runHistoryCard = screen.getByText('Run History').closest('.card');
    expect(runHistoryCard).toBeTruthy();
    expect(
      await within(runHistoryCard).findByText('Incident package for finance admin'),
    ).toBeInTheDocument();
    expect(within(runHistoryCard).queryByText('Global executive snapshot')).not.toBeInTheDocument();

    await waitFor(() => {
      expect(
        globalThis.fetch.mock.calls.some(
          ([url]) =>
            String(url) ===
            '/api/report-runs?case_id=42&incident_id=7&investigation_id=inv-7&source=case&scope=scoped',
        ),
      ).toBe(true);
    });

    fireEvent.click(screen.getByRole('tab', { name: 'Delivery' }));
    expect(await screen.findByText('Delivery History')).toBeInTheDocument();
    const deliveryHistoryCard = screen.getByText('Delivery History').closest('.card');
    expect(deliveryHistoryCard).toBeTruthy();
    expect(
      await within(deliveryHistoryCard).findByText('Scoped incident package delivery'),
    ).toBeInTheDocument();
    expect(
      within(deliveryHistoryCard).queryByText('Global executive digest'),
    ).not.toBeInTheDocument();

    await waitFor(() => {
      expect(
        globalThis.fetch.mock.calls.some(
          ([url]) =>
            String(url) ===
            '/api/report-schedules?case_id=42&incident_id=7&investigation_id=inv-7&source=case&scope=scoped',
        ),
      ).toBe(true);
    });
  });

  it('republishes a legacy backend report into the scoped artifact library', async () => {
    renderWithProviders('/reports?tab=runs&case=42&incident=7&investigation=inv-7&source=case');

    expect(await screen.findByText('Stored Report Artifacts')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Republish To Scope' }));

    await waitFor(() => {
      const reportDetailRequest = globalThis.fetch.mock.calls.find(
        ([url, options]) =>
          String(url) === '/api/reports/101' && (options?.method || 'GET') === 'GET',
      );
      expect(reportDetailRequest).toBeTruthy();
    });

    await waitFor(() => {
      const republishRequest = globalThis.fetch.mock.calls.find(
        ([url, options]) => String(url) === '/api/report-runs' && options?.method === 'POST',
      );
      expect(republishRequest).toBeTruthy();
      expect(JSON.parse(republishRequest[1].body)).toEqual(
        expect.objectContaining({
          case_id: '42',
          incident_id: '7',
          investigation_id: 'inv-7',
          source: 'case',
          kind: 'legacy_runtime_report',
        }),
      );
      expect(JSON.parse(republishRequest[1].body).preview_override).toEqual(
        expect.objectContaining({
          republished_from: expect.objectContaining({
            id: 101,
            report_type: 'legacy_runtime_report',
          }),
          execution_context: expect.objectContaining({
            case_id: '42',
            incident_id: '7',
            investigation_id: 'inv-7',
            source: 'case',
          }),
          report: legacyReportDetail.report,
        }),
      );
    });

    fireEvent.click(screen.getByRole('button', { name: 'Current Scope' }));
    const artifactCard = screen.getByText('Stored Report Artifacts').closest('.card');
    expect(artifactCard).toBeTruthy();
    expect(
      await within(artifactCard).findByText('Republished legacy runtime report #101'),
    ).toBeInTheDocument();
  });

  it('attaches execution context directly to a backend report', async () => {
    renderWithProviders('/reports?tab=runs&case=42&incident=7&investigation=inv-7&source=case');

    expect(await screen.findByText('Stored Report Artifacts')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Attach Current Scope' }));

    await waitFor(() => {
      const attachRequest = globalThis.fetch.mock.calls.find(
        ([url, options]) =>
          String(url) === '/api/reports/101/context' && options?.method === 'POST',
      );
      expect(attachRequest).toBeTruthy();
      expect(JSON.parse(attachRequest[1].body)).toEqual(
        expect.objectContaining({
          case_id: '42',
          incident_id: '7',
          investigation_id: 'inv-7',
          source: 'case',
        }),
      );
    });

    fireEvent.click(screen.getByRole('button', { name: 'Current Scope' }));
    await waitFor(() => {
      expect(
        globalThis.fetch.mock.calls.some(
          ([url]) =>
            String(url) ===
            '/api/reports?case_id=42&incident_id=7&investigation_id=inv-7&source=case&scope=scoped',
        ),
      ).toBe(true);
    });
    const artifactCard = screen.getByText('Stored Report Artifacts').closest('.card');
    expect(artifactCard).toBeTruthy();
    expect(
      await within(artifactCard).findByText('Context-Aware Backend Reports'),
    ).toBeInTheDocument();
    const scopedBackendRow = (
      await within(artifactCard).findByText('legacy_runtime_report')
    ).closest('tr');
    expect(scopedBackendRow).toBeTruthy();
    expect(within(scopedBackendRow).getByText('Case #42')).toBeInTheDocument();
    expect(within(artifactCard).queryByText('Attach Current Scope')).not.toBeInTheDocument();
  });

  it('exports filtered audit evidence as csv', async () => {
    renderWithProviders('/reports?tab=evidence');

    expect(await screen.findByText('Audit Log Evidence Export')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Search Query'), { target: { value: 'auth' } });
    fireEvent.change(screen.getByLabelText('HTTP Method'), { target: { value: 'GET' } });
    fireEvent.change(screen.getByLabelText('Status Filter'), { target: { value: '401' } });
    fireEvent.change(screen.getByLabelText('Auth State'), {
      target: { value: 'anonymous' },
    });
    fireEvent.click(screen.getByText('Download Audit CSV'));

    await waitFor(() => {
      expect(downloadData).toHaveBeenCalledWith(
        'timestamp,method,path,status_code,auth_used\n2026-04-21T12:00:00Z,GET,/api/auth/check,401,false\n',
        'audit-log-evidence.csv',
        'text/csv;charset=utf-8',
      );
    });

    expect(globalThis.fetch).toHaveBeenCalledWith(
      '/api/audit/log/export?q=auth&method=GET&status=401&auth=anonymous',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('pivots audit evidence workflows into retention controls', async () => {
    renderWithProviders('/reports?tab=evidence');

    expect(await screen.findByText('Audit Log Evidence Export')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('link', { name: 'Review Retention Controls' }));

    await waitFor(() => {
      const currentUrl = new URL(
        screen.getByTestId('location-probe').textContent || '/',
        'http://localhost',
      );
      expect(currentUrl.pathname).toBe('/settings');
      expect(currentUrl.searchParams.get('tab')).toBe('admin');
      expect(currentUrl.hash).toBe('#long-retention-history');
    });
  });

  it('runs a pii scan with the supplied sample text', async () => {
    renderWithProviders('/reports?tab=privacy');

    expect(await screen.findByText('PII Scan')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Sample Content'), {
      target: { value: 'alice@example.com connected from 203.0.113.42' },
    });
    fireEvent.click(screen.getByText('Run PII Scan'));

    expect(await screen.findByText('email, ip_address')).toBeInTheDocument();
    const piiRequest = globalThis.fetch.mock.calls.find(
      ([url, options]) => String(url) === '/api/pii/scan' && options?.method === 'POST',
    );
    expect(piiRequest).toBeTruthy();
    expect(piiRequest[1].body).toBe('alice@example.com connected from 203.0.113.42');
  });

  it('submits a gdpr erase request after confirmation', async () => {
    renderWithProviders('/reports?tab=privacy');

    expect(await screen.findByText('GDPR Right to Forget')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Entity Id'), {
      target: { value: 'user@example.com' },
    });
    fireEvent.change(screen.getByLabelText('Confirmation Phrase'), {
      target: { value: 'FORGET' },
    });
    fireEvent.click(screen.getByText('Submit Erase Request'));

    expect(await screen.findByText('Download Receipt')).toBeInTheDocument();
    expect(globalThis.fetch).toHaveBeenCalledWith(
      '/api/gdpr/forget/user%40example.com',
      expect.objectContaining({ method: 'DELETE' }),
    );
  });
});
