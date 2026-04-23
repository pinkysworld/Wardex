import { describe, it, expect, beforeEach, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import AssistantWorkspace from '../components/AssistantWorkspace.jsx';
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

function renderWithProviders(ui, route = '/assistant') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <AuthProvider>
        <RoleProvider>
          <ThemeProvider>
            <ToastProvider>{ui}</ToastProvider>
          </ThemeProvider>
        </RoleProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe('AssistantWorkspace', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.clearAllMocks();
    localStorage.clear();
  });

  it('submits assistant queries with selected case context and renders citations', async () => {
    const fetchMock = vi.fn(async (url, options = {}) => {
      const href = String(url);
      const method = options?.method || 'GET';

      if (href.includes('/api/auth/session')) {
        return jsonOk({ authenticated: true, role: 'analyst' });
      }
      if (href.includes('/api/assistant/status')) {
        return jsonOk({
          enabled: false,
          provider: 'OpenAi',
          model: 'retrieval-only',
          has_api_key: false,
          active_conversations: 0,
          endpoint: 'https://example.invalid',
          mode: 'retrieval-only',
        });
      }
      if (href.includes('/api/cases') && method === 'GET') {
        return jsonOk({
          cases: [
            {
              id: 42,
              title: 'Identity escalation case',
              status: 'investigating',
              priority: 'high',
              assignee: 'analyst-1',
            },
          ],
        });
      }
      if (href.includes('/api/assistant/query') && method === 'POST') {
        return jsonOk({
          answer: 'Case #42 has two linked signals pointing to identity abuse.',
          citations: [
            {
              source_type: 'alert',
              source_id: '101',
              summary: 'Credential dumping observed on db-01',
              relevance_score: 0.91,
            },
          ],
          confidence: 0.65,
          model_used: 'retrieval-only',
          tokens_used: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
          response_time_ms: 12,
          conversation_id: 'local-42',
          mode: 'retrieval-only',
          warnings: ['LLM assistant is not configured; using retrieval-only synthesis'],
          case_context: {
            case: {
              id: 42,
              title: 'Identity escalation case',
              description: 'Review suspicious admin activity.',
              status: 'Investigating',
              priority: 'High',
              assignee: 'analyst-1',
              created_at: '2026-04-20T09:00:00Z',
              updated_at: '2026-04-20T09:30:00Z',
              incident_ids: [],
              event_ids: [101],
              tags: ['identity'],
              comments: [],
              evidence: [],
              mitre_techniques: [],
            },
            linked_events: [
              {
                id: '101',
                event_type: 'alert',
                summary: 'Credential dumping observed on db-01',
                severity: 'Critical',
                timestamp: '2026-04-20T09:20:00Z',
                device: 'db-01',
                raw_data: null,
                relevance: 0.91,
              },
            ],
          },
          context_events: [
            {
              id: '101',
              event_type: 'alert',
              summary: 'Credential dumping observed on db-01',
              severity: 'Critical',
              timestamp: '2026-04-20T09:20:00Z',
              device: 'db-01',
              raw_data: null,
              relevance: 0.91,
            },
          ],
        });
      }

      return jsonOk({});
    });
    vi.stubGlobal('fetch', fetchMock);

    renderWithProviders(<AssistantWorkspace />, '/assistant?case=42');

    expect(await screen.findByText('Analyst Assistant')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Question'), {
      target: { value: 'Summarize this case and cite the strongest evidence.' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Ask Assistant' }));

    expect((await screen.findAllByText(/Case #42 has two linked signals/i)).length).toBeGreaterThan(0);
    expect(await screen.findByText('Context & citations')).toBeInTheDocument();
    expect((await screen.findAllByText('Credential dumping observed on db-01')).length).toBeGreaterThan(0);
    expect(screen.getByRole('link', { name: 'Open Case in SOC' })).toHaveAttribute(
      'href',
      '/soc?case=42#cases',
    );

    await waitFor(() => {
      const queryCall = fetchMock.mock.calls.find(
        ([url, options]) =>
          String(url).includes('/api/assistant/query') && options?.method === 'POST',
      );
      expect(queryCall).toBeTruthy();
      expect(JSON.parse(queryCall[1].body)).toEqual(
        expect.objectContaining({
          question: 'Summarize this case and cite the strongest evidence.',
          case_id: 42,
        }),
      );
    });
  });

  it('preserves incident and investigation scope from the URL in assistant requests and pivots', async () => {
    const fetchMock = vi.fn(async (url, options = {}) => {
      const href = String(url);
      const method = options?.method || 'GET';

      if (href.includes('/api/auth/session')) {
        return jsonOk({ authenticated: true, role: 'analyst' });
      }
      if (href.includes('/api/assistant/status')) {
        return jsonOk({
          enabled: false,
          provider: 'OpenAi',
          model: 'retrieval-only',
          has_api_key: false,
          active_conversations: 0,
          endpoint: 'https://example.invalid',
          mode: 'retrieval-only',
        });
      }
      if (href.includes('/api/cases') && method === 'GET') {
        return jsonOk({
          cases: [
            {
              id: 42,
              title: 'Identity escalation case',
              status: 'investigating',
              priority: 'high',
              assignee: 'analyst-1',
            },
          ],
        });
      }
      if (href.includes('/api/incidents/7')) {
        return jsonOk({
          id: 7,
          title: 'Password spray incident',
          status: 'open',
          severity: 'high',
          assignee: 'analyst-1',
        });
      }
      if (href.includes('/api/investigations/active')) {
        return jsonOk({
          items: [
            {
              id: 'inv-7',
              workflow_id: 'credential-storm',
              workflow_name: 'Investigate Credential Storm',
              workflow_description: 'Step through identity abuse triage.',
              workflow_severity: 'high',
              mitre_techniques: ['T1110'],
              estimated_minutes: 30,
              case_id: '42',
              analyst: 'analyst-1',
              started_at: '2026-04-20T09:00:00Z',
              updated_at: '2026-04-20T09:30:00Z',
              completed_steps: [],
              notes: {},
              status: 'in-progress',
              findings: [],
              handoff: null,
              total_steps: 2,
              completion_percent: 0,
              next_step: null,
              steps: [],
              completion_criteria: [],
            },
          ],
        });
      }
      if (href.includes('/api/assistant/query') && method === 'POST') {
        return jsonOk({
          answer: 'Investigation inv-7 is still active and tied to the password spray incident.',
          citations: [],
          confidence: 0.54,
          model_used: 'retrieval-only',
          tokens_used: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
          response_time_ms: 11,
          conversation_id: 'local-99',
          mode: 'retrieval-only',
          warnings: [],
          case_context: null,
          context_events: [],
        });
      }

      return jsonOk({});
    });
    vi.stubGlobal('fetch', fetchMock);

    renderWithProviders(
      <AssistantWorkspace />,
      '/assistant?case=42&incident=7&investigation=inv-7&source=case',
    );

    expect(await screen.findByText('Active investigation scope')).toBeInTheDocument();
    expect(await screen.findByText('Password spray incident')).toBeInTheDocument();
    expect((await screen.findAllByText('Investigate Credential Storm')).length).toBeGreaterThan(0);
    expect(screen.getByRole('link', { name: 'Open Case Drawer' })).toHaveAttribute(
      'href',
      '/soc?case=42&drawer=case-workspace&casePanel=summary#cases',
    );
    expect(screen.getByRole('link', { name: 'Open Incident Drawer' })).toHaveAttribute(
      'href',
      '/soc?case=42&incident=7&source=case&drawer=incident-detail&incidentPanel=summary#cases',
    );
    expect(screen.getByRole('link', { name: 'Open Investigation' })).toHaveAttribute(
      'href',
      '/soc?case=42&investigation=inv-7&source=case#investigations',
    );

    fireEvent.change(screen.getByLabelText('Question'), {
      target: { value: 'Should we hand off this investigation?' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Ask Assistant' }));

    expect(
      (
        await screen.findAllByText(
          /Investigation inv-7 is still active and tied to the password spray incident/i,
        )
      ).length,
    ).toBeGreaterThan(0);

    await waitFor(() => {
      const queryCall = fetchMock.mock.calls.find(
        ([url, requestOptions]) =>
          String(url).includes('/api/assistant/query') && requestOptions?.method === 'POST',
      );
      expect(queryCall).toBeTruthy();
      expect(JSON.parse(queryCall[1].body)).toEqual(
        expect.objectContaining({
          question: 'Should we hand off this investigation?',
          case_id: 42,
          incident_id: 7,
          investigation_id: 'inv-7',
          source: 'case',
        }),
      );
    });
  });
});
