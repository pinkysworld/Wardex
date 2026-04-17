import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { ToastProvider, ThemeProvider } from '../hooks.jsx';
import ThreatDetection from '../components/ThreatDetection.jsx';
import Infrastructure from '../components/Infrastructure.jsx';
import ReportsExports from '../components/ReportsExports.jsx';
import HelpDocs from '../components/HelpDocs.jsx';

globalThis.fetch = vi.fn();

beforeEach(() => {
  vi.clearAllMocks();
  globalThis.fetch.mockImplementation(async (url) => ({
    ok: true,
    headers: { get: () => 'application/json' },
    json: async () => {
      if (String(url).includes('/api/content/rules'))
        return {
          rules: [
            {
              id: 'rule-1',
              title: 'Suspicious PowerShell',
              lifecycle: 'test',
              enabled: true,
              attack: [],
              owner: 'secops',
              last_test_match_count: 2,
            },
          ],
        };
      if (String(url).includes('/api/report-templates'))
        return {
          templates: [
            {
              id: 'tpl-1',
              name: 'Executive Status',
              kind: 'executive_status',
              scope: 'global',
              format: 'json',
              status: 'ready',
              audience: 'executive',
              description: 'Leadership snapshot',
            },
          ],
        };
      if (String(url).includes('/api/inbox')) return { items: [] };
      return {};
    },
  }));
});

function renderWithProviders(node, route = '/') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <ThemeProvider>
        <ToastProvider>{node}</ToastProvider>
      </ThemeProvider>
    </MemoryRouter>,
  );
}

describe('workspace shells', () => {
  it('renders the detection workspace shell', async () => {
    renderWithProviders(<ThreatDetection />, '/detection');
    expect(await screen.findByText('Detection Engineering Workspace')).toBeInTheDocument();
  });

  it('renders the infrastructure explorer shell', async () => {
    renderWithProviders(<Infrastructure />, '/infrastructure');
    expect(await screen.findByText('Attention Queues')).toBeInTheDocument();
  });

  it('renders the report center shell', async () => {
    renderWithProviders(<ReportsExports />, '/reports');
    expect(await screen.findByText('Report Center')).toBeInTheDocument();
  });

  it('renders contextual support shell', async () => {
    renderWithProviders(<HelpDocs />, '/help');
    expect(await screen.findByText('Operator Support')).toBeInTheDocument();
  });
});
