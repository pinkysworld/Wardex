import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthProvider, RoleProvider, ThemeProvider, ToastProvider } from '../hooks.jsx';
import ProcessDrawer from '../components/ProcessDrawer.jsx';

function jsonOk(data) {
  return {
    ok: true,
    status: 200,
    headers: { get: (header) => (header === 'content-type' ? 'application/json' : null) },
    json: async () => data,
    text: async () => JSON.stringify(data),
  };
}

function renderWithProviders(node) {
  return render(
    <AuthProvider>
      <RoleProvider>
        <ThemeProvider>
          <ToastProvider>{node}</ToastProvider>
        </ThemeProvider>
      </RoleProvider>
    </AuthProvider>,
  );
}

describe('ProcessDrawer', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    globalThis.fetch = vi.fn((url) => {
      const href = String(url);

      if (href.includes('/api/auth/check')) return Promise.resolve(jsonOk({ authenticated: true }));
      if (href.includes('/api/auth/session')) {
        return Promise.resolve(
          jsonOk({
            authenticated: true,
            role: 'analyst',
            user_id: 'analyst-1',
            groups: ['soc-analysts'],
            source: 'session',
          }),
        );
      }
      if (href.includes('/api/processes/detail')) {
        return Promise.resolve(
          jsonOk({
            pid: 4242,
            ppid: 321,
            name: '/usr/bin/python3',
            display_name: 'python3',
            user: 'analyst',
            group: 'staff',
            cpu_percent: 12.4,
            mem_percent: 3.2,
            hostname: 'edge-1',
            platform: 'macos',
            cmd_line: '/usr/bin/python3 suspicious.py',
            exe_path: '/usr/bin/python3',
            cwd: '/tmp',
            start_time: '2026-04-27T10:00:00Z',
            elapsed: '5m',
            risk_level: 'severe',
            findings: [
              {
                pid: 4242,
                name: 'python3',
                user: 'analyst',
                risk_level: 'severe',
                reason: 'Suspicious parent chain',
                cpu_percent: 12.4,
                mem_percent: 3.2,
              },
            ],
            analysis: {
              self_process: false,
              listener_count: 1,
              recommendations: ['Inspect parent lineage before isolation.'],
            },
            network_activity: [{ protocol: 'tcp', endpoint: '10.0.0.1:443', state: 'established' }],
          }),
        );
      }
      if (href.includes('/api/process-tree/deep-chains')) {
        return Promise.resolve(
          jsonOk({
            deep_chains: [
              {
                pid: 4242,
                name: 'python3',
                cmd_line: '/usr/bin/python3 suspicious.py',
                depth: 4,
              },
            ],
          }),
        );
      }
      if (href.includes('/api/processes/threads')) {
        return Promise.resolve(
          jsonOk({
            pid: 4242,
            platform: 'macos',
            identifier_type: 'row_slot',
            note: 'macOS exposes real per-thread rows here, but thread IDs are collection-time row slots.',
            thread_count: 3,
            running_count: 1,
            sleeping_count: 1,
            blocked_count: 1,
            hot_thread_count: 1,
            top_cpu_percent: 12.5,
            wait_reason_count: 1,
            hot_threads: [
              {
                thread_id: 1,
                state: 'R',
                state_label: 'running',
                priority: '47T',
                cpu_percent: 12.5,
                system_time: '0:00.20',
                user_time: '0:00.45',
                wait_reason: null,
              },
            ],
            blocked_threads: [
              {
                thread_id: 2,
                state: 'D',
                state_label: 'blocked',
                priority: '37T',
                cpu_percent: 0.2,
                system_time: '0:00.01',
                user_time: '0:00.03',
                wait_reason: 'futex_wait_queue_me',
              },
            ],
            threads: [
              {
                thread_id: 1,
                state: 'R',
                state_label: 'running',
                priority: '47T',
                cpu_percent: 12.5,
                system_time: '0:00.20',
                user_time: '0:00.45',
                wait_reason: null,
              },
              {
                thread_id: 2,
                state: 'D',
                state_label: 'blocked',
                priority: '37T',
                cpu_percent: 0.2,
                system_time: '0:00.01',
                user_time: '0:00.03',
                wait_reason: 'futex_wait_queue_me',
              },
              {
                thread_id: 3,
                state: 'S',
                state_label: 'sleeping',
                priority: '37T',
                cpu_percent: 0.0,
                system_time: '0:00.00',
                user_time: '0:00.01',
                wait_reason: null,
              },
            ],
          }),
        );
      }
      if (href.includes('/api/process-tree')) {
        return Promise.resolve(
          jsonOk({
            processes: [
              { pid: 1, ppid: 0, name: 'launchd', user: 'root' },
              { pid: 321, ppid: 1, name: 'bash', user: 'analyst' },
              { pid: 4242, ppid: 321, name: 'python3', user: 'analyst' },
              { pid: 5252, ppid: 4242, name: 'curl', user: 'analyst' },
              { pid: 6262, ppid: 321, name: 'osascript', user: 'analyst' },
            ],
          }),
        );
      }

      return Promise.resolve(jsonOk({}));
    });
  });

  it('renders lineage, deep-chain context, and related-process pivots', async () => {
    const onSelectProcess = vi.fn();

    renderWithProviders(
      <ProcessDrawer
        pid={4242}
        onClose={() => {}}
        onUpdated={() => {}}
        onSelectProcess={onSelectProcess}
      />,
    );

    expect(await screen.findByText('Investigation Context')).toBeInTheDocument();
    expect(screen.getByText('Deep-chain summary')).toBeInTheDocument();
    expect(screen.getByText('Lineage')).toBeInTheDocument();
    expect(screen.getByText('launchd (PID 1)')).toBeInTheDocument();
    expect(screen.getByText('bash (PID 321)')).toBeInTheDocument();
    expect(screen.getByText('python3 (PID 4242)')).toBeInTheDocument();
    expect(screen.getByText(/Matched a deep process chain with depth 4/i)).toBeInTheDocument();
    expect(screen.getByText('Thread Activity')).toBeInTheDocument();
    expect(screen.getByText('Peak Thread CPU')).toBeInTheDocument();
    expect(
      screen.getByText(
        'macOS exposes real per-thread rows here, but thread IDs are collection-time row slots.',
      ),
    ).toBeInTheDocument();
    expect(screen.getAllByText('12.5%').length).toBeGreaterThan(0);
    expect(screen.getByText(/Hottest threads: T1 12.5%/i)).toBeInTheDocument();
    expect(
      screen.getByText(/Blocked threads: T2 waiting on futex_wait_queue_me/i),
    ).toBeInTheDocument();
    expect(screen.getAllByText('futex_wait_queue_me').length).toBeGreaterThan(0);
    expect(screen.getByText('0:00.20 / 0:00.45')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Inspect bash' }));

    await waitFor(() => {
      expect(onSelectProcess).toHaveBeenCalledWith(expect.objectContaining({ pid: 321 }));
    });

    expect(screen.getByRole('button', { name: 'Inspect curl' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Inspect osascript' })).toBeInTheDocument();
  });
});
