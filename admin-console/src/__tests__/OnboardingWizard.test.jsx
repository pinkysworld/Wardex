import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import OnboardingWizard from '../components/OnboardingWizard.jsx';
import * as api from '../api.js';
import { copyTextToClipboard } from '../components/clipboard.js';

vi.mock('../api.js', () => ({
  onboardingReadiness: vi.fn().mockResolvedValue({
    ready: false,
    checks: [
      { key: 'first_agent_online', label: 'First agent online', ready: false },
      { key: 'telemetry_flowing', label: 'Telemetry flowing', ready: false },
    ],
  }),
  agentsToken: vi.fn().mockResolvedValue({
    token: 'enroll-token-1',
    expires_at: '2026-05-12T10:00:00Z',
    max_uses: 1,
    uses_remaining: 1,
  }),
  authCheck: vi.fn().mockResolvedValue({ ok: true }),
  createAuthSession: vi.fn().mockResolvedValue({ ok: true }),
  addFeed: vi.fn().mockResolvedValue({ ok: true }),
  getToken: vi.fn(() => 'existing-admin-token'),
  setToken: vi.fn(),
}));

vi.mock('../components/clipboard.js', () => ({
  copyTextToClipboard: vi.fn().mockResolvedValue(true),
}));

describe('OnboardingWizard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
  });

  it('creates and copies a first-agent enrollment command', async () => {
    render(<OnboardingWizard onComplete={vi.fn()} />);

    expect(screen.getByText('Set up the Wardex admin console')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Verify Token/i })).toBeDisabled();

    fireEvent.click(screen.getByRole('radio', { name: /Linux/i }));
    fireEvent.click(screen.getByRole('button', { name: /Create Token/i }));

    await waitFor(() => {
      expect(api.agentsToken).toHaveBeenCalledWith({ max_uses: 1, ttl_secs: 86400 });
    });

    expect(await screen.findByText(/Enrollment command ready/i)).toBeInTheDocument();
    const command = screen.getByText(/sudo \/tmp\/wardex-agent enroll/i);
    expect(command).toHaveTextContent("--token 'enroll-token-1'");
    expect(command).toHaveTextContent('--platform linux');

    fireEvent.click(screen.getByRole('button', { name: /Copy Command/i }));

    await waitFor(() => {
      expect(copyTextToClipboard).toHaveBeenCalledWith(expect.stringContaining('enroll-token-1'));
    });
  });
});
