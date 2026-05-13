import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import SearchPalette from '../components/SearchPalette';
import { buildCommandHref } from '../components/workflowPivots.js';

// Mock the API module
vi.mock('../api', () => ({
  alerts: vi.fn().mockResolvedValue([]),
  incidents: vi.fn().mockResolvedValue([]),
  agents: vi.fn().mockResolvedValue([]),
  detectionRules: vi.fn().mockResolvedValue([]),
  feeds: vi.fn().mockResolvedValue([]),
}));

describe('SearchPalette', () => {
  const onClose = vi.fn();
  const onNavigate = vi.fn();

  beforeEach(() => {
    onClose.mockClear();
    onNavigate.mockClear();
    localStorage.clear();
  });

  it('renders nothing when closed', () => {
    const { container } = render(
      <SearchPalette open={false} onClose={onClose} onNavigate={onNavigate} />,
    );
    expect(container.querySelector('.search-palette')).not.toBeInTheDocument();
  });

  it('renders search input when open', () => {
    render(<SearchPalette open={true} onClose={onClose} onNavigate={onNavigate} />);
    expect(screen.getByPlaceholderText(/search/i)).toBeInTheDocument();
  });

  it('closes on ESC key', () => {
    render(<SearchPalette open={true} onClose={onClose} onNavigate={onNavigate} />);
    const input = screen.getByPlaceholderText(/search/i);
    fireEvent.keyDown(input, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledWith(false);
  });

  it('closes on backdrop click', () => {
    const { container } = render(
      <SearchPalette open={true} onClose={onClose} onNavigate={onNavigate} />,
    );
    const overlay = container.querySelector('.search-palette-overlay');
    if (overlay) fireEvent.click(overlay);
    expect(onClose).toHaveBeenCalledWith(false);
  });

  it('uses shared command routes for quick actions', () => {
    render(<SearchPalette open={true} onClose={onClose} onNavigate={onNavigate} />);

    fireEvent.click(screen.getByRole('button', { name: /Open Operator Launchpad/i }));

    expect(onNavigate).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'open-launchpad',
        path: buildCommandHref('open-launchpad'),
      }),
    );

    onNavigate.mockClear();
    onClose.mockClear();

    fireEvent.click(screen.getByRole('button', { name: /Create Incident/i }));

    expect(onNavigate).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'create-incident',
        path: buildCommandHref('create-incident'),
      }),
    );
    expect(onClose).toHaveBeenCalledWith(false);
  });

  it('includes operator trust quick actions', () => {
    render(<SearchPalette open={true} onClose={onClose} onNavigate={onNavigate} />);

    fireEvent.click(screen.getByRole('button', { name: /Start Detection Lab/i }));
    expect(onNavigate).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'start-detection-lab',
        path: '/detection-lab',
      }),
    );

    onNavigate.mockClear();
    fireEvent.click(screen.getByRole('button', { name: /Review Response Safety/i }));
    expect(onNavigate).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'review-response-safety',
        path: '/response-safety',
      }),
    );
  });

  it('surfaces connect, SOC, response, and deployment command destinations', () => {
    render(<SearchPalette open={true} onClose={onClose} onNavigate={onNavigate} />);

    fireEvent.click(screen.getByRole('button', { name: /Connect First Agent/i }));
    expect(onNavigate).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'connect-first-agent',
        path: buildCommandHref('connect-first-agent'),
      }),
    );

    onNavigate.mockClear();
    fireEvent.click(screen.getByRole('button', { name: /Open SOC Queue/i }));
    expect(onNavigate).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'open-soc-queue',
        path: buildCommandHref('open-soc-queue'),
      }),
    );

    onNavigate.mockClear();
    fireEvent.click(screen.getByRole('button', { name: /Response Readiness/i }));
    expect(onNavigate).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'response-readiness',
        path: buildCommandHref('response-readiness'),
      }),
    );

    onNavigate.mockClear();
    fireEvent.click(screen.getByRole('button', { name: /Deployment Confidence/i }));
    expect(onNavigate).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'deployment-confidence',
        path: buildCommandHref('deployment-confidence'),
      }),
    );
  });

  it('surfaces route-aware launchpad actions before the general command list', () => {
    render(
      <SearchPalette
        open={true}
        currentPath="/launchpad"
        onClose={onClose}
        onNavigate={onNavigate}
      />,
    );

    expect(screen.getByText('Launchpad actions')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Shift Handoff Workspace/i }));

    expect(onNavigate).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'shift-handoff-workspace',
        path: buildCommandHref('shift-handoff-workspace'),
      }),
    );

    onNavigate.mockClear();
    fireEvent.click(screen.getByRole('button', { name: /Morning Brief/i }));

    expect(onNavigate).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'morning-brief',
        path: buildCommandHref('morning-brief'),
      }),
    );

    onNavigate.mockClear();
    fireEvent.click(screen.getByRole('button', { name: /Visual Regression Gate/i }));

    expect(onNavigate).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'visual-regression-gate',
        path: buildCommandHref('visual-regression-gate'),
      }),
    );
  });
});
