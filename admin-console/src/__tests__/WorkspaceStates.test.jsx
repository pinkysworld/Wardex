import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { WorkspaceEmptyState, WorkspaceErrorState } from '../components/operator.jsx';

describe('WorkspaceEmptyState', () => {
  it('renders a polite status region with title and description', () => {
    render(<WorkspaceEmptyState title="No alerts" description="Things are quiet right now." />);
    const region = screen.getByRole('status');
    expect(region).toHaveAttribute('aria-live', 'polite');
    expect(screen.getByText('No alerts')).toBeInTheDocument();
    expect(screen.getByText('Things are quiet right now.')).toBeInTheDocument();
  });

  it('renders action slots when provided', () => {
    render(
      <WorkspaceEmptyState
        title="No alerts"
        actions={<button type="button">Create rule</button>}
      />,
    );
    expect(screen.getByRole('button', { name: 'Create rule' })).toBeInTheDocument();
  });
});

describe('WorkspaceErrorState', () => {
  it('renders an assertive alert region with the error message', () => {
    render(<WorkspaceErrorState error={{ message: 'boom' }} />);
    const region = screen.getByRole('alert');
    expect(region).toHaveAttribute('aria-live', 'assertive');
    expect(screen.getByText('boom')).toBeInTheDocument();
  });

  it('exposes the request id when it is attached to the error', () => {
    render(<WorkspaceErrorState error={{ message: 'boom', requestId: 'req-42' }} />);
    expect(screen.getByText(/req-42/)).toBeInTheDocument();
  });

  it('falls back to a generic message when no description or error is supplied', () => {
    render(<WorkspaceErrorState />);
    expect(
      screen.getByText('The workspace could not load the requested data.'),
    ).toBeInTheDocument();
  });

  it('invokes onRetry when the retry button is clicked', async () => {
    const user = userEvent.setup();
    const onRetry = vi.fn();
    render(<WorkspaceErrorState error={{ message: 'boom' }} onRetry={onRetry} />);
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});
