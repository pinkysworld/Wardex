import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import ErrorBoundary from '../components/ErrorBoundary';

function ThrowingChild({ shouldThrow }) {
  if (shouldThrow) throw new Error('Test explosion');
  return <div>All good</div>;
}

describe('ErrorBoundary', () => {
  afterEach(() => {
    delete window.navigator.clipboard;
    window.history.replaceState({}, '', '/');
  });

  it('renders children when no error', () => {
    render(
      <ErrorBoundary>
        <div>Safe content</div>
      </ErrorBoundary>,
    );
    expect(screen.getByText('Safe content')).toBeInTheDocument();
  });

  it('renders error UI when child throws and moves focus to the alert', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    render(
      <ErrorBoundary>
        <ThrowingChild shouldThrow />
      </ErrorBoundary>,
    );
    const alert = screen.getByRole('alert');
    expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
    expect(screen.getByText(/Test explosion/)).toBeInTheDocument();
    await waitFor(() => expect(alert).toHaveFocus());
    spy.mockRestore();
  });

  it('recovers when Try Again is clicked', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    let shouldThrow = true;
    function Child() {
      if (shouldThrow) throw new Error('boom');
      return <div>Recovered</div>;
    }

    const { rerender } = render(
      <ErrorBoundary>
        <Child />
      </ErrorBoundary>,
    );
    expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();

    shouldThrow = false;
    fireEvent.click(screen.getByText(/try again/i));

    rerender(
      <ErrorBoundary>
        <Child />
      </ErrorBoundary>,
    );
    expect(screen.getByText('Recovered')).toBeInTheDocument();
    spy.mockRestore();
  });

  it('copies a diagnostic report with route context', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(window.navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    window.history.replaceState({}, '', '/monitor?eventType=alert');

    render(
      <ErrorBoundary>
        <ThrowingChild shouldThrow />
      </ErrorBoundary>,
    );

    fireEvent.click(screen.getByRole('button', { name: /copy error report/i }));

    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    expect(writeText.mock.calls[0][0]).toContain('Wardex admin console error report');
    expect(writeText.mock.calls[0][0]).toContain('Message: Test explosion');
    expect(writeText.mock.calls[0][0]).toContain('Route: /monitor?eventType=alert');
    await waitFor(() =>
      expect(screen.getByText(/error report copied to the clipboard/i)).toBeInTheDocument(),
    );
    spy.mockRestore();
  });

  it('refreshes the return focus target for later crashes', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    let shouldThrow = false;

    function Child() {
      if (shouldThrow) throw new Error('boom');
      return <div>Recovered</div>;
    }

    const { rerender } = render(
      <>
        <button type="button">First trigger</button>
        <button type="button">Second trigger</button>
        <ErrorBoundary>
          <Child />
        </ErrorBoundary>
      </>,
    );

    const firstTrigger = screen.getByRole('button', { name: 'First trigger' });
    const secondTrigger = screen.getByRole('button', { name: 'Second trigger' });

    firstTrigger.focus();
    shouldThrow = true;
    rerender(
      <>
        <button type="button">First trigger</button>
        <button type="button">Second trigger</button>
        <ErrorBoundary>
          <Child />
        </ErrorBoundary>
      </>,
    );

    await waitFor(() => expect(screen.getByRole('alert')).toHaveFocus());

    shouldThrow = false;
    fireEvent.click(screen.getByRole('button', { name: /try again/i }));

    await waitFor(() => expect(firstTrigger).toHaveFocus());

    secondTrigger.focus();
    shouldThrow = true;
    rerender(
      <>
        <button type="button">First trigger</button>
        <button type="button">Second trigger</button>
        <ErrorBoundary>
          <Child />
        </ErrorBoundary>
      </>,
    );

    await waitFor(() => expect(screen.getByRole('alert')).toHaveFocus());

    shouldThrow = false;
    fireEvent.click(screen.getByRole('button', { name: /try again/i }));

    await waitFor(() => expect(secondTrigger).toHaveFocus());
    spy.mockRestore();
  });
});
