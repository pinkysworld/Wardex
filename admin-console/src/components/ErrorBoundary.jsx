import { Component, createRef } from 'react';

import { copyTextToClipboard } from './clipboard';

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      copyState: 'idle',
    };
    this.alertRef = createRef();
    this.previousActiveElement = null;

    this.handleReset = this.handleReset.bind(this);
    this.handleCopyReport = this.handleCopyReport.bind(this);
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidUpdate(_prevProps, prevState) {
    if (!prevState.hasError && this.state.hasError) {
      this.capturePreviousFocus();
      this.focusAlert();
    }
  }

  componentDidCatch(error, errorInfo) {
    console.error('[Wardex ErrorBoundary]', error, errorInfo);
    this.capturePreviousFocus();
    this.focusAlert();
    this.setState({ errorInfo });
  }

  capturePreviousFocus() {
    if (
      typeof document !== 'undefined' &&
      this.previousActiveElement == null &&
      document.activeElement instanceof HTMLElement
    ) {
      this.previousActiveElement = document.activeElement;
    }
  }

  focusAlert() {
    if (typeof queueMicrotask === 'function') {
      queueMicrotask(() => this.alertRef.current?.focus());
      return;
    }
    Promise.resolve().then(() => this.alertRef.current?.focus());
  }

  handleReset() {
    const focusTarget = this.previousActiveElement;
    this.setState(
      {
        hasError: false,
        error: null,
        errorInfo: null,
        copyState: 'idle',
      },
      () => {
        if (
          focusTarget instanceof HTMLElement &&
          typeof focusTarget.focus === 'function' &&
          document.contains(focusTarget)
        ) {
          focusTarget.focus();
        }
        this.previousActiveElement = null;
      },
    );
  }

  buildReport() {
    const route =
      typeof window === 'undefined'
        ? 'unknown'
        : `${window.location.pathname}${window.location.search}${window.location.hash}`;
    const userAgent = typeof navigator === 'undefined' ? 'unknown' : navigator.userAgent || 'unknown';
    const componentStack = this.state.errorInfo?.componentStack?.trim();

    return [
      'Wardex admin console error report',
      `Message: ${this.state.error?.message || 'Unknown error'}`,
      `Route: ${route}`,
      `User agent: ${userAgent}`,
      componentStack ? `Component stack:\n${componentStack}` : '',
      this.state.error?.stack ? `Stack:\n${this.state.error.stack}` : '',
    ]
      .filter(Boolean)
      .join('\n\n');
  }

  async handleCopyReport() {
    const copied = await copyTextToClipboard(this.buildReport());
    this.setState({ copyState: copied ? 'copied' : 'failed' });
  }

  render() {
    if (this.state.hasError) {
      const copyStatusMessage =
        this.state.copyState === 'copied'
          ? 'Error report copied to the clipboard.'
          : this.state.copyState === 'failed'
            ? 'Unable to copy the error report from this browser session.'
            : '';

      return (
        <div
          role="alert"
          className="error-boundary"
          ref={this.alertRef}
          tabIndex={-1}
          aria-live="assertive"
          aria-labelledby="error-boundary-title"
          aria-describedby="error-boundary-description error-boundary-copy-status"
          style={{
            padding: '2rem',
            margin: '2rem',
            border: '1px solid var(--color-danger, #e74c3c)',
            borderRadius: '8px',
            background: 'var(--bg-surface, #fff1f0)',
          }}
        >
          <h2 id="error-boundary-title">Something went wrong</h2>
          <p id="error-boundary-description">
            An unexpected error occurred in the Wardex admin console. Retry the section or
            copy the diagnostic report before escalating it.
          </p>
          <pre style={{ overflow: 'auto', maxHeight: '200px', fontSize: '0.85rem' }}>
            {this.state.error?.message || 'Unknown error'}
          </pre>
          <div className="btn-group" style={{ marginTop: '1rem' }}>
            <button type="button" className="btn btn-sm btn-primary" onClick={this.handleReset}>
              Try Again
            </button>
            <button type="button" className="btn btn-sm" onClick={this.handleCopyReport}>
              Copy Error Report
            </button>
          </div>
          <div
            id="error-boundary-copy-status"
            className="hint"
            aria-live="polite"
            style={{ marginTop: '0.75rem' }}
          >
            {copyStatusMessage || 'Captured report includes the route, component stack, and error details.'}
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
