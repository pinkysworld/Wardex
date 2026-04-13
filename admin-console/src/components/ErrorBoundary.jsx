import { Component } from 'react';

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('[Wardex ErrorBoundary]', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div role="alert" className="error-boundary" style={{
          padding: '2rem',
          margin: '2rem',
          border: '1px solid var(--color-danger, #e74c3c)',
          borderRadius: '8px',
          background: 'var(--bg-surface, #fff1f0)',
        }}>
          <h2>Something went wrong</h2>
          <p>An unexpected error occurred in the Wardex admin console.</p>
          <pre style={{ overflow: 'auto', maxHeight: '200px', fontSize: '0.85rem' }}>
            {this.state.error?.message || 'Unknown error'}
          </pre>
          <button
            onClick={() => { this.setState({ hasError: false, error: null }); }}
            style={{ marginTop: '1rem', padding: '0.5rem 1rem', cursor: 'pointer' }}
          >
            Try Again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
