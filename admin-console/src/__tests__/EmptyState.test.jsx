import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import EmptyState from '../components/EmptyState.jsx';

describe('EmptyState', () => {
  it('renders default title', () => {
    render(<EmptyState />);
    expect(screen.getByText('Nothing here yet')).toBeInTheDocument();
  });

  it('renders custom title and message', () => {
    render(<EmptyState title="No results" message="Try a different search." />);
    expect(screen.getByText('No results')).toBeInTheDocument();
    expect(screen.getByText('Try a different search.')).toBeInTheDocument();
  });

  it('renders icon when provided', () => {
    render(<EmptyState icon="🔍" title="Empty" />);
    expect(screen.getByText('🔍')).toBeInTheDocument();
  });

  it('renders primary CTA button', () => {
    const onClick = vi.fn();
    render(<EmptyState title="No items" primaryCta={{ label: 'Add Item', onClick }} />);
    const btn = screen.getByText('Add Item');
    expect(btn).toBeInTheDocument();
    fireEvent.click(btn);
    expect(onClick).toHaveBeenCalledOnce();
  });

  it('renders primary CTA as link when href is provided', () => {
    render(<EmptyState title="No docs" primaryCta={{ label: 'View Docs', href: '/docs' }} />);
    const link = screen.getByText('View Docs');
    expect(link.tagName).toBe('A');
    expect(link).toHaveAttribute('href', '/docs');
  });

  it('renders secondary CTA alongside primary', () => {
    render(
      <EmptyState
        title="Empty"
        primaryCta={{ label: 'Create', onClick: () => {} }}
        secondaryCta={{ label: 'Import', onClick: () => {} }}
      />,
    );
    expect(screen.getByText('Create')).toBeInTheDocument();
    expect(screen.getByText('Import')).toBeInTheDocument();
  });

  it('applies compact class when compact prop is true', () => {
    const { container } = render(<EmptyState compact title="Compact" />);
    expect(container.querySelector('.empty-state-compact')).toBeInTheDocument();
  });

  it('has role="status" for accessibility', () => {
    render(<EmptyState title="Accessible" />);
    expect(screen.getByRole('status')).toBeInTheDocument();
  });
});
