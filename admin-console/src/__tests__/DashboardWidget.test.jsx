import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import DashboardWidget from '../components/DashboardWidget';

describe('DashboardWidget', () => {
  it('renders title and children', () => {
    render(
      <DashboardWidget id="w1" title="My Widget">
        <p>Widget content</p>
      </DashboardWidget>,
    );
    expect(screen.getByText('My Widget')).toBeInTheDocument();
    expect(screen.getByText('Widget content')).toBeInTheDocument();
  });

  it('toggles collapse on button click', () => {
    render(
      <DashboardWidget id="w2" title="Collapsible">
        <p>Visible content</p>
      </DashboardWidget>,
    );
    expect(screen.getByText('Visible content')).toBeInTheDocument();

    // Find and click the collapse toggle
    const toggleBtn = screen.queryByText('▾') || screen.getByText('▸');
    fireEvent.click(toggleBtn);
    expect(screen.queryByText('Visible content')).not.toBeInTheDocument();
  });

  it('starts collapsed when collapsed prop is true', () => {
    render(
      <DashboardWidget id="w3" title="Hidden" collapsed>
        <p>Hidden content</p>
      </DashboardWidget>,
    );
    // The expand icon should be visible
    expect(screen.getByText('▸')).toBeInTheDocument();
  });

  it('calls onRemove when remove button clicked', () => {
    const onRemove = vi.fn();
    render(
      <DashboardWidget id="w4" title="Removable" onRemove={onRemove}>
        <p>Content</p>
      </DashboardWidget>,
    );
    const removeBtn = screen.getByText('✕');
    fireEvent.click(removeBtn);
    expect(onRemove).toHaveBeenCalledWith('w4');
  });

  it('does not render remove button without onRemove', () => {
    render(
      <DashboardWidget id="w5" title="No Remove">
        <p>Content</p>
      </DashboardWidget>,
    );
    expect(screen.queryByText('✕')).not.toBeInTheDocument();
  });
});
