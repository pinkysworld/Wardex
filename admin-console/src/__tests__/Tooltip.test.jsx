import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import Tooltip from '../components/Tooltip';

describe('Tooltip', () => {
  it('renders trigger with default icon', () => {
    render(<Tooltip text="Helpful info" />);
    expect(screen.getByText('ⓘ')).toBeInTheDocument();
  });

  it('renders custom trigger children', () => {
    render(
      <Tooltip text="Details">
        <button>Hover me</button>
      </Tooltip>,
    );
    expect(screen.getByText('Hover me')).toBeInTheDocument();
  });

  it('shows tooltip on mouse enter', () => {
    render(<Tooltip text="Secret tip" />);
    const trigger =
      screen.getByText('ⓘ').closest('.tooltip-trigger') || screen.getByText('ⓘ').parentElement;
    fireEvent.mouseEnter(trigger);
    expect(screen.getByText('Secret tip')).toBeInTheDocument();
  });

  it('hides tooltip on mouse leave', () => {
    render(<Tooltip text="Vanishing tip" />);
    const trigger =
      screen.getByText('ⓘ').closest('.tooltip-trigger') || screen.getByText('ⓘ').parentElement;
    fireEvent.mouseEnter(trigger);
    expect(screen.getByText('Vanishing tip')).toBeInTheDocument();
    fireEvent.mouseLeave(trigger);
    expect(screen.queryByText('Vanishing tip')).not.toBeInTheDocument();
  });
});
