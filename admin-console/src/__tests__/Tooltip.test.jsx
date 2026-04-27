import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import Tooltip from '../components/Tooltip';

describe('Tooltip', () => {
  it('renders trigger with default icon', () => {
    render(<Tooltip text="Helpful info" />);
    expect(screen.getByRole('button', { name: 'More information' })).toBeInTheDocument();
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
    expect(screen.getByRole('tooltip')).toHaveTextContent('Secret tip');
  });

  it('shows tooltip when the default trigger is clicked', () => {
    render(<Tooltip text="Click tip" />);
    const trigger = screen.getByRole('button', { name: 'More information' });

    fireEvent.click(trigger);

    expect(screen.getByRole('tooltip')).toHaveTextContent('Click tip');
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

  it('exposes tooltip content on keyboard focus and hides it with Escape', () => {
    render(<Tooltip text="Keyboard tip" />);
    const trigger = screen.getByRole('button', { name: 'More information' });

    fireEvent.focus(trigger);

    const tooltip = screen.getByRole('tooltip');
    expect(tooltip).toHaveTextContent('Keyboard tip');
    expect(trigger).toHaveAttribute('aria-describedby', tooltip.id);

    fireEvent.keyDown(trigger, { key: 'Escape' });
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
  });

  it('passes accessible tooltip wiring to custom trigger children', () => {
    render(
      <Tooltip text="Custom child tip">
        <button>Hover me</button>
      </Tooltip>,
    );
    const trigger = screen.getByRole('button', { name: 'Hover me' });

    fireEvent.focus(trigger);

    const tooltip = screen.getByRole('tooltip');
    expect(tooltip).toHaveTextContent('Custom child tip');
    expect(trigger).toHaveAttribute('aria-describedby', tooltip.id);
  });
});
