import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ConfirmDialog } from '../components/operator.jsx';

describe('ConfirmDialog', () => {
  it('does not render when open is false', () => {
    render(
      <ConfirmDialog
        open={false}
        title="Delete?"
        message="This is permanent."
        onConfirm={() => {}}
        onCancel={() => {}}
      />,
    );
    expect(screen.queryByText('Delete?')).not.toBeInTheDocument();
  });

  it('renders title and message when open', () => {
    render(
      <ConfirmDialog
        open={true}
        title="Remove agent?"
        message="This cannot be undone."
        onConfirm={() => {}}
        onCancel={() => {}}
      />,
    );
    expect(screen.getByText('Remove agent?')).toBeInTheDocument();
    expect(screen.getByText('This cannot be undone.')).toBeInTheDocument();
  });

  it('calls onConfirm when confirm button is clicked', () => {
    const onConfirm = vi.fn();
    render(
      <ConfirmDialog
        open={true}
        title="Confirm"
        message="Are you sure?"
        confirmLabel="Yes, delete"
        onConfirm={onConfirm}
        onCancel={() => {}}
      />,
    );
    fireEvent.click(screen.getByText('Yes, delete'));
    expect(onConfirm).toHaveBeenCalledOnce();
  });

  it('calls onCancel when cancel button is clicked', () => {
    const onCancel = vi.fn();
    render(
      <ConfirmDialog
        open={true}
        title="Confirm"
        message="Are you sure?"
        onConfirm={() => {}}
        onCancel={onCancel}
      />,
    );
    fireEvent.click(screen.getByText('Cancel'));
    expect(onCancel).toHaveBeenCalledOnce();
  });

  it('has accessible dialog attributes', () => {
    render(
      <ConfirmDialog
        open={true}
        title="Accessible dialog"
        message="Check aria."
        onConfirm={() => {}}
        onCancel={() => {}}
      />,
    );
    const dialog = screen.getByRole('alertdialog');
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(dialog).toHaveAttribute('aria-labelledby', 'confirm-dialog-title');
  });

  it('closes on Escape key', () => {
    const onCancel = vi.fn();
    render(
      <ConfirmDialog
        open={true}
        title="Escape test"
        message="Press escape."
        onConfirm={() => {}}
        onCancel={onCancel}
      />,
    );
    fireEvent.keyDown(screen.getByRole('alertdialog'), { key: 'Escape' });
    expect(onCancel).toHaveBeenCalledOnce();
  });
});
