import React, { useEffect, useRef } from 'react';

/**
 * ConfirmDialog — accessible replacement for window.confirm().
 *
 * Preferred usage via useConfirm():
 *   const [confirm, confirmUI] = useConfirm();
 *   if (!(await confirm({ title: 'Delete?', tone: 'danger' }))) return;
 *   return <>{confirmUI}...</>;
 */
export default function ConfirmDialog({ state, onClose }) {
  const dialogRef = useRef(null);
  const confirmBtnRef = useRef(null);

  useEffect(() => {
    if (!state) return undefined;
    const previous = document.activeElement;
    requestAnimationFrame(() => confirmBtnRef.current?.focus());
    const onKey = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose(false);
      } else if (e.key === 'Tab') {
        const focusables = dialogRef.current?.querySelectorAll(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
        );
        if (!focusables || focusables.length === 0) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener('keydown', onKey);
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = '';
      if (previous && typeof previous.focus === 'function') previous.focus();
    };
  }, [state, onClose]);

  if (!state) return null;
  const {
    title = 'Are you sure?',
    message = '',
    confirmLabel = 'Confirm',
    cancelLabel = 'Cancel',
    tone = 'default',
    onConfirm,
  } = state;

  const handleConfirm = () => {
    try {
      onConfirm?.();
    } finally {
      onClose(true);
    }
  };

  const toneClass =
    tone === 'danger'
      ? 'confirm-btn confirm-btn-danger'
      : tone === 'warning'
        ? 'confirm-btn confirm-btn-warning'
        : 'confirm-btn confirm-btn-primary';

  return (
    <div className="confirm-backdrop" onClick={() => onClose(false)} role="presentation">
      <div
        ref={dialogRef}
        className="confirm-dialog"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-title"
        aria-describedby="confirm-message"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 id="confirm-title" className="confirm-title">
          {title}
        </h2>
        {message && (
          <p id="confirm-message" className="confirm-message">
            {message}
          </p>
        )}
        <div className="confirm-actions">
          <button
            type="button"
            className="confirm-btn confirm-btn-ghost"
            onClick={() => onClose(false)}
          >
            {cancelLabel}
          </button>
          <button type="button" ref={confirmBtnRef} className={toneClass} onClick={handleConfirm}>
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
