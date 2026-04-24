import { useEffect, useRef } from 'react';
import { formatLabel, formatValue } from './operatorUtils.js';

function previewObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return Object.entries(value)
    .filter(([, inner]) => inner == null || typeof inner !== 'object')
    .slice(0, 3);
}

function isPrimitive(value) {
  return value == null || typeof value !== 'object';
}

function collectionSummary(value) {
  if (Array.isArray(value)) return `${value.length} item${value.length === 1 ? '' : 's'}`;
  if (value && typeof value === 'object')
    return `${Object.keys(value).length} field${Object.keys(value).length === 1 ? '' : 's'}`;
  return formatValue(value);
}

function itemPreview(value) {
  if (isPrimitive(value)) return formatValue(value);
  if (Array.isArray(value)) return collectionSummary(value);
  const preview = previewObject(value);
  if (!preview || preview.length === 0) return collectionSummary(value);
  return preview
    .map(([key, innerValue]) => `${formatLabel(key)}: ${formatValue(innerValue)}`)
    .join(' · ');
}

function StructuredInspector({ data, depth = 0 }) {
  if (data == null) return <div className="empty">No additional fields available.</div>;

  if (isPrimitive(data)) {
    return (
      <div className="inspector-leaf">{typeof data === 'string' ? data : formatValue(data)}</div>
    );
  }

  if (Array.isArray(data)) {
    if (data.length === 0) return <div className="empty">No items available.</div>;

    const visibleItems = data.slice(0, 12);
    const hiddenCount = data.length - visibleItems.length;

    if (visibleItems.every(isPrimitive)) {
      return (
        <div>
          <div className="chip-row">
            {visibleItems.map((item, index) => (
              <span key={`${String(item)}-${index}`} className="badge badge-info">
                {typeof item === 'string' ? item : formatValue(item)}
              </span>
            ))}
          </div>
          {hiddenCount > 0 && (
            <div className="hint" style={{ marginTop: 8 }}>
              {hiddenCount} more item{hiddenCount === 1 ? '' : 's'} hidden to keep this view
              readable.
            </div>
          )}
        </div>
      );
    }

    return (
      <div className="inspector-stack">
        {visibleItems.map((item, index) => (
          <details
            key={item?.id ?? `item-${index}`}
            className="inspector-section"
            open={depth === 0 && index < 2}
          >
            <summary>
              Item {index + 1}
              <span>{itemPreview(item)}</span>
            </summary>
            <div className="inspector-content">
              <StructuredInspector data={item} depth={depth + 1} />
            </div>
          </details>
        ))}
        {hiddenCount > 0 && (
          <div className="hint">
            {hiddenCount} more complex item{hiddenCount === 1 ? '' : 's'} hidden to keep this panel
            responsive.
          </div>
        )}
      </div>
    );
  }

  const entries = Object.entries(data);
  if (entries.length === 0) return <div className="empty">No additional fields available.</div>;

  const scalarEntries = entries.filter(([, value]) => isPrimitive(value));
  const complexEntries = entries.filter(([, value]) => !isPrimitive(value));
  const visibleComplexEntries = complexEntries.slice(0, 12);
  const hiddenComplexCount = complexEntries.length - visibleComplexEntries.length;

  return (
    <div className="inspector-stack">
      {scalarEntries.length > 0 && (
        <div className="inspector-kv-grid">
          {scalarEntries.map(([key, value]) => (
            <div key={key} className="inspector-kv-card">
              <div className="inspector-kv-label">{formatLabel(key)}</div>
              <div className="inspector-kv-value">
                {typeof value === 'string' ? value : formatValue(value)}
              </div>
            </div>
          ))}
        </div>
      )}

      {visibleComplexEntries.map(([key, value]) => (
        <details key={key} className="inspector-section" open={depth === 0}>
          <summary>
            {formatLabel(key)}
            <span>{collectionSummary(value)}</span>
          </summary>
          <div className="inspector-content">
            <StructuredInspector data={value} depth={depth + 1} />
          </div>
        </details>
      ))}

      {hiddenComplexCount > 0 && (
        <div className="hint">
          {hiddenComplexCount} more nested section{hiddenComplexCount === 1 ? '' : 's'} hidden to
          keep this panel readable.
        </div>
      )}
    </div>
  );
}

export function SummaryGrid({
  data,
  exclude = [],
  limit = 12,
  emptyMessage = 'No data available',
}) {
  if (!data || typeof data !== 'object') return <div className="empty">{emptyMessage}</div>;
  if (Array.isArray(data)) {
    if (data.length === 0) return <div className="empty">{emptyMessage}</div>;
    return (
      <div className="summary-grid">
        <div className="summary-card">
          <div className="summary-label">Items</div>
          <div className="summary-value">{data.length}</div>
        </div>
        {data.slice(0, Math.max(0, limit - 1)).map((value, index) => {
          const preview = previewObject(value);
          return (
            <div key={value?.id ?? `grid-${index}`} className="summary-card">
              <div className="summary-label">Item {index + 1}</div>
              <div className="summary-value">{formatValue(value)}</div>
              {preview && preview.length > 0 && (
                <div className="summary-meta">
                  {preview.map(([innerKey, innerValue]) => (
                    <div key={innerKey}>
                      {formatLabel(innerKey)}: {formatValue(innerValue)}
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    );
  }
  const entries = Object.entries(data).filter(([key]) => !exclude.includes(key));
  if (entries.length === 0) return <div className="empty">{emptyMessage}</div>;
  return (
    <div className="summary-grid">
      {entries.slice(0, limit).map(([key, value]) => {
        const preview = previewObject(value);
        return (
          <div key={key} className="summary-card">
            <div className="summary-label">{formatLabel(key)}</div>
            <div className="summary-value">{formatValue(value)}</div>
            {preview && preview.length > 0 && (
              <div className="summary-meta">
                {preview.map(([innerKey, innerValue]) => (
                  <div key={innerKey}>
                    {formatLabel(innerKey)}: {formatValue(innerValue)}
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

export function JsonDetails({ data, label = 'Expanded details' }) {
  if (data == null) return null;
  return (
    <details style={{ marginTop: 12 }}>
      <summary style={{ cursor: 'pointer', fontSize: 12, color: 'var(--text-secondary)' }}>
        {label}
      </summary>
      <div className="inspector-shell" style={{ marginTop: 8 }}>
        <StructuredInspector data={data} />
      </div>
    </details>
  );
}

export function WorkspaceEmptyState({ title, description, icon, actions, compact = false }) {
  return (
    <div
      className="empty"
      role="status"
      aria-live="polite"
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: 8,
        padding: compact ? '16px 12px' : '32px 20px',
        textAlign: 'center',
      }}
    >
      {icon ? (
        <div aria-hidden="true" style={{ fontSize: 28 }}>
          {icon}
        </div>
      ) : null}
      {title ? <div style={{ fontWeight: 600, fontSize: 14 }}>{title}</div> : null}
      {description ? (
        <div className="hint" style={{ maxWidth: 480 }}>
          {description}
        </div>
      ) : null}
      {actions ? (
        <div className="btn-group" style={{ marginTop: 4 }}>
          {actions}
        </div>
      ) : null}
    </div>
  );
}

export function WorkspaceErrorState({
  title = 'Something went wrong',
  description,
  error,
  onRetry,
  retryLabel = 'Retry',
}) {
  const message =
    description ||
    (typeof error?.message === 'string' && error.message) ||
    'The workspace could not load the requested data.';
  const requestId = typeof error?.requestId === 'string' ? error.requestId : null;
  return (
    <div
      className="empty"
      role="alert"
      aria-live="assertive"
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: 8,
        padding: '32px 20px',
        textAlign: 'center',
        border: '1px solid var(--err)',
        borderRadius: 8,
      }}
    >
      <div aria-hidden="true" style={{ fontSize: 28 }}>
        ⚠
      </div>
      <div style={{ fontWeight: 700, fontSize: 14, color: 'var(--err)' }}>{title}</div>
      <div className="hint" style={{ maxWidth: 480 }}>
        {message}
      </div>
      {requestId ? (
        <div className="hint" style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
          Request ID: {requestId}
        </div>
      ) : null}
      {onRetry ? (
        <button className="btn btn-sm" onClick={onRetry} type="button">
          {retryLabel}
        </button>
      ) : null}
    </div>
  );
}

export function RawJsonDetails({ data, label = 'Raw JSON' }) {
  if (data == null) return null;
  return (
    <details style={{ marginTop: 12 }}>
      <summary style={{ cursor: 'pointer', fontSize: 12, color: 'var(--text-secondary)' }}>
        {label}
      </summary>
      <div className="json-block" style={{ marginTop: 8 }}>
        {typeof data === 'string' ? data : JSON.stringify(data, null, 2)}
      </div>
    </details>
  );
}

export function SideDrawer({ open, title, subtitle, onClose, actions, children }) {
  const panelRef = useRef(null);
  const previousFocusRef = useRef(null);

  useEffect(() => {
    if (!open) return;
    const handleKey = (e) => {
      if (e.key === 'Escape') onClose?.();
    };
    document.addEventListener('keydown', handleKey);
    return () => document.removeEventListener('keydown', handleKey);
  }, [open, onClose]);

  // Focus trap: keep Tab cycling within the drawer
  useEffect(() => {
    if (!open || !panelRef.current) return;
    const panel = panelRef.current;
    previousFocusRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const focusable = () =>
      Array.from(
        panel.querySelectorAll(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
        ),
      ).filter((node) => !node.hasAttribute('disabled'));
    const first = focusable()[0] || panel;
    first.focus();

    const trapFocus = (e) => {
      if (e.key !== 'Tab') return;
      const els = focusable();
      if (els.length === 0) return;
      const firstEl = els[0];
      const lastEl = els[els.length - 1];
      if (e.shiftKey) {
        if (document.activeElement === firstEl) {
          e.preventDefault();
          lastEl.focus();
        }
      } else {
        if (document.activeElement === lastEl) {
          e.preventDefault();
          firstEl.focus();
        }
      }
    };
    panel.addEventListener('keydown', trapFocus);
    return () => {
      panel.removeEventListener('keydown', trapFocus);
      previousFocusRef.current?.focus?.();
    };
  }, [open]);

  if (!open) return null;
  return (
    <div className="drawer-overlay" onClick={onClose}>
      <aside
        className="drawer-panel"
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="drawer-header">
          <div>
            <div className="drawer-title">{title}</div>
            {subtitle && <div className="drawer-subtitle">{subtitle}</div>}
          </div>
          <div className="drawer-actions">
            {actions}
            <button className="btn btn-sm" onClick={onClose}>
              Close
            </button>
          </div>
        </div>
        <div className="drawer-body">{children}</div>
      </aside>
    </div>
  );
}

export function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  tone = 'danger',
  onConfirm,
  onCancel,
}) {
  const dialogRef = useRef(null);
  const previousFocusRef = useRef(null);

  useEffect(() => {
    if (!open) return;
    const handleKey = (event) => {
      if (event.key === 'Escape') onCancel?.();
    };
    document.addEventListener('keydown', handleKey);
    return () => document.removeEventListener('keydown', handleKey);
  }, [open, onCancel]);

  // Focus trap
  useEffect(() => {
    if (!open || !dialogRef.current) return;
    const dialog = dialogRef.current;
    previousFocusRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const focusable = () =>
      Array.from(
        dialog.querySelectorAll(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
        ),
      ).filter((node) => !node.hasAttribute('disabled'));
    const first = focusable()[0] || dialog;
    first.focus();

    const trapFocus = (e) => {
      if (e.key !== 'Tab') return;
      const els = focusable();
      if (els.length === 0) return;
      const firstEl = els[0];
      const lastEl = els[els.length - 1];
      if (e.shiftKey) {
        if (document.activeElement === firstEl) {
          e.preventDefault();
          lastEl.focus();
        }
      } else {
        if (document.activeElement === lastEl) {
          e.preventDefault();
          firstEl.focus();
        }
      }
    };
    dialog.addEventListener('keydown', trapFocus);
    return () => {
      dialog.removeEventListener('keydown', trapFocus);
      previousFocusRef.current?.focus?.();
    };
  }, [open]);

  if (!open) return null;

  return (
    <div className="confirm-overlay" onClick={onCancel}>
      <div
        className="confirm-dialog"
        ref={dialogRef}
        onClick={(event) => event.stopPropagation()}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        tabIndex={-1}
      >
        <div className="confirm-dialog-header">
          <h3 id="confirm-dialog-title">{title}</h3>
        </div>
        <p className="confirm-dialog-body">{message}</p>
        <div className="confirm-dialog-actions">
          <button className="btn btn-sm" onClick={onCancel}>
            {cancelLabel}
          </button>
          <button
            className={`btn btn-sm ${tone === 'danger' ? 'btn-danger' : 'btn-primary'}`}
            onClick={onConfirm}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
