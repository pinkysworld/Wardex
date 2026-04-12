import { useState, useCallback, useRef, useEffect } from 'react';

/**
 * DashboardWidget — draggable, collapsible, removable dashboard widget wrapper.
 * Uses HTML5 Drag and Drop API (no external deps).
 */
export default function DashboardWidget({ id, title, children, collapsed: defaultCollapsed = false, onRemove, onMove }) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed);
  const [dragging, setDragging] = useState(false);
  const ref = useRef(null);

  const handleDragStart = useCallback((e) => {
    e.dataTransfer.setData('text/plain', id);
    e.dataTransfer.effectAllowed = 'move';
    setDragging(true);
  }, [id]);

  const handleDragEnd = useCallback(() => {
    setDragging(false);
  }, []);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    const fromId = e.dataTransfer.getData('text/plain');
    if (fromId && fromId !== id) {
      onMove?.(fromId, id);
    }
  }, [id, onMove]);

  return (
    <div
      ref={ref}
      className={`dashboard-widget ${dragging ? 'widget-dragging' : ''}`}
      draggable
      onDragStart={handleDragStart}
      onDragEnd={handleDragEnd}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
      role="region"
      aria-label={title}
    >
      <div className="widget-header">
        <span className="widget-grip" aria-hidden="true">⠿</span>
        <span className="widget-title">{title}</span>
        <div className="widget-controls">
          <button
            className="btn-icon widget-collapse"
            onClick={() => setCollapsed(c => !c)}
            aria-label={collapsed ? `Expand ${title}` : `Collapse ${title}`}
            title={collapsed ? 'Expand' : 'Collapse'}
          >
            {collapsed ? '▸' : '▾'}
          </button>
          {onRemove && (
            <button
              className="btn-icon widget-remove"
              onClick={() => onRemove(id)}
              aria-label={`Remove ${title} widget`}
              title="Remove widget"
            >
              ✕
            </button>
          )}
        </div>
      </div>
      {!collapsed && (
        <div className="widget-content">
          {children}
        </div>
      )}
    </div>
  );
}

/**
 * Hook to manage widget order with localStorage persistence.
 */
export function useWidgetLayout(defaultOrder, storageKey = 'wardex_widget_layout') {
  const [order, setOrder] = useState(() => {
    try {
      const saved = localStorage.getItem(storageKey);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch { /* ignore */ }
    return defaultOrder;
  });

  const [hidden, setHidden] = useState(() => {
    try {
      const saved = localStorage.getItem(storageKey + '_hidden');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed)) return new Set(parsed);
      }
    } catch { /* ignore */ }
    return new Set();
  });

  useEffect(() => {
    localStorage.setItem(storageKey, JSON.stringify(order));
  }, [order, storageKey]);

  useEffect(() => {
    localStorage.setItem(storageKey + '_hidden', JSON.stringify([...hidden]));
  }, [hidden, storageKey]);

  const moveWidget = useCallback((fromId, toId) => {
    setOrder(prev => {
      const arr = [...prev];
      const fromIdx = arr.indexOf(fromId);
      const toIdx = arr.indexOf(toId);
      if (fromIdx < 0 || toIdx < 0) return prev;
      arr.splice(fromIdx, 1);
      arr.splice(toIdx, 0, fromId);
      return arr;
    });
  }, []);

  const removeWidget = useCallback((id) => {
    setHidden(prev => new Set([...prev, id]));
  }, []);

  const restoreWidget = useCallback((id) => {
    setHidden(prev => {
      const next = new Set(prev);
      next.delete(id);
      return next;
    });
  }, []);

  const resetLayout = useCallback(() => {
    setOrder(defaultOrder);
    setHidden(new Set());
  }, [defaultOrder]);

  const visibleWidgets = order.filter(id => !hidden.has(id));

  return { order: visibleWidgets, hidden, moveWidget, removeWidget, restoreWidget, resetLayout };
}
