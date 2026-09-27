import { useState, useCallback, useRef } from 'react';
import {
  IconChevronDown,
  IconChevronRight,
  IconClose,
  IconGripVertical,
  IconPause,
  IconPlay,
} from './icons.jsx';

/**
 * DashboardWidget — draggable, collapsible, removable dashboard widget wrapper.
 * Uses HTML5 Drag and Drop API (no external deps).
 */
export default function DashboardWidget({
  id,
  title,
  children,
  collapsed: defaultCollapsed = false,
  onRemove,
  onMove,
  paused,
  onTogglePause,
}) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed);
  const [dragging, setDragging] = useState(false);
  const ref = useRef(null);

  const handleDragStart = useCallback(
    (e) => {
      e.dataTransfer.setData('text/plain', id);
      e.dataTransfer.effectAllowed = 'move';
      setDragging(true);
    },
    [id],
  );

  const handleDragEnd = useCallback(() => {
    setDragging(false);
  }, []);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
  }, []);

  const handleDrop = useCallback(
    (e) => {
      e.preventDefault();
      const fromId = e.dataTransfer.getData('text/plain');
      if (fromId && fromId !== id) {
        onMove?.(fromId, id);
      }
    },
    [id, onMove],
  );

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
        <span className="widget-grip" aria-hidden="true">
          <IconGripVertical size={14} />
        </span>
        <span className="widget-title">{title}</span>
        <div className="widget-controls">
          {onTogglePause && (
            <button
              className="btn-icon"
              onClick={() => onTogglePause(id)}
              aria-label={paused ? `Resume ${title} auto-refresh` : `Pause ${title} auto-refresh`}
              title={paused ? 'Resume auto-refresh' : 'Pause auto-refresh'}
              style={{ fontSize: 12, opacity: paused ? 1 : 0.5 }}
            >
              {paused ? <IconPlay size={14} /> : <IconPause size={14} />}
            </button>
          )}
          <button
            className="btn-icon widget-collapse"
            onClick={() => setCollapsed((c) => !c)}
            aria-label={collapsed ? `Expand ${title}` : `Collapse ${title}`}
            title={collapsed ? 'Expand' : 'Collapse'}
          >
            {collapsed ? <IconChevronRight size={14} /> : <IconChevronDown size={14} />}
          </button>
          {onRemove && (
            <button
              className="btn-icon widget-remove"
              onClick={() => onRemove(id)}
              aria-label={`Remove ${title} widget`}
              title="Remove widget"
            >
              <IconClose size={14} />
            </button>
          )}
        </div>
      </div>
      {!collapsed && <div className="widget-content">{children}</div>}
    </div>
  );
}
