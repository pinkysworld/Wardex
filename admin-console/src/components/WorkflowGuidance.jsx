import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useRole } from '../hooks.jsx';

const ROLE_LEVEL = {
  viewer: 0,
  analyst: 1,
  admin: 2,
};

function hasAccess(role, minRole = 'viewer') {
  return (ROLE_LEVEL[role] ?? ROLE_LEVEL.viewer) >= (ROLE_LEVEL[minRole] ?? ROLE_LEVEL.viewer);
}

export default function WorkflowGuidance({
  title = 'Workflow Guidance',
  description = 'Use these pivots to keep the current investigation context moving across the console.',
  items = [],
}) {
  const { role } = useRole();
  const visibleItems = useMemo(
    () => items.filter((item) => item?.to && hasAccess(role, item.minRole)),
    [items, role],
  );

  if (visibleItems.length === 0) return null;

  return (
    <div className="card" style={{ marginBottom: 16 }}>
      <div className="card-header" style={{ alignItems: 'flex-start' }}>
        <div>
          <div className="card-title">{title}</div>
          <div className="hint" style={{ marginTop: 6 }}>
            {description}
          </div>
        </div>
      </div>
      <div className="workflow-pivot-grid">
        {visibleItems.map((item) => (
          <article key={item.id || item.title} className="summary-card workflow-pivot-card">
            {item.badge ? (
              <span className={`badge ${item.badgeTone || 'badge-info'}`}>{item.badge}</span>
            ) : null}
            <div className="workflow-pivot-title">{item.title}</div>
            <div className="summary-meta">{item.description}</div>
            <div className="btn-group">
              <Link
                className={`btn btn-sm ${item.tone === 'primary' ? 'btn-primary' : ''}`}
                to={item.to}
              >
                {item.actionLabel || 'Open'}
              </Link>
              {item.secondaryTo ? (
                <Link className="btn btn-sm" to={item.secondaryTo}>
                  {item.secondaryLabel || 'Alternate'}
                </Link>
              ) : null}
            </div>
          </article>
        ))}
      </div>
    </div>
  );
}
