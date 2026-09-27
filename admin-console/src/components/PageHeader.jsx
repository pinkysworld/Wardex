// Shared page-level header: an optional small eyebrow/breadcrumb, an
// optional heading, and a right-aligned actions row. Used by workspace pages
// so every screen has exactly one row of page-scoped chrome instead of
// stacking a breadcrumb block, a scope bar, and a duplicate title above it.
export default function PageHeader({ eyebrow, title, description, actions, children }) {
  return (
    <div className="page-header">
      <div className="page-header-text">
        {eyebrow && <div className="page-header-eyebrow">{eyebrow}</div>}
        {title && <h2 className="page-header-title">{title}</h2>}
        {description && <div className="page-header-description">{description}</div>}
        {children}
      </div>
      {actions && <div className="page-header-actions btn-group">{actions}</div>}
    </div>
  );
}
