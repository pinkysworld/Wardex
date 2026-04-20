import React from 'react';

/**
 * EmptyState — contextual empty-state block for lists/tables/cards.
 *
 * Props:
 *   title        short title    (default "Nothing here yet")
 *   message      short body     (optional)
 *   icon         inline SVG     (optional)
 *   primaryCta   { label, onClick | href }
 *   secondaryCta { label, onClick | href }
 */
export default function EmptyState({
  title = 'Nothing here yet',
  message,
  icon,
  primaryCta,
  secondaryCta,
  compact = false,
}) {
  const renderCta = (cta, variant) => {
    if (!cta) return null;
    const className = variant === 'primary' ? 'empty-cta empty-cta-primary' : 'empty-cta';
    if (cta.href) {
      return (
        <a
          className={className}
          href={cta.href}
          target={cta.external ? '_blank' : undefined}
          rel={cta.external ? 'noreferrer' : undefined}
        >
          {cta.label}
        </a>
      );
    }
    return (
      <button type="button" className={className} onClick={cta.onClick}>
        {cta.label}
      </button>
    );
  };

  return (
    <div className={`empty-state${compact ? ' empty-state-compact' : ''}`} role="status">
      {icon && (
        <div className="empty-state-icon" aria-hidden="true">
          {icon}
        </div>
      )}
      <h3 className="empty-state-title">{title}</h3>
      {message && <p className="empty-state-message">{message}</p>}
      {(primaryCta || secondaryCta) && (
        <div className="empty-state-actions">
          {renderCta(primaryCta, 'primary')}
          {renderCta(secondaryCta, 'ghost')}
        </div>
      )}
    </div>
  );
}
