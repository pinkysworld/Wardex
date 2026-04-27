import { cloneElement, isValidElement, useId, useState } from 'react';

function composeHandlers(...handlers) {
  return (event) => {
    handlers.forEach((handler) => handler?.(event));
  };
}

export default function Tooltip({ text, children }) {
  const [show, setShow] = useState(false);
  const tooltipId = useId();
  const describedBy = show ? tooltipId : undefined;

  const triggerProps = {
    'aria-describedby': describedBy,
    onFocus: () => setShow(true),
    onBlur: () => setShow(false),
    onKeyDown: (event) => {
      if (event.key === 'Escape') setShow(false);
    },
  };

  const trigger = isValidElement(children) ? (
    cloneElement(children, {
      ...triggerProps,
      ...children.props,
      'aria-describedby': describedBy ?? children.props['aria-describedby'],
      onFocus: composeHandlers(children.props.onFocus, triggerProps.onFocus),
      onBlur: composeHandlers(children.props.onBlur, triggerProps.onBlur),
      onKeyDown: composeHandlers(children.props.onKeyDown, triggerProps.onKeyDown),
    })
  ) : (
    <button
      type="button"
      className="tooltip-icon"
      aria-label="More information"
      {...triggerProps}
      onClick={() => setShow(true)}
      style={{
        cursor: 'help',
        opacity: 0.5,
        fontSize: 12,
        border: 0,
        padding: 0,
        background: 'transparent',
        color: 'inherit',
      }}
    >
      ⓘ
    </button>
  );

  return (
    <span
      className="tooltip-trigger"
      onMouseEnter={() => setShow(true)}
      onMouseLeave={() => setShow(false)}
      style={{ position: 'relative', display: 'inline-flex', alignItems: 'center' }}
    >
      {trigger}
      {show && (
        <span id={tooltipId} role="tooltip" className="tooltip-content">
          {text}
        </span>
      )}
    </span>
  );
}
