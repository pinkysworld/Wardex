import { useState } from 'react';

export default function Tooltip({ text, children }) {
  const [show, setShow] = useState(false);
  return (
    <span className="tooltip-trigger" onMouseEnter={() => setShow(true)} onMouseLeave={() => setShow(false)} style={{ position: 'relative', display: 'inline-flex', alignItems: 'center' }}>
      {children || <span style={{ cursor: 'help', opacity: 0.5, fontSize: 12 }}>ⓘ</span>}
      {show && <span className="tooltip-content">{text}</span>}
    </span>
  );
}
