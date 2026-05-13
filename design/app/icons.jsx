// app/icons.jsx — 16x16 stroke icon set, lucide-style. Single export `Icon`.
window.Icon = function Icon({ name, size = 16, stroke = 1.6, style }) {
  const p = ICON_PATHS[name];
  if (!p) return null;
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none"
         stroke="currentColor" strokeWidth={stroke}
         strokeLinecap="round" strokeLinejoin="round" style={{ flex: '0 0 auto', ...style }}>
      {typeof p === 'string' ? <path d={p} /> : p}
    </svg>
  );
};

const _ = (jsx) => jsx;
const ICON_PATHS = {
  grid: _(<><rect x="2" y="2" width="5" height="5" rx="1"/><rect x="9" y="2" width="5" height="5" rx="1"/><rect x="2" y="9" width="5" height="5" rx="1"/><rect x="9" y="9" width="5" height="5" rx="1"/></>),
  pulse: "M1 8h3l2-5 3 10 2-5h4",
  shield: "M8 1.5 2 4v4c0 3.3 2.6 5.8 6 6.5 3.4-.7 6-3.2 6-6.5V4L8 1.5z",
  bug: _(<><circle cx="8" cy="9" r="3.5"/><path d="M8 5.5V3M5.5 6.5 4 5M10.5 6.5 12 5M4.5 9H2M11.5 9H14M5 11.5l-2 1.5M11 11.5l2 1.5"/></>),
  server: _(<><rect x="2" y="3" width="12" height="4" rx="1"/><rect x="2" y="9" width="12" height="4" rx="1"/><circle cx="5" cy="5" r=".5" fill="currentColor"/><circle cx="5" cy="11" r=".5" fill="currentColor"/></>),
  lock: _(<><rect x="3" y="7" width="10" height="7" rx="1.5"/><path d="M5 7V5a3 3 0 016 0v2"/></>),
  workbench: _(<><rect x="2" y="3" width="12" height="9" rx="1.5"/><path d="M2 12h12M5 14l1-2M11 14l-1-2"/></>),
  command: "M3 5a2 2 0 114 0v6a2 2 0 11-4 0 2 2 0 014 0h6a2 2 0 11-4 0V5a2 2 0 114 0 2 2 0 01-4 0",
  bot: _(<><rect x="2.5" y="5" width="11" height="8" rx="2"/><path d="M8 5V2.5M5 8.5v1M11 8.5v1"/><circle cx="5.5" cy="8.5" r=".3" fill="currentColor"/><circle cx="10.5" cy="8.5" r=".3" fill="currentColor"/></>),
  layers: "M8 1.5 1.5 5 8 8.5 14.5 5 8 1.5zM1.5 8 8 11.5 14.5 8M1.5 11 8 14.5 14.5 11",
  search: _(<><circle cx="7" cy="7" r="4.5"/><path d="m13.5 13.5-3-3"/></>),
  bell: "M3.5 11.5h9l-1-2v-3a3.5 3.5 0 10-7 0v3l-1 2M6.5 13.5a1.5 1.5 0 003 0",
  user: _(<><circle cx="8" cy="6" r="2.5"/><path d="M3 13.5c.5-2.5 2.5-4 5-4s4.5 1.5 5 4"/></>),
  settings: _(<><circle cx="8" cy="8" r="2"/><path d="M8 1v2.5M8 12.5V15M3.5 3.5l1.8 1.8M10.7 10.7l1.8 1.8M1 8h2.5M12.5 8H15M3.5 12.5l1.8-1.8M10.7 5.3l1.8-1.8"/></>),
  help: _(<><circle cx="8" cy="8" r="6.5"/><path d="M6 6.5a2 2 0 014 0c0 1-1 1.5-2 2.5M8 12v.5"/></>),
  chevR: "M6 3l5 5-5 5",
  chevD: "M3 6l5 5 5-5",
  chevU: "M3 10l5-5 5 5",
  chevL: "M10 3l-5 5 5 5",
  arrowUp: "M8 13V3M3 8l5-5 5 5",
  arrowDn: "M8 3v10M3 8l5 5 5-5",
  arrowR: "M3 8h10M8 3l5 5-5 5",
  plus: "M8 3v10M3 8h10",
  close: "M3.5 3.5l9 9M12.5 3.5l-9 9",
  check: "M3 8.5l3 3 7-7",
  flag: "M3.5 14V2M3.5 3h9l-2 3 2 3h-9",
  filter: "M2 3h12l-4.5 5.5V13L6.5 14v-5.5L2 3z",
  pin: "M5 1.5h6M6 1.5v5L4 9.5h8L10 6.5v-5M8 9.5V14",
  star: "M8 1.5l1.8 4.2 4.7.4-3.6 3 1.2 4.5L8 11.3 3.9 13.6l1.2-4.5-3.6-3 4.7-.4L8 1.5z",
  zap: "M8.5 1.5L3 9h4L6.5 14.5 12 7H8L8.5 1.5z",
  fire: "M8 1.5c1 3 5 4.5 5 8a5 5 0 11-10 0c0-1 .5-2 1.5-3 0 1.5 1 2 1.5 2-.5-2 1-4 2-7z",
  globe: _(<><circle cx="8" cy="8" r="6.5"/><path d="M1.5 8h13M8 1.5c2 2 3 4 3 6.5s-1 4.5-3 6.5c-2-2-3-4-3-6.5s1-4.5 3-6.5z"/></>),
  doc: "M4 1.5h5l3 3v10h-8v-13zM9 1.5v3h3",
  download: "M8 2v8M4 7l4 4 4-4M2 13.5h12",
  upload: "M8 11V3M4 6l4-4 4 4M2 13.5h12",
  copy: _(<><rect x="2" y="4" width="9" height="10" rx="1.5"/><path d="M5 4V3a1 1 0 011-1h7a1 1 0 011 1v8a1 1 0 01-1 1h-1"/></>),
  link: "M6.5 9.5l3-3M6 4.5l1.5-1.5a3 3 0 014 4L10 8.5M6 7.5l-1.5 1.5a3 3 0 004 4L10 11.5",
  eye: _(<><path d="M1.5 8s2-5 6.5-5 6.5 5 6.5 5-2 5-6.5 5S1.5 8 1.5 8z"/><circle cx="8" cy="8" r="2"/></>),
  pause: _(<><rect x="4" y="3" width="2.5" height="10" rx=".5"/><rect x="9.5" y="3" width="2.5" height="10" rx=".5"/></>),
  play: "M5 3l8 5-8 5V3z",
  stop: _(<rect x="4" y="4" width="8" height="8" rx="1"/>),
  rotate: "M14 8a6 6 0 11-3-5.2M14 2v3.5h-3.5",
  network: _(<><circle cx="3" cy="13" r="1.5"/><circle cx="8" cy="3" r="1.5"/><circle cx="13" cy="13" r="1.5"/><path d="M4 11.5L7 5M9 5l3 6.5M4.5 13h7"/></>),
  cpu: _(<><rect x="3" y="3" width="10" height="10" rx="1.5"/><rect x="6" y="6" width="4" height="4" rx=".5"/><path d="M5 1v2M8 1v2M11 1v2M5 13v2M8 13v2M11 13v2M1 5h2M1 8h2M1 11h2M13 5h2M13 8h2M13 11h2"/></>),
  mail: _(<><rect x="2" y="3.5" width="12" height="9" rx="1.5"/><path d="M2.5 4.5L8 9l5.5-4.5"/></>),
  graph: _(<><circle cx="4" cy="4" r="1.5"/><circle cx="12" cy="4" r="1.5"/><circle cx="8" cy="12" r="1.5"/><path d="M5 5l2.5 6M11 5L8.5 11M5.5 4h5"/></>),
  send: "M14 2L1 7l5 2 2 5L14 2zM6 9l4-4",
};
