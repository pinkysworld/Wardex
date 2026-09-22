// ── Icon set ─────────────────────────────────────────────────
// A small, hand-written set of inline SVG icons used throughout the admin
// console shell and workspaces. One stroke style (round caps/joins, 1.75px
// stroke), sized 16-18px by default, and colored via `currentColor` so every
// icon inherits its surrounding text/button color and theme automatically.
// These are original shapes drawn for Wardex — not sourced from a third
// party icon set — so no separate license notice is required.

function Svg({ size = 17, children, ...rest }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      {children}
    </svg>
  );
}

export function IconMenu(props) {
  return (
    <Svg {...props}>
      <line x1="4" y1="6" x2="20" y2="6" />
      <line x1="4" y1="12" x2="20" y2="12" />
      <line x1="4" y1="18" x2="20" y2="18" />
    </Svg>
  );
}

export function IconChevronLeft(props) {
  return (
    <Svg {...props}>
      <polyline points="14,5 8,12 14,19" />
    </Svg>
  );
}

export function IconChevronRight(props) {
  return (
    <Svg {...props}>
      <polyline points="10,5 16,12 10,19" />
    </Svg>
  );
}

export function IconChevronDown(props) {
  return (
    <Svg {...props}>
      <polyline points="5,9 12,15 19,9" />
    </Svg>
  );
}

export function IconSun(props) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="4" />
      <line x1="12" y1="2.5" x2="12" y2="5" />
      <line x1="12" y1="19" x2="12" y2="21.5" />
      <line x1="2.5" y1="12" x2="5" y2="12" />
      <line x1="19" y1="12" x2="21.5" y2="12" />
      <line x1="4.9" y1="4.9" x2="6.7" y2="6.7" />
      <line x1="17.3" y1="17.3" x2="19.1" y2="19.1" />
      <line x1="4.9" y1="19.1" x2="6.7" y2="17.3" />
      <line x1="17.3" y1="6.7" x2="19.1" y2="4.9" />
    </Svg>
  );
}

export function IconMoon(props) {
  return (
    <Svg {...props}>
      <path d="M20 14.5A8.5 8.5 0 1 1 9.5 4a6.8 6.8 0 0 0 10.5 10.5Z" />
    </Svg>
  );
}

export function IconLogOut(props) {
  return (
    <Svg {...props}>
      <path d="M9 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h3" />
      <polyline points="15,8 19,12 15,16" />
      <line x1="19" y1="12" x2="9" y2="12" />
    </Svg>
  );
}

export function IconRefresh(props) {
  return (
    <Svg {...props}>
      <path d="M4 12a8 8 0 0 1 14-5.3L20 8" />
      <polyline points="20,3 20,8 15,8" />
      <path d="M20 12a8 8 0 0 1-14 5.3L4 16" />
      <polyline points="4,21 4,16 9,16" />
    </Svg>
  );
}

export function IconLayoutReset(props) {
  return (
    <Svg {...props}>
      <rect x="3.5" y="3.5" width="7" height="7" rx="1.2" />
      <rect x="13.5" y="3.5" width="7" height="7" rx="1.2" />
      <rect x="3.5" y="13.5" width="7" height="7" rx="1.2" />
      <rect x="13.5" y="13.5" width="7" height="7" rx="1.2" />
    </Svg>
  );
}

export function IconMonitorPlay(props) {
  return (
    <Svg {...props}>
      <rect x="2.5" y="4" width="19" height="13" rx="1.5" />
      <line x1="8" y1="21" x2="16" y2="21" />
      <line x1="12" y1="17" x2="12" y2="21" />
      <polygon points="10.5,8 15,10.5 10.5,13" fill="currentColor" stroke="none" />
    </Svg>
  );
}

export function IconSearch(props) {
  return (
    <Svg {...props}>
      <circle cx="10.5" cy="10.5" r="6.5" />
      <line x1="15.5" y1="15.5" x2="21" y2="21" />
    </Svg>
  );
}

export function IconHelp(props) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="9" />
      <path d="M9.3 9.2a2.7 2.7 0 1 1 3.9 2.4c-.8.5-1.2 1-1.2 2" />
      <line x1="12" y1="17" x2="12" y2="17.1" />
    </Svg>
  );
}

export function IconLink(props) {
  return (
    <Svg {...props}>
      <path d="M9.5 14.5 14.5 9.5" />
      <path d="M11 6.5 12.6 4.9a3.5 3.5 0 1 1 5 5L16 11.5" />
      <path d="M13 17.5 11.4 19.1a3.5 3.5 0 1 1-5-5L8 12.5" />
    </Svg>
  );
}

export function IconInbox(props) {
  return (
    <Svg {...props}>
      <path d="M3.5 12.5h5l1.5 2.5h4l1.5-2.5h5" />
      <path d="M5.5 5.5h13l2 7v6a1.5 1.5 0 0 1-1.5 1.5h-14A1.5 1.5 0 0 1 3.5 18.5v-6Z" />
    </Svg>
  );
}

export function IconMore(props) {
  return (
    <Svg {...props}>
      <circle cx="5" cy="12" r="1.4" fill="currentColor" stroke="none" />
      <circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none" />
      <circle cx="19" cy="12" r="1.4" fill="currentColor" stroke="none" />
    </Svg>
  );
}

export function IconKeyboard(props) {
  return (
    <Svg {...props}>
      <rect x="2.5" y="6" width="19" height="12" rx="1.6" />
      <line x1="6" y1="10" x2="6" y2="10" />
      <line x1="9" y1="10" x2="9" y2="10" />
      <line x1="12" y1="10" x2="12" y2="10" />
      <line x1="15" y1="10" x2="15" y2="10" />
      <line x1="18" y1="10" x2="18" y2="10" />
      <line x1="7" y1="14.5" x2="17" y2="14.5" />
    </Svg>
  );
}

export function IconClose(props) {
  return (
    <Svg {...props}>
      <line x1="6" y1="6" x2="18" y2="18" />
      <line x1="18" y1="6" x2="6" y2="18" />
    </Svg>
  );
}

export function IconStar(props) {
  const { filled, ...rest } = props;
  return (
    <Svg {...rest} fill={filled ? 'currentColor' : 'none'}>
      <path d="M12 3.3 14.5 9l6.2.5-4.7 4.1 1.4 6.1L12 16.6 6.6 19.7 8 13.6 3.3 9.5 9.5 9Z" />
    </Svg>
  );
}

// ── Section / navigation icons ──────────────────────────────
function IconGrid(props) {
  return (
    <Svg {...props}>
      <rect x="3" y="3" width="7.5" height="7.5" rx="1.3" />
      <rect x="13.5" y="3" width="7.5" height="7.5" rx="1.3" />
      <rect x="3" y="13.5" width="7.5" height="7.5" rx="1.3" />
      <rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1.3" />
    </Svg>
  );
}

function IconCompass(props) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="9" />
      <polygon points="15.5,8.5 13,13 8.5,15.5 11,11" />
    </Svg>
  );
}

function IconActivity(props) {
  return (
    <Svg {...props}>
      <polyline points="3,12 8,12 10.5,5 14,19 16.5,12 21,12" />
    </Svg>
  );
}

function IconShieldAlert(props) {
  return (
    <Svg {...props}>
      <path d="M12 3 4.5 6v6c0 5 3.4 8 7.5 9 4.1-1 7.5-4 7.5-9V6Z" />
      <line x1="12" y1="9" x2="12" y2="13.5" />
      <line x1="12" y1="16" x2="12" y2="16.1" />
    </Svg>
  );
}

function IconServer(props) {
  return (
    <Svg {...props}>
      <rect x="3" y="4" width="18" height="6.5" rx="1.4" />
      <rect x="3" y="13.5" width="18" height="6.5" rx="1.4" />
      <line x1="7" y1="7.2" x2="7" y2="7.2" />
      <line x1="7" y1="16.7" x2="7" y2="16.7" />
    </Svg>
  );
}

function IconLock(props) {
  return (
    <Svg {...props}>
      <rect x="5" y="10.5" width="14" height="10" rx="1.6" />
      <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
    </Svg>
  );
}

function IconTarget(props) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="9" />
      <circle cx="12" cy="12" r="5" />
      <circle cx="12" cy="12" r="1.1" fill="currentColor" stroke="none" />
    </Svg>
  );
}

function IconTerminal(props) {
  return (
    <Svg {...props}>
      <rect x="2.5" y="4.5" width="19" height="15" rx="1.6" />
      <polyline points="6.5,9.5 10.5,12.5 6.5,15.5" />
      <line x1="13" y1="15.5" x2="17.5" y2="15.5" />
    </Svg>
  );
}

function IconChat(props) {
  return (
    <Svg {...props}>
      <path d="M4 5.5h16v10.5H9.5L5 20v-4H4Z" />
    </Svg>
  );
}

function IconBug(props) {
  return (
    <Svg {...props}>
      <rect x="8" y="8" width="8" height="10" rx="4" />
      <line x1="12" y1="4" x2="12" y2="8" />
      <line x1="4.5" y1="9" x2="8" y2="11" />
      <line x1="19.5" y1="9" x2="16" y2="11" />
      <line x1="4.5" y1="17.5" x2="8" y2="15.5" />
      <line x1="19.5" y1="17.5" x2="16" y2="15.5" />
      <line x1="9" y1="4.5" x2="10.5" y2="6.5" />
      <line x1="15" y1="4.5" x2="13.5" y2="6.5" />
    </Svg>
  );
}

function IconFlask(props) {
  return (
    <Svg {...props}>
      <path d="M10 3.5h4" />
      <path d="M10.5 3.5v6L5.5 18a2 2 0 0 0 1.7 3h9.6a2 2 0 0 0 1.7-3l-5-8.5v-6" />
      <line x1="8" y1="15" x2="16" y2="15" />
    </Svg>
  );
}

function IconShieldCheck(props) {
  return (
    <Svg {...props}>
      <path d="M12 3 4.5 6v6c0 5 3.4 8 7.5 9 4.1-1 7.5-4 7.5-9V6Z" />
      <polyline points="9,12 11.2,14.2 15,10" />
    </Svg>
  );
}

function IconPlug(props) {
  return (
    <Svg {...props}>
      <path d="M9 3v5" />
      <path d="M15 3v5" />
      <path d="M6.5 8h11v3.5a5.5 5.5 0 0 1-11 0Z" />
      <line x1="12" y1="16" x2="12" y2="21" />
    </Svg>
  );
}

function IconPulse(props) {
  return (
    <Svg {...props}>
      <path d="M4 12h3l2 6 4-14 2 8h5" />
    </Svg>
  );
}

function IconDatabase(props) {
  return (
    <Svg {...props}>
      <ellipse cx="12" cy="5.5" rx="8" ry="3" />
      <path d="M4 5.5v13c0 1.7 3.6 3 8 3s8-1.3 8-3v-13" />
      <path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" />
    </Svg>
  );
}

function IconFileText(props) {
  return (
    <Svg {...props}>
      <path d="M6 2.5h8l4.5 4.5v14a1 1 0 0 1-1 1h-11a1 1 0 0 1-1-1v-17a1 1 0 0 1 1-1Z" />
      <polyline points="14,2.5 14,7 18.5,7" />
      <line x1="8.5" y1="12" x2="15.5" y2="12" />
      <line x1="8.5" y1="16" x2="15.5" y2="16" />
    </Svg>
  );
}

function IconGear(props) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="3" />
      <path d="M12 3.5v2.2M12 18.3v2.2M4.9 12H2.7M21.3 12h-2.2M6.3 6.3 4.7 4.7M19.3 19.3l-1.6-1.6M17.7 6.3l1.6-1.6M4.7 19.3l1.6-1.6" />
    </Svg>
  );
}

function IconBook(props) {
  return (
    <Svg {...props}>
      <path d="M4 5a2 2 0 0 1 2-2h6.5v16H6a2 2 0 0 0-2 2Z" />
      <path d="M20 5a2 2 0 0 0-2-2h-6.5v16H18a2 2 0 0 1 2 2Z" />
    </Svg>
  );
}

function IconUserCheck(props) {
  return (
    <Svg {...props}>
      <circle cx="9.5" cy="8" r="3.2" />
      <path d="M3.5 20c.6-3.5 3.1-5.5 6-5.5s5.4 2 6 5.5" />
      <polyline points="16,12.5 17.7,14.2 21,10.5" />
    </Svg>
  );
}

function IconNetwork(props) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="4.5" r="2" />
      <circle cx="5" cy="18" r="2" />
      <circle cx="19" cy="18" r="2" />
      <line x1="12" y1="6.5" x2="5" y2="16" />
      <line x1="12" y1="6.5" x2="19" y2="16" />
      <line x1="7" y1="18" x2="17" y2="18" />
    </Svg>
  );
}

function IconMail(props) {
  return (
    <Svg {...props}>
      <rect x="2.5" y="5" width="19" height="14" rx="1.6" />
      <polyline points="3,6.5 12,13 21,6.5" />
    </Svg>
  );
}

function IconGraph(props) {
  return (
    <Svg {...props}>
      <circle cx="6" cy="6" r="2" />
      <circle cx="18" cy="6" r="2" />
      <circle cx="12" cy="18" r="2" />
      <line x1="7.5" y1="7.2" x2="10.7" y2="16" />
      <line x1="16.5" y1="7.2" x2="13.3" y2="16" />
      <line x1="8" y1="6" x2="16" y2="6" />
    </Svg>
  );
}

const SECTION_ICONS = {
  dashboard: IconGrid,
  'operator-launchpad': IconCompass,
  'live-monitor': IconActivity,
  'threat-detection': IconShieldAlert,
  'fleet-agents': IconServer,
  'security-policy': IconLock,
  'soc-workbench': IconTarget,
  'command-center': IconTerminal,
  'assistant-workspace': IconChat,
  'malware-scanning': IconBug,
  'detection-lab': IconFlask,
  'response-safety': IconShieldCheck,
  integrations: IconPlug,
  'operations-health': IconPulse,
  infrastructure: IconDatabase,
  'reports-exports': IconFileText,
  settings: IconGear,
  'help-docs': IconBook,
  ueba: IconUserCheck,
  ndr: IconNetwork,
  'email-security': IconMail,
  'attack-graph': IconGraph,
};

export function SectionIcon({ sectionId, ...rest }) {
  const Component = SECTION_ICONS[sectionId] || IconGrid;
  return <Component {...rest} />;
}
