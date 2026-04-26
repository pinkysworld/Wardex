const SETTINGS_TABS = [
  { id: 'config', label: 'Config' },
  { id: 'monitoring', label: 'Monitoring' },
  { id: 'integrations', label: 'Integrations' },
  { id: 'flags', label: 'Flags' },
  { id: 'team', label: 'Team' },
  { id: 'admin', label: 'Admin' },
];

export function SettingsTabs({ activeTab, onChange }) {
  return (
    <div className="tabs" role="tablist" aria-label="Settings sections">
      {SETTINGS_TABS.map((tab) => (
        <button
          key={tab.id}
          className={`tab ${activeTab === tab.id ? 'active' : ''}`}
          onClick={() => onChange(tab.id)}
          role="tab"
          aria-selected={activeTab === tab.id}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}
