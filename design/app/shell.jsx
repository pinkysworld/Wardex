// app/shell.jsx — three-pane workbench shell: rail, topbar, content
const { useState: uS, useEffect: uE } = React;

window.Shell = function Shell({ active='investigation', onNav, children, density='compact', railMode='rail' }) {
  const D = window.DATA;
  const collapsed = railMode === 'rail';
  return (
    <div className="wx wx-shell" style={{display:'grid', gridTemplateColumns:`${collapsed?56:224}px 1fr`, height:'100%'}}>
      <Rail active={active} onNav={onNav} collapsed={collapsed}/>
      <div style={{display:'flex', flexDirection:'column', minWidth:0, background:'var(--bg-0)'}}>
        <Topbar active={active}/>
        <div style={{flex:1, minHeight:0, overflow:'hidden'}}>{children}</div>
      </div>
    </div>
  );
};

function Rail({ active, onNav, collapsed }) {
  const D = window.DATA;
  return (
    <aside style={{background:'var(--bg-1)', borderRight:'1px solid var(--line-soft)', display:'flex', flexDirection:'column', overflow:'hidden'}}>
      {/* brand */}
      <div style={{display:'flex', alignItems:'center', gap:10, padding:'14px 14px', borderBottom:'1px solid var(--line-soft)', minHeight:48}}>
        <Logo/>
        {!collapsed && <span style={{fontSize:14, fontWeight:600, letterSpacing:'-0.01em'}}>Wardex</span>}
        {!collapsed && <span className="chip mono" style={{marginLeft:'auto', fontSize:10, height:16, padding:'0 5px'}}>v1.0.11</span>}
      </div>

      {/* nav */}
      <nav style={{flex:1, overflowY:'auto', padding:'8px 6px'}}>
        {D.sections.map(group => (
          <div key={group.group} style={{marginBottom:6}}>
            {!collapsed && <div className="eyebrow" style={{padding:'10px 10px 4px', fontSize:9.5}}>{group.group}</div>}
            {group.items.map(([id, label, _pinned, badge]) => (
              <NavItem key={id} id={id} label={label} active={active===id} collapsed={collapsed} badge={badge} onClick={()=>onNav?.(id)}/>
            ))}
          </div>
        ))}
      </nav>

      {/* footer */}
      <div style={{padding:8, borderTop:'1px solid var(--line-soft)', display:'flex', gap:6, alignItems:'center'}}>
        <div style={{width:24, height:24, borderRadius:'50%', background:'var(--accent-soft)', color:'var(--accent)', display:'flex', alignItems:'center', justifyContent:'center', fontSize:10, fontWeight:700}}>EJ</div>
        {!collapsed && <div style={{display:'flex', flexDirection:'column', minWidth:0, flex:1}}>
          <span style={{fontSize:11, fontWeight:600}}>Elena J.</span>
          <span style={{fontSize:10, color:'var(--fg-3)'}}>analyst · L2</span>
        </div>}
        {!collapsed && <button className="btn btn-sm btn-icon" title="Settings"><Icon name="settings" size={13}/></button>}
      </div>
    </aside>
  );
}

function NavItem({ id, label, active, collapsed, badge, onClick }) {
  const D = window.DATA;
  const iconName = D.sectionIcons[id] || 'grid';
  return (
    <button onClick={onClick} style={{
      display:'flex', alignItems:'center', gap:10, width:'100%',
      padding: collapsed ? '7px 0' : '6px 10px',
      justifyContent: collapsed ? 'center' : 'flex-start',
      background: active?'var(--bg-3)':'transparent',
      color: active?'var(--fg)':'var(--fg-2)',
      border:'none', borderRadius:6, cursor:'pointer', position:'relative',
      fontSize:12.5, fontWeight: active?500:400, textAlign:'left',
      height: 28, marginBottom:1,
    }}>
      {active && <span style={{position:'absolute', left:-6, top:6, bottom:6, width:2, background:'var(--accent)', borderRadius:2}}/>}
      <Icon name={iconName} size={15} style={{color: active?'var(--accent)':'var(--fg-3)'}}/>
      {!collapsed && <span style={{flex:1, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap'}}>{label}</span>}
      {!collapsed && badge && <span style={{
        minWidth:16, height:16, padding:'0 5px', borderRadius:8,
        background:'var(--sev-crit)', color:'#fff', fontSize:9.5, fontWeight:700,
        display:'flex', alignItems:'center', justifyContent:'center',
      }}>{badge}</span>}
    </button>
  );
}

function Logo() {
  return (
    <svg width="22" height="22" viewBox="0 0 22 22" fill="none">
      <path d="M11 1.5L2.5 5v6.5c0 4.4 3.6 7.6 8.5 9 4.9-1.4 8.5-4.6 8.5-9V5L11 1.5z" fill="var(--accent-soft)" stroke="var(--accent)" strokeWidth="1.2"/>
      <path d="M6.5 11l3 3 6-6" stroke="var(--accent)" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
    </svg>
  );
}

function Topbar({ active }) {
  const D = window.DATA;
  const labels = {
    investigation: ['Investigation', 'prod-app-07 · ' + D.alert.id],
    command: ['Command Center', 'Active incidents and approvals'],
    dashboard: ['Dashboard', D.NOW],
    monitor: ['Live Monitor', '12,448 events/min'],
    detection: ['Threat Detection', '247 rules · 14 tuning'],
    fleet: ['Fleet & Agents', '482 hosts · 478 healthy'],
    approvals: ['Response Approvals', '4 awaiting · 1 critical'],
    malware: ['Malware Analysis', '8 scans active'],
    reports: ['Reports & Exports', 'SOC weekly · 3 scheduled'],
    settings: ['Settings', 'RBAC · Audit · Integrations'],
  };
  const [t, s] = labels[active] || ['Wardex', ''];

  return (
    <header style={{display:'flex', alignItems:'center', gap:14, padding:'10px 18px', borderBottom:'1px solid var(--line-soft)', background:'var(--bg-0)', minHeight:52, flexShrink:0}}>
      <div style={{minWidth:0, flex:'0 0 auto'}}>
        <div style={{display:'flex', alignItems:'baseline', gap:10}}>
          <h1 style={{fontSize:15, fontWeight:600, letterSpacing:'-0.01em', margin:0}}>{t}</h1>
          <span className="mono" style={{fontSize:11, color:'var(--fg-3)'}}>{s}</span>
        </div>
      </div>

      {/* command-k search */}
      <div style={{flex:1, maxWidth:520, marginLeft:'auto'}}>
        <div style={{display:'flex', alignItems:'center', gap:8, padding:'0 10px', height:28, background:'var(--bg-1)', border:'1px solid var(--line-soft)', borderRadius:6, color:'var(--fg-3)', cursor:'text'}}>
          <Icon name="search" size={13}/>
          <span style={{flex:1, fontSize:12}}>Search alerts, hosts, hashes, rules…</span>
          <Kbd k="⌘"/><Kbd k="K"/>
        </div>
      </div>

      {/* status pills */}
      <div style={{display:'flex', alignItems:'center', gap:6}}>
        <span className="chip" style={{height:24, color:'var(--sev-crit)', borderColor:'var(--sev-crit-soft)', background:'var(--sev-crit-soft)'}}>
          <span className="dot" style={{background:'var(--sev-crit)'}}/>
          INCIDENT
        </span>
        <button className="btn btn-sm btn-icon" title="Inbox" style={{position:'relative'}}>
          <Icon name="bell" size={13}/>
          <span style={{position:'absolute', top:1, right:1, width:6, height:6, borderRadius:'50%', background:'var(--sev-crit)'}}/>
        </button>
        <button className="btn btn-sm btn-icon" title="Help"><Icon name="help" size={13}/></button>
      </div>
    </header>
  );
}
