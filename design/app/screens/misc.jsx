// app/screens/misc.jsx — Fleet, Detection, Approvals, Malware, Monitor, Settings, etc.
const { useState: muS } = React;

window.FleetScreen = function FleetScreen() {
  const D = window.DATA;
  return (
    <div style={{padding:'18px 22px', overflow:'auto', height:'100%'}}>
      <div className="card">
        <div className="card-h">
          <h3>Hosts</h3>
          <div className="row" style={{gap:6, marginLeft:'auto'}}>
            <span className="chip mono">482 total</span>
            <span className="chip mono" style={{color:'var(--sev-low)'}}>478 healthy</span>
            <span className="chip mono" style={{color:'var(--sev-high)'}}>3 at risk</span>
            <span className="chip mono" style={{color:'var(--sev-crit)'}}>1 isolated</span>
            <button className="btn btn-sm btn-ghost"><Icon name="filter" size={12}/>Filter</button>
            <button className="btn btn-sm"><Icon name="download" size={12}/>Export</button>
          </div>
        </div>
        <div style={{display:'grid', gridTemplateColumns:'1.5fr 80px 120px 130px 90px 1.2fr 70px 60px', gap:12, padding:'8px 16px', borderBottom:'1px solid var(--line-soft)'}}>
          {['Host','OS','Site','Status','Alerts 24h','Risk','Agent','Seen'].map(h=><span key={h} className="eyebrow">{h}</span>)}
        </div>
        {D.fleet.map(h=>(
          <div key={h.host} style={{display:'grid', gridTemplateColumns:'1.5fr 80px 120px 130px 90px 1.2fr 70px 60px', gap:12, padding:'8px 16px', borderBottom:'1px solid var(--line-soft)', alignItems:'center'}}>
            <span className="mono" style={{fontSize:12, fontWeight: h.status==='ISOLATED'?600:500, color: h.status==='ISOLATED'?'var(--sev-crit)':'var(--fg)'}}>{h.host}</span>
            <OsIcon os={h.os}/>
            <span className="mono" style={{fontSize:11, color:'var(--fg-3)'}}>{h.site}</span>
            <span style={{display:'flex', alignItems:'center', gap:6}}><StatusDot s={h.status}/><span style={{fontSize:11.5}}>{h.status}</span></span>
            <span className="mono tnum" style={{fontSize:11, color: h.alerts>0?'var(--sev-high)':'var(--fg-4)'}}>{h.alerts}</span>
            <RiskBar v={h.risk}/>
            <span className="mono" style={{fontSize:10.5, color:'var(--fg-3)'}}>{h.agent}</span>
            <span className="mono tnum" style={{fontSize:10.5, color:'var(--fg-3)'}}>{h.last}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

window.DetectionScreen = function DetectionScreen() {
  const D = window.DATA;
  return (
    <div style={{padding:'18px 22px', overflow:'auto', height:'100%'}}>
      <div className="card">
        <div className="card-h">
          <h3>Detection rules</h3>
          <div className="row" style={{gap:6, marginLeft:'auto'}}>
            <span className="chip mono">247 total · 14 tuning</span>
            <button className="btn btn-sm"><Icon name="plus" size={12}/>New rule</button>
          </div>
        </div>
        <div style={{display:'grid', gridTemplateColumns:'56px 1.8fr 100px 80px 110px 90px 80px 80px', gap:12, padding:'8px 16px', borderBottom:'1px solid var(--line-soft)'}}>
          {['ID','Rule','ATT&CK','Sev','State','Hits 24h','FP rate','Updated'].map(h=><span key={h} className="eyebrow">{h}</span>)}
        </div>
        {D.detectionRules.map(r=>(
          <div key={r.id} style={{display:'grid', gridTemplateColumns:'56px 1.8fr 100px 80px 110px 90px 80px 80px', gap:12, padding:'8px 16px', borderBottom:'1px solid var(--line-soft)', alignItems:'center'}}>
            <span className="mono" style={{fontSize:11, color:'var(--fg-3)'}}>{r.id}</span>
            <span className="mono" style={{fontSize:12}}>{r.name}</span>
            <span className="mono" style={{fontSize:10.5, color:'var(--fg-3)'}}>{r.mitre}</span>
            <Sev level={r.sev}/>
            <span className="chip" style={{fontSize:10, color: r.state==='SUPPRESS'?'var(--fg-3)': r.state==='TUNING'?'var(--sev-high)':'var(--sev-low)', borderColor:'currentColor', background:'transparent'}}>{r.state}</span>
            <span className="mono tnum" style={{fontSize:11, color: r.hits24>100?'var(--sev-high)':'var(--fg-2)'}}>{r.hits24}</span>
            <span className="mono tnum" style={{fontSize:11, color: parseFloat(r.fpRate)>10?'var(--sev-high)':'var(--fg-2)'}}>{r.fpRate}</span>
            <span className="mono" style={{fontSize:10.5, color:'var(--fg-3)'}}>{r.updated}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

window.ApprovalsScreen = function ApprovalsScreen() {
  const D = window.DATA;
  return (
    <div style={{padding:'18px 22px', overflow:'auto', height:'100%', display:'grid', gridTemplateColumns:'1fr 320px', gap:14}}>
      <div className="card">
        <div className="card-h"><h3>Response approvals · awaiting</h3><span className="chip mono" style={{marginLeft:'auto'}}>{D.approvals.length}</span></div>
        {D.approvals.map(a=>(
          <div key={a.id} style={{padding:'14px 18px', borderBottom:'1px solid var(--line-soft)', display:'grid', gridTemplateColumns:'80px 1fr 200px', gap:14, alignItems:'center'}}>
            <span className="mono" style={{fontSize:11, color:'var(--fg-3)'}}>{a.id}</span>
            <div>
              <div style={{display:'flex', alignItems:'center', gap:8, marginBottom:3}}>
                <span style={{fontSize:13, fontWeight:600}}>{a.action}</span>
                <span className="chip mono" style={{fontSize:10}}>{a.target}</span>
                <span className="chip" style={{fontSize:10, color: a.risk==='high'?'var(--sev-crit)':'var(--sev-med)', borderColor:'currentColor', background:'transparent'}}>{a.risk} risk</span>
              </div>
              <div style={{fontSize:11.5, color:'var(--fg-3)'}}>{a.why} · {a.by} · {a.at}</div>
            </div>
            <div style={{display:'flex', gap:6, justifyContent:'flex-end'}}>
              <button className="btn btn-sm">Deny</button>
              <button className="btn btn-sm btn-primary">Approve</button>
            </div>
          </div>
        ))}
      </div>
      <div className="card">
        <div className="card-h"><h3>Audit · last 24h</h3></div>
        <div style={{padding:'12px 14px', display:'flex', flexDirection:'column', gap:8, fontSize:11.5}}>
          {['11:47 Isolate · prod-app-07 · Elena J.','11:46 Kill kryptos.exe · Elena J.','11:32 Block IP 185.220.101.43 · auto','11:14 Tune rule D-044 · k.adams','10:51 Disable order-svc · M. Kato','10:02 Snapshot fileserver-02 · Elena J.'].map((l,i)=>(
            <div key={i} style={{display:'flex', alignItems:'baseline', gap:8, paddingBottom:6, borderBottom:'1px dashed var(--line-soft)'}}>
              <span className="mono tnum" style={{fontSize:10.5, color:'var(--fg-3)', minWidth:38}}>{l.slice(0,5)}</span>
              <span style={{fontSize:11.5}}>{l.slice(6)}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

window.MalwareScreen = function MalwareScreen() {
  const D = window.DATA;
  return (
    <div style={{padding:'18px 22px', overflow:'auto', height:'100%'}}>
      <div className="card">
        <div className="card-h"><h3>Sample analysis</h3><span className="chip mono" style={{marginLeft:'auto'}}>{D.malware.length} samples</span><button className="btn btn-sm"><Icon name="upload" size={12}/>Submit</button></div>
        <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:0}}>
          {D.malware.map((m,i)=>(
            <div key={m.hash} style={{padding:'14px 18px', borderRight: i%2===0?'1px solid var(--line-soft)':'none', borderBottom:'1px solid var(--line-soft)'}}>
              <div style={{display:'flex', alignItems:'center', gap:8, marginBottom:8}}>
                <span style={{fontSize:13, fontWeight:600}} className="mono">{m.file}</span>
                <span className="chip mono" style={{marginLeft:'auto', color: m.verdict==='MALICIOUS'?'var(--sev-crit)':m.verdict==='SUSPICIOUS'?'var(--sev-high)':'var(--sev-low)', borderColor:'currentColor', background:'transparent'}}>{m.verdict}</span>
              </div>
              <div className="mono" style={{fontSize:11, color:'var(--fg-3)', display:'flex', flexDirection:'column', gap:3, lineHeight:1.6}}>
                <span>sha256 · {m.hash}</span>
                <span>host  · {m.host}</span>
                <span>family · {m.family}</span>
                <span>engine · {m.engine}</span>
                <span>size  · {m.size}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

window.MonitorScreen = function MonitorScreen() {
  const D = window.DATA;
  return (
    <div style={{padding:'18px 22px', overflow:'auto', height:'100%', display:'grid', gridTemplateColumns:'1fr 1fr', gap:14, alignContent:'start'}}>
      {[
        ['Events / minute', 'pulse', D.spark24(3), '12,448', '+8.2%'],
        ['Auth attempts',   'lock',  D.spark24(7), '3,202',  '+0.4%'],
        ['Process exec',    'cpu',   D.spark24(2), '88,104', '-1.1%'],
        ['Network flows',   'network', D.spark24(9), '441K',  '+3.0%'],
      ].map(([l,ic,s,v,d])=>(
        <div key={l} className="card" style={{padding:14}}>
          <div style={{display:'flex', alignItems:'center', gap:8, marginBottom:8}}>
            <Icon name={ic} size={14} style={{color:'var(--accent)'}}/>
            <span className="eyebrow">{l}</span>
            <span className="mono tnum" style={{fontSize:11, color: d.startsWith('+')?'var(--sev-low)':'var(--sev-high)', marginLeft:'auto'}}>{d}</span>
          </div>
          <div style={{fontSize:24, fontWeight:600, letterSpacing:'-0.02em'}}>{v}</div>
          <div style={{marginTop:8}}><Spark data={s} w={400} h={48}/></div>
        </div>
      ))}
    </div>
  );
};

window.ReportsScreen = function ReportsScreen() {
  return (
    <div style={{padding:'18px 22px', overflow:'auto', height:'100%'}}>
      <div className="card">
        <div className="card-h"><h3>Reports & exports</h3><button className="btn btn-sm btn-primary" style={{marginLeft:'auto'}}><Icon name="plus" size={12}/>New report</button></div>
        {[
          ['SOC weekly digest','Mon 09:00 UTC','PDF','soc@wardex.dev','last sent · 4d'],
          ['Audit · response actions','daily 00:00 UTC','CSV','compliance@wardex.dev','last sent · 11h'],
          ['MITRE coverage','monthly','PDF','ciso@wardex.dev','queued · 9d'],
          ['Incident · ALT…7732','on-demand','PDF + JSON','—','generating…'],
        ].map((r,i)=>(
          <div key={i} style={{display:'grid', gridTemplateColumns:'1.5fr 1fr 80px 1.5fr 1fr', gap:12, padding:'10px 16px', borderBottom:'1px solid var(--line-soft)', alignItems:'center'}}>
            <span style={{fontSize:12.5, fontWeight:500}}>{r[0]}</span>
            <span className="mono" style={{fontSize:11, color:'var(--fg-3)'}}>{r[1]}</span>
            <span className="chip mono" style={{fontSize:10}}>{r[2]}</span>
            <span className="mono" style={{fontSize:11, color:'var(--fg-3)'}}>{r[3]}</span>
            <span className="mono" style={{fontSize:10.5, color: r[4].includes('generating')?'var(--accent)':'var(--fg-3)'}}>{r[4]}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

window.SettingsScreen = function SettingsScreen() {
  return (
    <div style={{padding:'18px 22px', overflow:'auto', height:'100%', display:'grid', gridTemplateColumns:'200px 1fr', gap:18}}>
      <nav style={{display:'flex', flexDirection:'column', gap:1}}>
        {['Profile','Workspace','RBAC & roles','SSO / SAML','API keys','Integrations','Notifications','Audit log','Billing'].map((l,i)=>(
          <button key={l} className="btn btn-ghost" style={{justifyContent:'flex-start', background: i===2?'var(--bg-3)':'transparent'}}>{l}</button>
        ))}
      </nav>
      <div className="card">
        <div className="card-h"><h3>RBAC & roles</h3><button className="btn btn-sm btn-primary" style={{marginLeft:'auto'}}><Icon name="plus" size={12}/>New role</button></div>
        {[
          ['L0 · Read-only','12','view alerts, fleet, reports'],
          ['L1 · Triage','24','+ assign, comment, suppress'],
          ['L2 · Responder','8','+ isolate, kill, block (with approval)'],
          ['L3 · Admin','3','+ rules, RBAC, integrations'],
          ['Auditor','2','read-only across all data'],
        ].map((r,i)=>(
          <div key={i} style={{display:'grid', gridTemplateColumns:'200px 60px 1fr 80px', gap:12, padding:'12px 16px', borderBottom:'1px solid var(--line-soft)', alignItems:'center'}}>
            <span style={{fontSize:13, fontWeight:500}}>{r[0]}</span>
            <span className="chip mono">{r[1]}</span>
            <span style={{fontSize:11.5, color:'var(--fg-3)'}}>{r[2]}</span>
            <button className="btn btn-sm btn-ghost" style={{justifyContent:'flex-end'}}>Edit</button>
          </div>
        ))}
      </div>
    </div>
  );
};
