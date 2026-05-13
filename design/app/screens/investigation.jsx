// app/screens/investigation.jsx — Hero: ransomware investigation workbench
// Three-pane: alert queue / case canvas / inspector
const { useState: iuS } = React;

window.InvestigationScreen = function InvestigationScreen() {
  const D = window.DATA;
  const [selPid, setSelPid] = iuS(7188);
  const [tab, setTab] = iuS('process');
  const sel = D.procs.find(p => p.pid === selPid) || D.procs[0];

  return (
    <div style={{display:'grid', gridTemplateColumns:'320px 1fr 360px', height:'100%', minHeight:0}}>
      {/* Left: alert queue (linked to incident) */}
      <AlertQueue/>

      {/* Center: case canvas */}
      <div style={{display:'flex', flexDirection:'column', minWidth:0, borderRight:'1px solid var(--line-soft)', overflow:'hidden'}}>
        <CaseHeader/>
        <CaseTabs tab={tab} setTab={setTab}/>
        <div style={{flex:1, overflow:'auto', padding:'12px 16px'}}>
          {tab==='process' && <ProcessTree selPid={selPid} setSelPid={setSelPid}/>}
          {tab==='timeline' && <Timeline/>}
          {tab==='graph' && <AttackGraph/>}
          {tab==='evidence' && <Evidence/>}
        </div>
      </div>

      {/* Right: inspector */}
      <Inspector sel={sel}/>
    </div>
  );
};

function AlertQueue() {
  const D = window.DATA;
  return (
    <div style={{display:'flex', flexDirection:'column', minWidth:0, borderRight:'1px solid var(--line-soft)', background:'var(--bg-0)'}}>
      <div style={{padding:'10px 14px', borderBottom:'1px solid var(--line-soft)', display:'flex', alignItems:'center', gap:8}}>
        <div className="eyebrow">Linked alerts</div>
        <span className="chip mono tnum" style={{fontSize:10, height:16, padding:'0 5px', marginLeft:'auto'}}>11</span>
      </div>
      <div style={{padding:'8px 10px', display:'flex', gap:6, borderBottom:'1px solid var(--line-soft)'}}>
        <button className="btn btn-sm" style={{background:'var(--bg-3)'}}>Incident</button>
        <button className="btn btn-sm btn-ghost">Host</button>
        <button className="btn btn-sm btn-ghost">Open</button>
      </div>
      <div style={{flex:1, overflow:'auto'}}>
        {D.alertsList.map((a, i) => (
          <div key={a.id} style={{
            padding:'8px 12px', borderBottom:'1px solid var(--line-soft)',
            background: i===0 ? 'var(--bg-3)' : 'transparent',
            cursor:'pointer', position:'relative',
          }}>
            {i===0 && <span style={{position:'absolute', left:0, top:0, bottom:0, width:2, background:'var(--accent)'}}/>}
            <div style={{display:'flex', alignItems:'center', gap:6, marginBottom:4}}>
              <Sev level={a.sev}/>
              <span className="mono" style={{fontSize:10, color:'var(--fg-3)', marginLeft:'auto'}}>{a.age}</span>
            </div>
            <div style={{fontSize:12, fontWeight:500, color:'var(--fg)', marginBottom:3, lineHeight:1.35}}>{a.title}</div>
            <div style={{display:'flex', alignItems:'center', gap:6, fontSize:10.5, color:'var(--fg-3)'}}>
              <span className="mono">{a.host}</span>
              <span>·</span>
              <span className="mono">{a.rule}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function CaseHeader() {
  const D = window.DATA;
  return (
    <div style={{padding:'12px 18px', borderBottom:'1px solid var(--line-soft)', background:'var(--bg-1)'}}>
      <div style={{display:'flex', alignItems:'center', gap:10, marginBottom:8}}>
        <Sev level="crit"/>
        <h2 style={{fontSize:16, fontWeight:600, letterSpacing:'-0.01em', margin:0, color:'var(--fg)'}}>{D.alert.title}</h2>
        <span className="chip mono" style={{fontSize:10}}>{D.alert.id}</span>
        <div style={{flex:1}}/>
        <button className="btn btn-sm"><Icon name="copy" size={12}/>Link</button>
        <button className="btn btn-sm"><Icon name="user" size={12}/>Assign</button>
        <button className="btn btn-sm btn-danger"><Icon name="zap" size={12}/>Isolate host</button>
      </div>
      <div style={{display:'flex', alignItems:'center', gap:18, fontSize:11.5, color:'var(--fg-2)'}}>
        <Stat label="Started" value={D.alert.started} mono/>
        <Stat label="Duration" value={D.alert.duration} mono accent="var(--sev-crit)"/>
        <Stat label="Score" value={`${D.alert.score}/100`} mono/>
        <Stat label="Confidence" value={`${Math.round(D.alert.confidence*100)}%`} mono/>
        <Stat label="Host" value={D.host.short} mono/>
        <Stat label="Rule" value={D.alert.rule} mono/>
        <div style={{flex:1}}/>
        <div className="row" style={{gap:4}}>
          {D.alert.mitre.slice(0,3).map(m=> <span key={m} className="chip mono" style={{fontSize:10}}>{m.split(' · ')[0]}</span>)}
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value, mono, accent }) {
  return (
    <div style={{display:'flex', flexDirection:'column', gap:1}}>
      <span style={{fontSize:9.5, letterSpacing:'0.08em', textTransform:'uppercase', color:'var(--fg-3)'}}>{label}</span>
      <span className={mono?'mono tnum':''} style={{fontSize:12, color: accent || 'var(--fg)', fontWeight:500}}>{value}</span>
    </div>
  );
}

function CaseTabs({ tab, setTab }) {
  const tabs = [
    ['process', 'Process tree', 'workbench'],
    ['timeline','Timeline','pulse'],
    ['graph',   'Attack graph','graph'],
    ['evidence','Evidence','doc'],
  ];
  return (
    <div style={{display:'flex', gap:0, padding:'0 16px', borderBottom:'1px solid var(--line-soft)', background:'var(--bg-1)'}}>
      {tabs.map(([id, label, icon]) => (
        <button key={id} onClick={()=>setTab(id)} style={{
          padding:'8px 12px', display:'flex', alignItems:'center', gap:6,
          background:'transparent', border:'none', cursor:'pointer',
          color: tab===id?'var(--fg)':'var(--fg-3)',
          fontSize:12, fontWeight: tab===id?500:400,
          borderBottom: tab===id?'1.5px solid var(--accent)':'1.5px solid transparent',
          marginBottom:-1,
        }}>
          <Icon name={icon} size={13} style={{color: tab===id?'var(--accent)':'inherit'}}/>
          {label}
        </button>
      ))}
      <div style={{flex:1}}/>
      <button className="btn btn-sm btn-ghost" style={{alignSelf:'center'}}><Icon name="filter" size={12}/>Filter</button>
    </div>
  );
}

function ProcessTree({ selPid, setSelPid }) {
  const D = window.DATA;
  return (
    <div className="card" style={{overflow:'hidden'}}>
      <div className="card-h"><h3>Process tree</h3><span className="chip mono" style={{fontSize:10}}>{D.procs.length} processes</span></div>
      <div style={{padding:'4px 0'}}>
        {/* header */}
        <div style={{display:'grid', gridTemplateColumns:'minmax(0,1fr) minmax(0,110px) 60px 90px', gap:10, padding:'6px 14px', borderBottom:'1px solid var(--line-soft)'}}>
          <span className="eyebrow">Process</span>
          <span className="eyebrow">User</span>
          <span className="eyebrow" style={{textAlign:'right'}}>CPU</span>
          <span className="eyebrow">Signature</span>
        </div>
        {D.procs.map(p => {
          const isSel = p.pid === selPid;
          const flagColor = p.flag === 'crit' ? 'var(--sev-crit)' : p.flag==='high'?'var(--sev-high)':p.flag==='med'?'var(--sev-med)':p.flag==='low'?'var(--sev-low)':null;
          return (
            <div key={p.pid} onClick={()=>setSelPid(p.pid)} style={{
              display:'grid', gridTemplateColumns:'minmax(0,1fr) minmax(0,110px) 60px 90px', gap:10,
              padding:'6px 14px',
              alignItems:'center',
              cursor:'pointer',
              background: isSel ? 'var(--bg-3)' : 'transparent',
              borderLeft: isSel ? '2px solid var(--accent)' : '2px solid transparent',
              borderBottom:'1px solid var(--line-soft)',
              position:'relative',
            }}>
              <div style={{display:'flex', alignItems:'center', gap:6, paddingLeft: p.d*16, minWidth:0, overflow:'hidden'}}>
                {p.d > 0 && <span style={{width:10, color:'var(--fg-4)', fontSize:10, flexShrink:0}}>└</span>}
                {flagColor && <span className="dot" style={{background:flagColor, boxShadow: p.flag==='crit'?`0 0 0 3px ${flagColor}33`:'none', flexShrink:0}}/>}
                <span className="mono" style={{fontSize:12, fontWeight: p.active?600:500, color: p.active?'var(--sev-crit)':'var(--fg)', flexShrink:0}}>{p.name}</span>
                <span className="mono tnum" style={{fontSize:10.5, color:'var(--fg-3)', flexShrink:0}}>#{p.pid}</span>
                <span className="mono" style={{fontSize:10.5, color:'var(--fg-4)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', minWidth:0}}>{p.cmd}</span>
              </div>
              <span className="mono" style={{fontSize:11, color:'var(--fg-2)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap'}}>{p.user}</span>
              <span className="mono tnum" style={{fontSize:11, textAlign:'right', color: p.cpu>50?'var(--sev-crit)':p.cpu>20?'var(--sev-high)':'var(--fg-2)'}}>{p.cpu}%</span>
              <span style={{fontSize:11, color: p.sig==='Unsigned'?'var(--sev-high)':'var(--fg-3)'}}>{p.sig}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function Timeline() {
  const D = window.DATA;
  return (
    <div className="card" style={{overflow:'hidden'}}>
      <div className="card-h"><h3>Timeline · last 9 minutes</h3><span className="chip mono" style={{fontSize:10}}>{D.events.length} events</span></div>
      <div>
        {D.events.map((e, i) => (
          <div key={i} style={{display:'grid', gridTemplateColumns:'76px 50px 60px 1fr 100px', gap:12, padding:'7px 14px', borderBottom:'1px solid var(--line-soft)', alignItems:'center', position:'relative'}}>
            <span className="mono tnum" style={{fontSize:11, color:'var(--fg-3)'}}>{e.t}</span>
            <Sev level={e.s}/>
            <span className="mono" style={{fontSize:10, color:'var(--fg-3)', letterSpacing:'0.08em'}}>{e.tag}</span>
            <span style={{fontSize:12, color:'var(--fg)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap'}}>{e.line}</span>
            <span className="mono" style={{fontSize:10.5, color:'var(--fg-3)'}}>{e.host}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function AttackGraph() {
  // SVG attack graph: user → host → process → c2
  const nodes = [
    {id:'svc', x:80, y:140, label:'order-svc', sub:'service', kind:'user'},
    {id:'host', x:240, y:140, label:'prod-app-07', sub:'host', kind:'host'},
    {id:'kry', x:420, y:80, label:'kryptos.exe', sub:'#7188', kind:'proc-crit'},
    {id:'ps',  x:420, y:200, label:'powershell.exe', sub:'#6618', kind:'proc'},
    {id:'c2',  x:620, y:80, label:'185.220.101.43', sub:'c2 · TOR', kind:'c2'},
    {id:'fs',  x:620, y:200, label:'fileserver-02', sub:'SMB share', kind:'host'},
  ];
  const edges = [
    ['svc','host','auth'],['host','ps','spawn'],['ps','kry','exec'],
    ['kry','c2','beacon'],['kry','fs','encrypt'],
  ];
  const find = id => nodes.find(n=>n.id===id);
  const fill = k => k==='proc-crit'?'var(--sev-crit-soft)' : k==='c2'?'var(--sev-crit-soft)' : k==='proc'?'var(--bg-3)' : 'var(--bg-2)';
  const stroke = k => k==='proc-crit'||k==='c2'?'var(--sev-crit)' : 'var(--line)';
  return (
    <div className="card" style={{overflow:'hidden'}}>
      <div className="card-h"><h3>Attack graph</h3><div className="row" style={{gap:6}}><button className="btn btn-sm btn-ghost"><Icon name="rotate" size={11}/>Auto layout</button></div></div>
      <div style={{background:'var(--bg-inset)', backgroundImage:'radial-gradient(circle at 1px 1px, var(--line-soft) 1px, transparent 0)', backgroundSize:'14px 14px'}}>
        <svg width="100%" height="320" viewBox="0 0 720 320">
          {edges.map(([a,b,l],i) => {
            const A = find(a), B = find(b);
            const danger = (B.kind==='proc-crit'||B.kind==='c2'||(a==='kry'));
            return <g key={i}>
              <line x1={A.x+50} y1={A.y} x2={B.x-50} y2={B.y} stroke={danger?'var(--sev-crit)':'var(--line-strong)'} strokeWidth="1.2" strokeDasharray={danger?'':'3 3'}/>
              <text x={(A.x+B.x)/2} y={(A.y+B.y)/2 - 6} fontSize="9.5" fill="var(--fg-3)" textAnchor="middle" fontFamily="JetBrains Mono">{l}</text>
            </g>;
          })}
          {nodes.map(n => (
            <g key={n.id}>
              <rect x={n.x-50} y={n.y-20} width="100" height="40" rx="6" fill={fill(n.kind)} stroke={stroke(n.kind)} strokeWidth="1"/>
              <text x={n.x} y={n.y-3} fontSize="11.5" fontWeight="600" fill={n.kind==='proc-crit'||n.kind==='c2'?'var(--sev-crit)':'var(--fg)'} textAnchor="middle">{n.label}</text>
              <text x={n.x} y={n.y+11} fontSize="9.5" fill="var(--fg-3)" textAnchor="middle" fontFamily="JetBrains Mono">{n.sub}</text>
            </g>
          ))}
        </svg>
      </div>
    </div>
  );
}

function Evidence() {
  const D = window.DATA;
  return (
    <div className="card" style={{overflow:'hidden'}}>
      <div className="card-h"><h3>Evidence bundle</h3><button className="btn btn-sm"><Icon name="download" size={12}/>Export bundle</button></div>
      <div style={{padding:14, display:'grid', gridTemplateColumns:'1fr 1fr', gap:12}}>
        {D.malware.map(m=>(
          <div key={m.hash} style={{padding:12, background:'var(--bg-inset)', borderRadius:6, border:'1px solid var(--line-soft)'}}>
            <div style={{display:'flex', alignItems:'center', gap:8, marginBottom:6}}>
              <span style={{fontSize:12, fontWeight:600}} className="mono">{m.file}</span>
              <span className="chip mono" style={{fontSize:10, color: m.verdict==='MALICIOUS'?'var(--sev-crit)':m.verdict==='SUSPICIOUS'?'var(--sev-high)':'var(--accent)', borderColor:'currentColor', background:'transparent'}}>{m.verdict}</span>
            </div>
            <div className="mono" style={{fontSize:10.5, color:'var(--fg-3)', display:'flex', flexDirection:'column', gap:2}}>
              <span>sha256 {m.hash}</span>
              <span>{m.engine} · {m.size}</span>
              {m.family!=='—' && <span>family · {m.family}</span>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function Inspector({ sel }) {
  const D = window.DATA;
  return (
    <aside style={{background:'var(--bg-1)', display:'flex', flexDirection:'column', overflow:'hidden'}}>
      <div style={{padding:'12px 16px', borderBottom:'1px solid var(--line-soft)'}}>
        <div className="eyebrow" style={{marginBottom:6}}>Inspector · process</div>
        <div style={{display:'flex', alignItems:'center', gap:8, marginBottom:6}}>
          <span className="mono" style={{fontSize:14, fontWeight:600, color: sel.flag==='crit'?'var(--sev-crit)':'var(--fg)'}}>{sel.name}</span>
          <span className="mono tnum" style={{fontSize:11, color:'var(--fg-3)'}}>#{sel.pid}</span>
        </div>
        <div className="mono" style={{fontSize:10.5, color:'var(--fg-3)', wordBreak:'break-all', lineHeight:1.45}}>{sel.cmd}</div>
      </div>

      <div style={{flex:1, overflow:'auto', padding:'10px 16px'}}>
        <InspSection title="Facts">
          <KV k="User"     v={sel.user} mono/>
          <KV k="Signature" v={sel.sig} mono color={sel.sig==='Unsigned'?'var(--sev-high)':null}/>
          <KV k="CPU"      v={sel.cpu+'%'} mono color={sel.cpu>50?'var(--sev-crit)':null}/>
          <KV k="Host"     v={D.host.short} mono/>
          <KV k="Parent"   v="rundll32.exe #7144" mono/>
        </InspSection>

        <InspSection title="MITRE ATT&CK">
          <div className="row" style={{flexWrap:'wrap', gap:5}}>
            {D.alert.mitre.map(m=><span key={m} className="chip mono" style={{fontSize:10}}>{m}</span>)}
          </div>
        </InspSection>

        <InspSection title="Network · last 5m">
          <div style={{padding:'8px 0', display:'flex', flexDirection:'column', gap:5}}>
            <NetLine to="185.220.101.43:8443" desc="TLS · TOR exit" sev="crit"/>
            <NetLine to="fileserver-02:445" desc="SMB write burst" sev="high"/>
            <NetLine to="dns-01:53"          desc="DNS · 122 queries" sev="med"/>
          </div>
        </InspSection>
      </div>

      {/* Approval dock */}
      <div style={{padding:'12px 16px', borderTop:'1px solid var(--line-soft)', background:'var(--bg-inset)'}}>
        <div style={{display:'flex', alignItems:'center', gap:8, marginBottom:10}}>
          <Icon name="zap" size={14} style={{color:'var(--sev-crit)'}}/>
          <span style={{fontSize:11, fontWeight:600, letterSpacing:'0.04em', textTransform:'uppercase'}}>Response — awaiting</span>
        </div>
        <div style={{display:'flex', flexDirection:'column', gap:6}}>
          <ResponseBtn label="Kill process" kbd="K" danger/>
          <ResponseBtn label="Isolate host" kbd="I" danger/>
          <ResponseBtn label="Block beacon IP" kbd="B"/>
          <ResponseBtn label="Quarantine binary" kbd="Q"/>
        </div>
        <div style={{marginTop:10, padding:'8px 10px', background:'var(--bg-1)', borderRadius:5, border:'1px solid var(--line-soft)', fontSize:10.5, color:'var(--fg-3)', display:'flex', alignItems:'center', gap:8}}>
          <Icon name="lock" size={12}/>
          <span>Actions require <strong style={{color:'var(--fg-2)'}}>L2+ approval</strong>. Audit signed.</span>
        </div>
      </div>
    </aside>
  );
}

function InspSection({ title, children }) {
  return (
    <div style={{marginBottom:14}}>
      <div className="eyebrow" style={{marginBottom:6}}>{title}</div>
      {children}
    </div>
  );
}
function KV({ k, v, mono, color }) {
  return (
    <div style={{display:'flex', justifyContent:'space-between', padding:'3px 0', borderBottom:'1px dashed var(--line-soft)'}}>
      <span style={{fontSize:11, color:'var(--fg-3)'}}>{k}</span>
      <span className={mono?'mono tnum':''} style={{fontSize:11.5, color: color || 'var(--fg)', textAlign:'right', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', maxWidth:'60%'}}>{v}</span>
    </div>
  );
}
function NetLine({ to, desc, sev }) {
  return (
    <div style={{display:'flex', alignItems:'center', gap:8}}>
      <span className="dot" style={{background:`var(--sev-${sev})`}}/>
      <span className="mono" style={{fontSize:11}}>{to}</span>
      <span style={{fontSize:10.5, color:'var(--fg-3)', marginLeft:'auto'}}>{desc}</span>
    </div>
  );
}
function ResponseBtn({ label, kbd, danger }) {
  return (
    <button className={`btn btn-sm ${danger?'btn-danger':''}`} style={{justifyContent:'space-between', width:'100%', height:28}}>
      <span>{label}</span>
      <Kbd k={kbd}/>
    </button>
  );
}
