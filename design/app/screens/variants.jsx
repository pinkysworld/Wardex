// app/screens/variants.jsx — Aesthetic variant explorations of the workbench
// Each is a self-contained mini-mock that re-imagines the investigation surface.

window.VariantTerminal = function VariantTerminal() {
  const D = window.DATA;
  return (
    <div className="theme-amber" style={{height:'100%', background:'var(--bg-0)', color:'var(--fg)', fontFamily:'var(--font-mono)', overflow:'hidden', display:'flex', flexDirection:'column'}}>
      <div style={{padding:'10px 16px', borderBottom:'1px solid var(--line)', display:'flex', alignItems:'center', gap:10, fontSize:12, letterSpacing:'0.04em'}}>
        <span style={{color:'var(--accent)'}}>● wardex</span>
        <span style={{color:'var(--fg-3)'}}>investigation://{D.alert.id.toLowerCase()}</span>
        <span style={{marginLeft:'auto', color:'var(--sev-crit)'}}>[CRIT] ACTIVE</span>
      </div>
      <div style={{flex:1, padding:'14px 18px', overflow:'auto', fontSize:12.5, lineHeight:1.55}}>
        <pre style={{margin:0, fontFamily:'inherit', color:'var(--fg-2)', whiteSpace:'pre-wrap'}}>{`╭─ INCIDENT ─────────────────────────────────────────────────────────────╮
│  ${D.alert.title.padEnd(54)}      │
│  rule=${D.alert.rule}                  │
│  host=${D.host.short}   started=${D.alert.started}   dur=${D.alert.duration}      │
│  score=${D.alert.score}/100   conf=${(D.alert.confidence*100).toFixed(0)}%   files=${D.alert.counts.files.toLocaleString().padEnd(8)}                │
╰────────────────────────────────────────────────────────────────────────╯`}</pre>
        <div style={{marginTop:14, color:'var(--accent)'}}>→ ps --tree --flag</div>
        <pre style={{margin:'6px 0 0', fontFamily:'inherit', whiteSpace:'pre'}}>
{D.procs.map(p => {
  const ind = '  '.repeat(p.d);
  const mark = p.flag==='crit'?'\u001b[CRIT]':p.flag==='high'?'[HIGH]':p.flag==='med'?'[MED] ':p.flag==='low'?'[LOW] ':'      ';
  const c = p.flag==='crit'?'var(--sev-crit)':p.flag==='high'?'var(--sev-high)':p.flag==='med'?'var(--sev-med)':'var(--fg-3)';
  return <div key={p.pid} style={{color: p.flag?c:'var(--fg-2)'}}>{ind}{p.flag==='crit'?'▶ ':p.d>0?'└─':'• '}<span style={{color:c}}>{p.name.padEnd(20)}</span>#{p.pid.toString().padEnd(6)} {p.cpu.toString().padStart(3)}%  {p.sig}</div>;
})}
        </pre>
        <div style={{marginTop:14, color:'var(--accent)'}}>→ events --tail 6</div>
        <pre style={{margin:'6px 0 0', fontFamily:'inherit', whiteSpace:'pre', color:'var(--fg-2)'}}>
{D.events.slice(0,6).map((e,i)=>(
  <div key={i} style={{color: e.s==='crit'?'var(--sev-crit)':e.s==='high'?'var(--sev-high)':'var(--fg-2)'}}>
    {e.t}  [{e.s.toUpperCase().padEnd(4)}] {e.tag.padEnd(8)} {e.line}
  </div>
))}
        </pre>
        <div style={{marginTop:14}}>
          <span style={{color:'var(--accent)'}}>→</span> <span style={{color:'var(--fg-3)'}}>respond</span> <span style={{background:'var(--sev-crit)', color:'#fff', padding:'1px 6px'}}>isolate</span> {D.host.short} <span style={{color:'var(--fg-4)'}}>[awaiting approval · L2]</span><span style={{animation:'blink 1s steps(2) infinite', color:'var(--accent)'}}>█</span>
        </div>
      </div>
      <style>{`@keyframes blink { 50% { opacity: 0; } }`}</style>
    </div>
  );
};

window.VariantTimelineFirst = function VariantTimelineFirst() {
  const D = window.DATA;
  // Severity-painted scrollable single-track timeline
  return (
    <div style={{height:'100%', overflow:'auto', padding:'18px 22px', background:'var(--bg-inset)'}}>
      <div style={{display:'flex', alignItems:'center', gap:10, marginBottom:14}}>
        <Sev level="crit"/>
        <span style={{fontSize:16, fontWeight:600}}>{D.alert.title}</span>
        <span className="mono" style={{fontSize:11, color:'var(--fg-3)'}}>{D.host.short} · {D.alert.duration}</span>
        <button className="btn btn-sm btn-danger" style={{marginLeft:'auto'}}><Icon name="zap" size={12}/>Isolate</button>
      </div>
      <div className="card">
        <div style={{position:'relative', padding:'14px 0'}}>
          {/* time axis */}
          <div style={{position:'absolute', left:120, right:24, top:14, bottom:14, borderLeft:'2px solid var(--line-strong)'}}/>
          {D.events.map((e,i)=>{
            const c = e.s==='crit'?'var(--sev-crit)':e.s==='high'?'var(--sev-high)':e.s==='med'?'var(--sev-med)':e.s==='low'?'var(--sev-low)':'var(--fg-3)';
            return (
              <div key={i} style={{display:'grid', gridTemplateColumns:'100px 24px 1fr', gap:0, alignItems:'flex-start', padding:'10px 14px'}}>
                <div style={{textAlign:'right', paddingRight:14}}>
                  <div className="mono tnum" style={{fontSize:11, color:'var(--fg)'}}>{e.t.slice(0,5)}</div>
                  <div className="mono" style={{fontSize:9.5, color:'var(--fg-3)'}}>{e.t.slice(6)}</div>
                </div>
                <div style={{position:'relative', height:'100%'}}>
                  <div style={{position:'absolute', left:5, top:5, width:14, height:14, borderRadius:'50%', background:'var(--bg-0)', border:`2.5px solid ${c}`, boxShadow: e.s==='crit'?`0 0 0 4px ${c}22`:'none'}}/>
                </div>
                <div style={{paddingLeft:14, paddingBottom:4}}>
                  <div style={{display:'flex', alignItems:'center', gap:8, marginBottom:2}}>
                    <Sev level={e.s}/>
                    <span className="mono" style={{fontSize:10, color:'var(--fg-4)'}}>{e.tag}</span>
                  </div>
                  <div style={{fontSize:13, color:'var(--fg)'}}>{e.line}</div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

window.VariantGraphFirst = function VariantGraphFirst() {
  const D = window.DATA;
  return (
    <div className="theme-dark" style={{height:'100%', background:'var(--bg-0)', overflow:'hidden', display:'grid', gridTemplateColumns:'1fr 300px'}}>
      <div style={{position:'relative', overflow:'hidden', background:'radial-gradient(circle at 30% 40%, rgba(91,133,255,0.08), transparent 60%)'}}>
        <div style={{padding:'14px 18px', display:'flex', alignItems:'center', gap:10, borderBottom:'1px solid var(--line-soft)'}}>
          <Sev level="crit"/>
          <span style={{fontSize:14, fontWeight:600, color:'var(--fg)'}}>{D.alert.title}</span>
          <span className="mono" style={{fontSize:11, color:'var(--fg-3)', marginLeft:'auto'}}>graph · ego({D.host.short})</span>
        </div>
        <svg width="100%" height="92%" viewBox="0 0 800 500" style={{background:'transparent'}}>
          <defs>
            <radialGradient id="pulse" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#d83a3a" stopOpacity="0.4"/>
              <stop offset="100%" stopColor="#d83a3a" stopOpacity="0"/>
            </radialGradient>
          </defs>
          {/* edges */}
          <g stroke="rgba(91,133,255,0.35)" strokeWidth="1" fill="none">
            <path d="M120,250 Q250,170 400,250"/>
            <path d="M400,250 Q500,150 660,120"/>
            <path d="M400,250 Q500,350 660,380"/>
            <path d="M400,250 Q300,360 200,420"/>
            <path d="M400,250 L400,90"/>
          </g>
          {/* danger edges */}
          <g stroke="#d83a3a" strokeWidth="1.6" fill="none">
            <path d="M400,250 Q550,200 700,180"/>
            <path d="M400,250 Q480,280 580,300"/>
          </g>
          {/* central pulsing node */}
          <circle cx="400" cy="250" r="80" fill="url(#pulse)"/>
          <circle cx="400" cy="250" r="32" fill="#3a1818" stroke="#d83a3a" strokeWidth="1.6"/>
          <text x="400" y="248" textAnchor="middle" fontSize="12" fontWeight="600" fill="#e6e9ef">prod-app-07</text>
          <text x="400" y="262" textAnchor="middle" fontSize="9.5" fontFamily="JetBrains Mono" fill="#d83a3a">ISOLATED</text>
          {/* satellite nodes */}
          {[
            [120,250,'order-svc','svc'],
            [400,90,'AD · contoso','identity'],
            [660,120,'185.220.101.43','c2 · TOR',true],
            [660,380,'fileserver-02','smb'],
            [200,420,'jump-01','rdp'],
            [700,180,'kryptos.exe','#7188',true],
            [580,300,'vssadmin','shadow del',true],
          ].map(([x,y,l,s,d],i)=>(
            <g key={i}>
              <circle cx={x} cy={y} r="22" fill={d?'#3a1818':'#1f2530'} stroke={d?'#d83a3a':'#5b85ff'} strokeWidth="1.2"/>
              <text x={x} y={y+38} textAnchor="middle" fontSize="11" fontWeight="600" fill={d?'#d83a3a':'#e6e9ef'}>{l}</text>
              <text x={x} y={y+50} textAnchor="middle" fontSize="9" fontFamily="JetBrains Mono" fill="#7a8395">{s}</text>
            </g>
          ))}
        </svg>
      </div>
      <aside style={{background:'var(--bg-1)', borderLeft:'1px solid var(--line-soft)', padding:18, overflow:'auto', color:'var(--fg)'}}>
        <div className="eyebrow" style={{marginBottom:8}}>Blast radius</div>
        <div style={{fontSize:32, fontWeight:600, color:'var(--sev-crit)'}}>1 host</div>
        <div style={{fontSize:12, color:'var(--fg-3)', marginBottom:18}}>contained · {D.alert.counts.files.toLocaleString()} files affected</div>
        <div className="eyebrow" style={{marginBottom:8}}>Reachable next</div>
        {[['fileserver-02','smb · open share','high'],['ad-dc-01','tier-0 · firewalled','med'],['k8s-orders','svc-account auth','high']].map((r,i)=>(
          <div key={i} style={{padding:'10px 0', borderBottom:'1px solid var(--line-soft)'}}>
            <div style={{display:'flex', justifyContent:'space-between', alignItems:'center'}}><span className="mono" style={{fontSize:12, color:'var(--fg)'}}>{r[0]}</span><Sev level={r[2]}/></div>
            <div style={{fontSize:11, color:'var(--fg-3)', marginTop:2}}>{r[1]}</div>
          </div>
        ))}
        <button className="btn btn-danger" style={{width:'100%', justifyContent:'center', marginTop:14}}><Icon name="zap" size={13}/>Contain lateral paths</button>
      </aside>
    </div>
  );
};

window.VariantStoryline = function VariantStoryline() {
  // Editorial / report-style — narrative summary that an analyst would send to leadership
  const D = window.DATA;
  return (
    <div style={{height:'100%', overflow:'auto', background:'#fbfaf7', padding:'40px 0'}}>
      <article style={{maxWidth:680, margin:'0 auto', padding:'0 24px', fontFamily:'Georgia, "Source Serif Pro", serif', color:'#1c1a17', lineHeight:1.65}}>
        <div className="row" style={{gap:10, marginBottom:8, fontFamily:'var(--font-sans)'}}>
          <Sev level="crit"/>
          <span className="mono" style={{fontSize:11, color:'#7a6f5f'}}>{D.alert.id} · {D.NOW}</span>
        </div>
        <h1 style={{fontSize:36, fontWeight:600, letterSpacing:'-0.02em', lineHeight:1.15, marginTop:6, marginBottom:8}}>A ransomware operator reached an order-tier host in under five minutes.</h1>
        <p style={{fontSize:17, color:'#5a5040', marginTop:0}}>At 11:42 UTC, an unsigned MSI began executing on <span className="mono">prod-app-07</span>. Four minutes later, <span className="mono">kryptos.exe</span> had encrypted 23,847 files and was beaconing to a TOR exit.</p>
        <div style={{borderTop:'1px solid #ddd2bd', borderBottom:'1px solid #ddd2bd', padding:'14px 0', margin:'24px 0', display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:14, fontFamily:'var(--font-sans)'}}>
          {[['Duration','4m 51s'],['Files','23.8k'],['Hosts','1 isolated'],['Confidence','94%']].map(([k,v])=>(
            <div key={k}><div className="eyebrow">{k}</div><div style={{fontSize:18, fontWeight:600, color:'#1c1a17', fontFamily:'var(--font-sans)', marginTop:2}}>{v}</div></div>
          ))}
        </div>
        <h2 style={{fontSize:22, marginTop:30, marginBottom:6}}>How it unfolded</h2>
        <p>The intrusion began as a routine-looking install. An <span className="mono">msiexec</span> call from <span className="mono">\\\\share\\update.msi</span> ran under the <span className="mono">order-svc</span> service principal — itself a sign of pre-existing access, not initial entry. From there the operator pivoted into a hidden, base64-encoded PowerShell session, then loaded a DLL via <span className="mono">rundll32</span> and finally launched <span className="mono">kryptos.exe</span>.</p>
        <p>The detonator deleted shadow copies, opened LSASS for credential reading, and started a TLS beacon to <span className="mono">185.220.101.43</span>, a known TOR exit. File encryption began moments later, sweeping <span className="mono">D:\\orders\\</span> at roughly 300 files per second.</p>
        <h2 style={{fontSize:22, marginTop:30, marginBottom:6}}>What we did</h2>
        <p>Wardex isolated <span className="mono">prod-app-07</span> at 11:47, killed the encrypting process tree, blocked the beacon destination at the edge, and disabled the abused service principal. Lateral reach to <span className="mono">fileserver-02</span> was contained before any SMB writes succeeded against shared volumes.</p>
        <p style={{fontFamily:'var(--font-sans)', fontSize:13, color:'#7a6f5f', marginTop:30}}>Drafted by Wardex · sign off to send →</p>
        <div className="row" style={{gap:8, marginTop:14}}>
          <button className="btn btn-primary"><Icon name="send" size={12}/>Send to leadership</button>
          <button className="btn"><Icon name="copy" size={12}/>Copy markdown</button>
        </div>
      </article>
    </div>
  );
};

window.VariantAssistant = function VariantAssistant() {
  // AI copilot-led layout — Wardex Assist driving the investigation
  const D = window.DATA;
  return (
    <div style={{height:'100%', display:'grid', gridTemplateColumns:'1fr 360px', overflow:'hidden'}}>
      <div style={{display:'flex', flexDirection:'column', overflow:'hidden'}}>
        <div style={{padding:'14px 18px', borderBottom:'1px solid var(--line-soft)', display:'flex', alignItems:'center', gap:10}}>
          <Icon name="bot" size={16} style={{color:'var(--accent)'}}/>
          <span style={{fontSize:14, fontWeight:600}}>Wardex Assist</span>
          <span className="chip mono" style={{fontSize:10}}>investigating · {D.alert.id}</span>
        </div>
        <div style={{flex:1, overflow:'auto', padding:'18px 24px', display:'flex', flexDirection:'column', gap:16, background:'var(--bg-inset)'}}>
          <AssistMsg who="Assist" t="11:47:12">
            <p style={{margin:'0 0 8px'}}>I&rsquo;m seeing a ransomware detonation pattern on <span className="mono">prod-app-07</span>. Confidence <strong>94%</strong>. Started 4m 51s ago.</p>
            <p style={{margin:'0 0 8px'}}>Three signals correlate inside the same process tree:</p>
            <ol style={{margin:'0 0 8px 20px', padding:0}}>
              <li>LSASS read from a child of <span className="mono">rundll32</span></li>
              <li>23,847 files renamed with <span className="mono">.kryptos</span> extension in 4 seconds</li>
              <li>TLS beacon to a known TOR exit (<span className="mono">185.220.101.43</span>)</li>
            </ol>
            <p style={{margin:0}}>I&rsquo;d recommend isolating now and killing PID 7188. Want me to draft those actions?</p>
            <div className="row" style={{gap:6, marginTop:10}}>
              <button className="btn btn-sm btn-primary">Yes — draft actions</button>
              <button className="btn btn-sm">Show evidence</button>
              <button className="btn btn-sm btn-ghost">Wait</button>
            </div>
          </AssistMsg>
          <AssistMsg who="You" me t="11:47:38">
            <p style={{margin:0}}>Draft them. Also check if order-svc is used on other hosts.</p>
          </AssistMsg>
          <AssistMsg who="Assist" t="11:47:42">
            <p style={{margin:'0 0 8px'}}>Drafted. Both require L2+ approval — your role qualifies.</p>
            <div style={{border:'1px solid var(--line-soft)', borderRadius:6, overflow:'hidden', background:'var(--bg-0)'}}>
              {[['Isolate host','prod-app-07','high'],['Kill process','kryptos.exe #7188','high'],['Block IP','185.220.101.43','med'],['Disable account','order-svc','med']].map(r=>(
                <div key={r[0]} style={{display:'grid', gridTemplateColumns:'130px 1fr 70px 90px', gap:10, padding:'8px 12px', borderBottom:'1px solid var(--line-soft)', alignItems:'center'}}>
                  <span style={{fontSize:12, fontWeight:500}}>{r[0]}</span>
                  <span className="mono" style={{fontSize:11, color:'var(--fg-3)'}}>{r[1]}</span>
                  <span className="chip" style={{fontSize:10, color: r[2]==='high'?'var(--sev-crit)':'var(--sev-med)', borderColor:'currentColor', background:'transparent'}}>{r[2]}</span>
                  <button className="btn btn-sm btn-primary" style={{justifyContent:'center'}}>Approve</button>
                </div>
              ))}
            </div>
            <p style={{margin:'10px 0 0', fontSize:12, color:'var(--fg-3)'}}>On <span className="mono">order-svc</span>: it&rsquo;s authenticated from 3 other hosts in last 24h. None show suspicious activity yet — I&rsquo;m watching.</p>
          </AssistMsg>
        </div>
        <div style={{padding:'12px 18px', borderTop:'1px solid var(--line-soft)', background:'var(--bg-0)'}}>
          <div style={{display:'flex', alignItems:'center', gap:8, padding:'8px 12px', border:'1px solid var(--line)', borderRadius:8, background:'var(--bg-1)'}}>
            <Icon name="zap" size={14} style={{color:'var(--accent)'}}/>
            <input placeholder="Ask Assist or run a slash command…" style={{flex:1, border:'none', background:'transparent', outline:'none', fontSize:13, color:'var(--fg)'}}/>
            <Kbd k="/"/><Kbd k="↵"/>
          </div>
        </div>
      </div>
      <aside style={{background:'var(--bg-1)', borderLeft:'1px solid var(--line-soft)', padding:18, overflow:'auto'}}>
        <div className="eyebrow" style={{marginBottom:8}}>Context Assist is using</div>
        {['Process tree (PID 7188 and ancestry)','11 linked alerts','4 malware verdicts','5m of beacon traffic','RBAC policy v3','Last week of order-svc baseline'].map((c,i)=>(
          <div key={i} style={{padding:'8px 0', borderBottom:'1px solid var(--line-soft)', display:'flex', alignItems:'center', gap:8}}>
            <Icon name="layers" size={12} style={{color:'var(--accent)'}}/>
            <span style={{fontSize:12, color:'var(--fg-2)'}}>{c}</span>
          </div>
        ))}
        <div className="eyebrow" style={{marginTop:18, marginBottom:8}}>Suggested next</div>
        {['Pull memory image of PID 7188','Diff baseline of order-svc','Hunt: kryptos.exe across fleet'].map((s,i)=>(
          <button key={i} className="btn btn-sm" style={{width:'100%', justifyContent:'flex-start', marginBottom:6}}><Icon name="arrowR" size={11}/>{s}</button>
        ))}
      </aside>
    </div>
  );
};

function AssistMsg({ who, me, t, children }) {
  return (
    <div style={{display:'flex', gap:10, maxWidth: me?'80%':'100%', alignSelf: me?'flex-end':'flex-start'}}>
      {!me && <div style={{width:26, height:26, borderRadius:6, background:'var(--accent-soft)', color:'var(--accent)', display:'flex', alignItems:'center', justifyContent:'center', flexShrink:0}}><Icon name="bot" size={14}/></div>}
      <div style={{flex:1, minWidth:0}}>
        <div style={{display:'flex', alignItems:'baseline', gap:8, marginBottom:4}}>
          <span style={{fontSize:11.5, fontWeight:600, color: me?'var(--accent)':'var(--fg)'}}>{who}</span>
          <span className="mono" style={{fontSize:10, color:'var(--fg-3)'}}>{t}</span>
        </div>
        <div style={{padding:'10px 14px', background: me?'var(--accent-soft)':'var(--bg-0)', border:'1px solid var(--line-soft)', borderRadius:8, fontSize:13, lineHeight:1.55, color:'var(--fg)'}}>{children}</div>
      </div>
      {me && <div style={{width:26, height:26, borderRadius:6, background:'var(--bg-3)', color:'var(--fg-2)', display:'flex', alignItems:'center', justifyContent:'center', fontSize:10, fontWeight:700, flexShrink:0}}>EJ</div>}
    </div>
  );
}
