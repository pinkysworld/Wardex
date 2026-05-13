// app/screens/dashboard.jsx — Command Center / overview
window.DashboardScreen = function DashboardScreen() {
  const D = window.DATA;
  return (
    <div style={{padding:'18px 22px', overflow:'auto', height:'100%', display:'grid', gridTemplateColumns:'2fr 1fr', gap:14}}>
      {/* Left column */}
      <div style={{display:'flex', flexDirection:'column', gap:14}}>
        {/* Hero KPI row */}
        <div style={{display:'grid', gridTemplateColumns:'repeat(4, 1fr)', gap:10}}>
          <KPI label="Active incidents"  value="1"   delta="+1"  spark={D.spark24(2)} danger/>
          <KPI label="Open alerts"        value="34" delta="+12" spark={D.spark24(5)} warn/>
          <KPI label="Hosts at risk"      value="3"  delta="+2"  spark={D.spark24(8)} warn/>
          <KPI label="Mean time to triage" value="2m 14s" delta="-18s" spark={D.spark24(11)}/>
        </div>

        {/* Incident strip */}
        <div className="card" style={{borderColor:'var(--sev-crit-soft)', boxShadow:'0 0 0 1px var(--sev-crit-soft) inset'}}>
          <div style={{padding:'14px 18px', display:'flex', alignItems:'center', gap:14, background:'linear-gradient(to right, var(--sev-crit-soft), transparent 60%)'}}>
            <div style={{width:36, height:36, borderRadius:8, background:'var(--sev-crit)', color:'#fff', display:'flex', alignItems:'center', justifyContent:'center'}}>
              <Icon name="fire" size={18}/>
            </div>
            <div style={{minWidth:0, flex:1}}>
              <div style={{display:'flex', alignItems:'center', gap:8, marginBottom:2}}>
                <Sev level="crit"/>
                <span style={{fontSize:14, fontWeight:600}}>{D.alert.title}</span>
                <span className="mono" style={{fontSize:11, color:'var(--fg-3)'}}>{D.alert.id}</span>
              </div>
              <div className="mono" style={{fontSize:11, color:'var(--fg-3)'}}>
                {D.host.short} · started {D.alert.started} · {D.alert.duration} · {D.alert.counts.files.toLocaleString()} files encrypted
              </div>
            </div>
            <button className="btn"><Icon name="eye" size={12}/>Investigate</button>
            <button className="btn btn-danger"><Icon name="zap" size={12}/>Isolate host</button>
          </div>
        </div>

        {/* Alert feed */}
        <div className="card">
          <div className="card-h">
            <h3>Alert feed · last 60m</h3>
            <div className="row" style={{gap:6, marginLeft:'auto'}}>
              <button className="btn btn-sm btn-ghost"><Icon name="filter" size={12}/>Filters</button>
              <button className="btn btn-sm btn-ghost"><Icon name="pause" size={12}/>Pause</button>
            </div>
          </div>
          <div>
            {D.alertsList.slice(0,8).map((a,i)=>(
              <div key={a.id} style={{display:'grid', gridTemplateColumns:'56px 1fr 130px 110px 70px', gap:12, padding:'8px 14px', borderBottom:'1px solid var(--line-soft)', alignItems:'center'}}>
                <Sev level={a.sev}/>
                <span style={{fontSize:12.5, color:'var(--fg)'}}>{a.title}</span>
                <span className="mono" style={{fontSize:11, color:'var(--fg-3)'}}>{a.host}</span>
                <span className="mono" style={{fontSize:10.5, color:'var(--fg-4)'}}>{a.rule}</span>
                <span className="mono tnum" style={{fontSize:11, color:'var(--fg-3)', textAlign:'right'}}>{a.age}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Right column */}
      <div style={{display:'flex', flexDirection:'column', gap:14}}>
        <div className="card">
          <div className="card-h"><h3>Approvals queue</h3><span className="chip mono" style={{fontSize:10, marginLeft:'auto'}}>{D.approvals.length}</span></div>
          <div>
            {D.approvals.map(a=>(
              <div key={a.id} style={{padding:'10px 14px', borderBottom:'1px solid var(--line-soft)'}}>
                <div style={{display:'flex', alignItems:'center', gap:6, marginBottom:3}}>
                  <span className="mono" style={{fontSize:11, color:'var(--fg-3)'}}>{a.id}</span>
                  <span style={{fontSize:12, fontWeight:500}}>{a.action}</span>
                  <span className="chip" style={{marginLeft:'auto', fontSize:10, color: a.risk==='high'?'var(--sev-crit)':'var(--sev-med)', borderColor:'currentColor', background:'transparent'}}>{a.risk}</span>
                </div>
                <div className="mono" style={{fontSize:10.5, color:'var(--fg-3)', marginBottom:6}}>{a.target}</div>
                <div style={{display:'flex', gap:6}}>
                  <button className="btn btn-sm btn-primary" style={{flex:1, justifyContent:'center'}}>Approve</button>
                  <button className="btn btn-sm" style={{flex:1, justifyContent:'center'}}>Deny</button>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-h"><h3>MITRE coverage · 7d</h3></div>
          <div style={{padding:14}}>
            <MitreHeatmap/>
          </div>
        </div>
      </div>
    </div>
  );
};

function KPI({ label, value, delta, spark, danger, warn }) {
  return (
    <div className="card" style={{padding:'12px 14px'}}>
      <div className="eyebrow" style={{marginBottom:6}}>{label}</div>
      <div style={{display:'flex', alignItems:'flex-end', gap:10, justifyContent:'space-between'}}>
        <div>
          <div style={{fontSize:22, fontWeight:600, letterSpacing:'-0.02em', color: danger?'var(--sev-crit)':'var(--fg)'}}>{value}</div>
          <div className="mono" style={{fontSize:10.5, color: delta.startsWith('+')&&!label.includes('triage')?'var(--sev-crit)': delta.startsWith('-')?'var(--sev-low)':'var(--fg-3)'}}>{delta} · 24h</div>
        </div>
        <Spark data={spark} w={70} h={28} danger={danger} warn={warn}/>
      </div>
    </div>
  );
}

function MitreHeatmap() {
  const tactics = ['Initial','Execution','Persist.','Privesc','Defense','Cred','Discovery','Lateral','C2','Impact'];
  return (
    <div style={{display:'grid', gridTemplateColumns:'repeat(10, 1fr)', gap:3}}>
      {tactics.map((t,col)=>(
        <div key={t} style={{display:'flex', flexDirection:'column', gap:3}}>
          <div style={{fontSize:9, color:'var(--fg-3)', textAlign:'center', marginBottom:2, transform:'rotate(0deg)', whiteSpace:'nowrap'}}>{t}</div>
          {Array.from({length:6}).map((_,row)=>{
            const v = ((col*7 + row*3 + (col===9?12:0) + (col===4&&row===2?8:0)) % 10);
            const a = v / 10;
            const color = col===9||col===5? `rgba(216,58,58,${0.15 + a*0.7})` : `rgba(47,92,242,${0.1 + a*0.55})`;
            return <div key={row} style={{height:14, background:v===0?'var(--bg-2)':color, borderRadius:2}}/>;
          })}
        </div>
      ))}
    </div>
  );
}
