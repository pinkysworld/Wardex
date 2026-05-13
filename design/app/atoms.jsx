// app/atoms.jsx — shared atoms (Sparkline, Sev, Chip, Kbd, MiniBars, RiskBar)

window.Spark = function Spark({ data, w=80, h=22, danger=false, warn=false }) {
  const min = Math.min(...data), max = Math.max(...data);
  const r = max - min || 1;
  const step = w / (data.length - 1);
  const pts = data.map((v,i) => `${i*step},${h - ((v-min)/r)*(h-2) - 1}`).join(' ');
  const last = data[data.length-1], lx = (data.length-1)*step, ly = h - ((last-min)/r)*(h-2) - 1;
  const cls = danger ? 'spark danger' : warn ? 'spark warn' : 'spark';
  return (
    <svg className={cls} width={w} height={h} viewBox={`0 0 ${w} ${h}`}>
      <polyline points={pts} fill="none" stroke="currentColor" strokeWidth="1.2" />
      <circle cx={lx} cy={ly} r="1.6" fill="currentColor" />
    </svg>
  );
};
window.Sev = function Sev({ level, children }) {
  const map = { crit:['sev-crit','CRIT'], high:['sev-high','HIGH'], med:['sev-med','MED'], low:['sev-low','LOW'], info:['sev-info','INFO'] };
  const [cls, dflt] = map[level] || map.info;
  return <span className={`sev ${cls}`}>{children ?? dflt}</span>;
};
window.Chip = function Chip({ children, mono, style }) {
  return <span className={`chip${mono?' mono':''}`} style={style}>{children}</span>;
};
window.Kbd = function Kbd({ k }) { return <span className="kbd">{k}</span>; };
window.RiskBar = function RiskBar({ v }) {
  const color = v>=80 ? 'var(--sev-crit)' : v>=50 ? 'var(--sev-high)' : v>=25 ? 'var(--sev-med)' : 'var(--sev-low)';
  return (
    <div style={{display:'flex', alignItems:'center', gap:8}}>
      <div style={{width:60, height:4, background:'var(--bg-2)', borderRadius:2, overflow:'hidden'}}>
        <div style={{width:`${v}%`, height:'100%', background:color}}/>
      </div>
      <span className="mono tnum" style={{fontSize:11, color:'var(--fg-2)', minWidth:24, textAlign:'right'}}>{v}</span>
    </div>
  );
};
window.MiniBars = function MiniBars({ data, w=120, h=24, color='var(--accent)' }) {
  const max = Math.max(...data, 1);
  const bw = w / data.length;
  return (
    <svg width={w} height={h}>
      {data.map((v,i)=><rect key={i} x={i*bw+0.5} y={h - (v/max)*h} width={bw-1.5} height={(v/max)*h} fill={color} opacity={0.4 + 0.6*(v/max)}/>)}
    </svg>
  );
};
window.OsIcon = function OsIcon({ os, size=12 }) {
  const c = { win:'#3b82f6', lin:'#f59e0b', mac:'#a3a3a3' }[os] || 'var(--fg-3)';
  const t = { win:'W', lin:'L', mac:'M' }[os] || '?';
  return <span style={{display:'inline-flex',alignItems:'center',justifyContent:'center',width:size+4,height:size+4,borderRadius:3,background:`${c}22`,color:c,fontSize:9,fontWeight:700,fontFamily:'JetBrains Mono, monospace'}}>{t}</span>;
};
window.StatusDot = function StatusDot({ s }) {
  const c = {ISOLATED:'var(--sev-crit)','AT RISK':'var(--sev-high)',INVESTIGATE:'var(--sev-high)',HEALTHY:'var(--accent)',STALE:'var(--fg-4)'}[s] || 'var(--fg-3)';
  return <span className="dot" style={{background:c, boxShadow:`0 0 0 3px ${c}22`}}/>;
};
