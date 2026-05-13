// app/data.js — mock data shaped around the ransomware hero scenario.
window.DATA = (() => {
  const NOW = "11 May 2026 · 11:47 UTC";

  const sections = [
    { group: 'Command', items: [['command','Command Center']] },
    { group: 'Monitor', items: [
      ['dashboard','Dashboard'],
      ['launchpad','Operator Launchpad'],
      ['monitor','Live Monitor'],
      ['reports','Reports & Exports'],
    ]},
    { group: 'Investigate', items: [
      ['investigation','Investigation', true],
      ['assistant','Analyst Assistant'],
      ['detection','Threat Detection'],
      ['ueba','UEBA'],
      ['ndr','NDR'],
      ['graph','Attack Graph'],
    ]},
    { group: 'Respond', items: [['fleet','Fleet & Agents'],['approvals','Approvals', null, 3]] },
    { group: 'Protect', items: [
      ['malware','Malware Scanning'],
      ['policy','Security Policy'],
      ['email','Email Security'],
    ]},
    { group: 'Manage', items: [['settings','Settings'],['help','Help & Docs']] },
  ];

  const sectionIcons = {
    command:'command', dashboard:'grid', launchpad:'zap', monitor:'pulse', reports:'doc',
    investigation:'workbench', assistant:'bot', detection:'bug', ueba:'user', ndr:'network', graph:'graph',
    fleet:'server', approvals:'check',
    malware:'shield', policy:'flag', email:'mail',
    settings:'settings', help:'help',
  };

  const host = {
    id: 'host-7732',
    name: 'prod-app-07.us-east-1.internal',
    short: 'prod-app-07',
    ip: '10.42.18.207',
    os: 'Windows Server 2022 · 21H2',
    role: 'Application · Order ingest',
    agent: 'wardex-agent 1.0.11',
    site: 'AWS · us-east-1c',
    tags: ['prod', 'pci-in-scope', 'order-tier'],
    owner: 'platform-orders@wardex.dev',
  };

  const alert = {
    id: 'ALT-2026-051104-7732',
    title: 'Suspected ransomware detonation',
    detection: 'Mass file rename + LSASS read + outbound beacon',
    rule: 'wardex.detection.ransomware.detonation-v3',
    severity: 'crit',
    score: 98,
    confidence: 0.94,
    started: '11:42:18 UTC',
    duration: '4m 51s',
    status: 'active',
    mitre: ['T1486 · Data Encrypted for Impact','T1003.001 · LSASS Memory','T1071.001 · Web Protocols'],
    counts: { files: 23847, processes: 7, network: 14 },
  };

  // Process tree (depth-encoded)
  const procs = [
    { d:0, pid:4012, name:'services.exe',         user:'NT AUTHORITY\\SYSTEM',  cmd:'C:\\Windows\\System32\\services.exe',                     cpu: 1, sig:'Microsoft',  flag:null },
    { d:1, pid:4288, name:'svchost.exe',          user:'NT AUTHORITY\\SYSTEM',  cmd:'svchost.exe -k netsvcs -p',                                cpu: 3, sig:'Microsoft',  flag:null },
    { d:2, pid:5104, name:'msiexec.exe',          user:'order-svc',             cmd:'msiexec /i \\\\share\\update.msi /quiet',                  cpu: 8, sig:'Unsigned',   flag:'low' },
    { d:3, pid:6618, name:'powershell.exe',       user:'order-svc',             cmd:'powershell -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGI…',  cpu: 24, sig:'Microsoft', flag:'high' },
    { d:4, pid:7144, name:'rundll32.exe',         user:'order-svc',             cmd:'rundll32 C:\\Users\\Public\\update.dll,Entry',              cpu: 12, sig:'Unsigned',  flag:'high' },
    { d:5, pid:7188, name:'kryptos.exe',          user:'order-svc',             cmd:'C:\\Users\\Public\\kryptos.exe --enc --no-shadow --beacon', cpu: 78, sig:'Unsigned',  flag:'crit', active:true },
    { d:6, pid:7212, name:'vssadmin.exe',         user:'SYSTEM',                cmd:'vssadmin delete shadows /all /quiet',                       cpu: 4, sig:'Microsoft',  flag:'high' },
    { d:6, pid:7244, name:'cmd.exe',              user:'order-svc',             cmd:'cmd /c wmic shadowcopy delete',                             cpu: 1, sig:'Microsoft',  flag:'med' },
    { d:6, pid:7301, name:'kryptos.exe',          user:'order-svc',             cmd:'(child) → \\\\fileserver-02\\orders$',                       cpu: 41, sig:'Unsigned', flag:'crit', active:true },
  ];

  // Timeline events (newest first)
  const events = [
    { t:'11:47:02', s:'crit', tag:'FILE',    line:'D:\\orders\\ → .kryptos rename burst · +1,238 files in 4s', host:'prod-app-07' },
    { t:'11:46:48', s:'crit', tag:'NET',     line:'Beacon · 185.220.101.43:8443 (TLS · TOR exit)', host:'prod-app-07' },
    { t:'11:46:21', s:'high', tag:'PROC',    line:'kryptos.exe spawned by rundll32.exe', host:'prod-app-07' },
    { t:'11:45:55', s:'high', tag:'CRED',    line:'LSASS open · PROCESS_VM_READ from PID 7144', host:'prod-app-07' },
    { t:'11:45:12', s:'med',  tag:'PERSIST', line:'Scheduled task created: \\Microsoft\\Office\\OfficeTelemetry', host:'prod-app-07' },
    { t:'11:44:33', s:'high', tag:'PROC',    line:'Encoded PowerShell -nop -w hidden -enc …', host:'prod-app-07' },
    { t:'11:42:18', s:'med',  tag:'EXEC',    line:'msiexec /i \\\\share\\update.msi /quiet (unsigned)', host:'prod-app-07' },
    { t:'11:41:07', s:'low',  tag:'AUTH',    line:'order-svc · service ticket refresh', host:'prod-app-07' },
    { t:'11:38:45', s:'info', tag:'AGENT',   line:'Heartbeat · agent 1.0.11 healthy', host:'prod-app-07' },
  ];

  const alertsList = [
    { id:'ALT…7732', sev:'crit', title:'Suspected ransomware detonation',         host:'prod-app-07',  age:'5m',  status:'OPEN',     assignee:'You',   rule:'ransomware.detonation-v3' },
    { id:'ALT…7704', sev:'high', title:'LSASS memory access',                     host:'prod-app-07',  age:'6m',  status:'LINKED',   assignee:'You',   rule:'cred.lsass-read' },
    { id:'ALT…7691', sev:'high', title:'Encoded PowerShell · base64 b64 length 2.4kB', host:'prod-app-07', age:'7m', status:'LINKED', assignee:'You',  rule:'ps.encoded' },
    { id:'ALT…7642', sev:'med',  title:'Unsigned MSI from network share',          host:'prod-app-07',  age:'10m', status:'LINKED',   assignee:'You',   rule:'install.unsigned-msi' },
    { id:'ALT…7610', sev:'high', title:'Beacon to known TOR exit',                 host:'prod-app-07',  age:'8m',  status:'LINKED',   assignee:'You',   rule:'c2.tor-exit' },
    { id:'ALT…7588', sev:'med',  title:'Anomalous SMB write burst',                host:'fileserver-02',age:'12m', status:'OPEN',     assignee:'—',     rule:'net.smb-burst' },
    { id:'ALT…7559', sev:'low',  title:'New scheduled task created',               host:'prod-app-07',  age:'14m', status:'LINKED',   assignee:'You',   rule:'persist.scheduled' },
    { id:'ALT…7501', sev:'high', title:'RDP brute force · 412 failed attempts',    host:'jump-01',      age:'31m', status:'OPEN',     assignee:'M. Kato', rule:'auth.rdp-brute' },
    { id:'ALT…7488', sev:'med',  title:'YARA · Mimikatz-like memory pattern',      host:'dev-build-12', age:'1h',  status:'TRIAGE',   assignee:'A. Rao',  rule:'yara.mimikatz' },
    { id:'ALT…7404', sev:'low',  title:'Outbound DNS to newly observed domain',    host:'prod-app-04',  age:'1h',  status:'SUPPRESS', assignee:'auto',    rule:'net.nod-dns' },
    { id:'ALT…7388', sev:'info', title:'Agent rolled forward to 1.0.11',           host:'fleet (482)',  age:'2h',  status:'INFO',     assignee:'system',  rule:'agent.rollout' },
  ];

  // Sparkline series (24h)
  const spark24 = (seed) => {
    const out = []; let v = 30 + (seed % 20);
    for (let i = 0; i < 48; i++) { v += (Math.sin(i*0.4 + seed) + (i===44?40:0) + (i===45?30:0) + (i===46?20:0)) * 2 + (i*seed%7 - 3); out.push(Math.max(2, v)); }
    return out;
  };

  // Fleet sample
  const fleet = [
    { host:'prod-app-07',    os:'win', site:'us-east-1c', status:'ISOLATED',    risk:98, alerts:11, agent:'1.0.11', last:'4s' },
    { host:'prod-app-06',    os:'win', site:'us-east-1c', status:'AT RISK',     risk:64, alerts:3,  agent:'1.0.11', last:'2s' },
    { host:'prod-app-05',    os:'win', site:'us-east-1b', status:'HEALTHY',     risk:12, alerts:0,  agent:'1.0.11', last:'2s' },
    { host:'prod-app-04',    os:'win', site:'us-east-1b', status:'HEALTHY',     risk:18, alerts:1,  agent:'1.0.11', last:'3s' },
    { host:'fileserver-02',  os:'lin', site:'us-east-1c', status:'INVESTIGATE', risk:72, alerts:4,  agent:'1.0.11', last:'1s' },
    { host:'fileserver-01',  os:'lin', site:'us-east-1c', status:'HEALTHY',     risk:8,  alerts:0,  agent:'1.0.11', last:'4s' },
    { host:'jump-01',        os:'lin', site:'us-east-1a', status:'AT RISK',     risk:54, alerts:2,  agent:'1.0.11', last:'1s' },
    { host:'mac-jenna',      os:'mac', site:'remote',     status:'STALE',       risk:0,  alerts:0,  agent:'1.0.9',  last:'2d' },
    { host:'k8s-node-014',   os:'lin', site:'us-east-1a', status:'HEALTHY',     risk:6,  alerts:0,  agent:'1.0.11', last:'1s' },
    { host:'k8s-node-015',   os:'lin', site:'us-east-1a', status:'HEALTHY',     risk:4,  alerts:0,  agent:'1.0.11', last:'2s' },
  ];

  const detectionRules = [
    { id:'D-014', name:'ransomware.detonation-v3', mitre:'T1486', sev:'crit', state:'ENABLED',  hits24:1,  fpRate:'0.2%', author:'wardex',   updated:'2d' },
    { id:'D-008', name:'cred.lsass-read',          mitre:'T1003', sev:'high', state:'ENABLED',  hits24:3,  fpRate:'1.1%', author:'wardex',   updated:'14d' },
    { id:'D-022', name:'ps.encoded',               mitre:'T1059', sev:'high', state:'ENABLED',  hits24:7,  fpRate:'4.2%', author:'wardex',   updated:'1d' },
    { id:'D-031', name:'c2.tor-exit',              mitre:'T1071', sev:'high', state:'ENABLED',  hits24:2,  fpRate:'0.0%', author:'intel',    updated:'6h' },
    { id:'D-044', name:'install.unsigned-msi',     mitre:'T1218', sev:'med',  state:'TUNING',   hits24:18, fpRate:'12%',  author:'k.adams',  updated:'4h' },
    { id:'D-055', name:'persist.scheduled',        mitre:'T1053', sev:'low',  state:'ENABLED',  hits24:24, fpRate:'7%',   author:'wardex',   updated:'21d' },
    { id:'D-061', name:'net.smb-burst',            mitre:'T1021', sev:'med',  state:'ENABLED',  hits24:6,  fpRate:'2%',   author:'m.kato',   updated:'1d' },
    { id:'D-068', name:'yara.mimikatz',            mitre:'T1003', sev:'high', state:'ENABLED',  hits24:1,  fpRate:'0%',   author:'wardex',   updated:'7d' },
    { id:'D-077', name:'auth.rdp-brute',           mitre:'T1110', sev:'high', state:'ENABLED',  hits24:4,  fpRate:'0.3%', author:'wardex',   updated:'30d' },
    { id:'D-088', name:'net.nod-dns',              mitre:'T1071', sev:'low',  state:'SUPPRESS', hits24:412,fpRate:'88%',  author:'a.rao',    updated:'2h' },
  ];

  const approvals = [
    { id:'RX-204', action:'Isolate host',  target:'prod-app-07',  by:'You',       at:'just now', risk:'high', why:'Active ransomware detonation' },
    { id:'RX-203', action:'Kill process',  target:'kryptos.exe @ prod-app-07', by:'You', at:'1m ago', risk:'high', why:'Encrypting volume' },
    { id:'RX-202', action:'Block IP',      target:'185.220.101.43', by:'auto',    at:'2m ago', risk:'med',  why:'Beacon C2 destination' },
    { id:'RX-201', action:'Disable account', target:'order-svc',    by:'You',     at:'4m ago', risk:'med',  why:'Service principal abused' },
  ];

  const malware = [
    { hash:'a3f1…be71', file:'kryptos.exe',       host:'prod-app-07', verdict:'MALICIOUS',  family:'Kryptos',   engine:'YARA + behavior', size:'412 KB' },
    { hash:'09c2…12a4', file:'update.dll',       host:'prod-app-07', verdict:'MALICIOUS',  family:'Kryptos loader', engine:'YARA', size:'88 KB' },
    { hash:'77d4…5510', file:'update.msi',       host:'prod-app-07', verdict:'SUSPICIOUS', family:'—',         engine:'static + hash',   size:'1.8 MB' },
    { hash:'bb19…aa2c', file:'note.txt',         host:'prod-app-07', verdict:'CLEAN',      family:'—',         engine:'static',          size:'2 KB' },
  ];

  return {
    NOW, sections, sectionIcons, host, alert, procs, events,
    alertsList, spark24, fleet, detectionRules, approvals, malware,
  };
})();
