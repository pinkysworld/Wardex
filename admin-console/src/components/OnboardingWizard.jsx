import { useState } from 'react';
import * as api from '../api.js';

const STEPS = [
  {
    title: 'Welcome to SentinelEdge',
    body: 'This wizard helps you set up your XDR workspace in a few steps. You can always revisit settings later.',
    field: null,
  },
  {
    title: 'API Token',
    body: 'Enter or confirm your API token so the console can communicate with the backend.',
    field: 'token',
  },
  {
    title: 'Your Role',
    body: 'Choose a role to personalise navigation. Analysts see SOC tools; admins see fleet management.',
    field: 'role',
  },
  {
    title: 'Threat Feeds',
    body: 'Enable at least one threat-intelligence feed to start ingesting IoCs automatically.',
    field: 'feeds',
  },
  {
    title: 'You\'re all set!',
    body: 'The dashboard is ready. Explore alerts, fleet status, and detection coverage from the sidebar.',
    field: null,
  },
];

const ROLES = ['viewer', 'analyst', 'admin'];
const FEEDS = ['Abuse.ch MalwareBazaar', 'CIRCL MISP (TAXII)', 'Custom URL feed'];

export default function OnboardingWizard({ onComplete }) {
  const [step, setStep] = useState(0);
  const [token, setToken] = useState(localStorage.getItem('wardex_token') || '');
  const [role, setRole] = useState(localStorage.getItem('wardex_role') || 'analyst');
  const [selectedFeeds, setSelectedFeeds] = useState([FEEDS[0]]);

  const current = STEPS[step];
  const isLast = step === STEPS.length - 1;

  const toggleFeed = (f) => {
    setSelectedFeeds(prev => prev.includes(f) ? prev.filter(x => x !== f) : [...prev, f]);
  };

  const finish = async () => {
    if (token) localStorage.setItem('wardex_token', token);
    if (role) localStorage.setItem('wardex_role', role);
    for (const feed of selectedFeeds) {
      try { await api.addFeed({ name: feed }); } catch { /* best-effort */ }
    }
    onComplete?.();
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 10000,
      background: 'rgba(0,0,0,.6)', display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        background: 'var(--bg-card)', borderRadius: 12, padding: 32,
        width: 460, maxWidth: '90vw', color: 'var(--text)',
        boxShadow: '0 8px 30px rgba(0,0,0,.5)',
        border: '1px solid var(--border)',
      }}>
        {/* Progress dots */}
        <div style={{ display: 'flex', gap: 6, marginBottom: 20, justifyContent: 'center' }}>
          {STEPS.map((_, i) => (
            <div key={i} style={{
              width: 10, height: 10, borderRadius: '50%',
              background: i <= step ? 'var(--primary)' : 'var(--border)',
              transition: 'background .2s',
            }} />
          ))}
        </div>

        <h3 style={{ margin: '0 0 8px', fontSize: 20 }}>{current.title}</h3>
        <p style={{ margin: '0 0 20px', color: 'var(--text-secondary)', fontSize: 14, lineHeight: 1.5 }}>{current.body}</p>

        {/* Step-specific fields */}
        {current.field === 'token' && (
          <input
            type="password"
            value={token}
            onChange={e => setToken(e.target.value)}
            placeholder="Paste API token…"
            style={{
              width: '100%', padding: '8px 12px', borderRadius: 6,
              border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)',
              fontSize: 14, boxSizing: 'border-box',
            }}
          />
        )}

        {current.field === 'role' && (
          <div style={{ display: 'flex', gap: 8 }}>
            {ROLES.map(r => (
              <button
                key={r}
                onClick={() => setRole(r)}
                style={{
                  flex: 1, padding: '8px 0', borderRadius: 6, cursor: 'pointer',
                  border: `1px solid ${role === r ? 'var(--primary)' : 'var(--border)'}`,
                  background: role === r ? 'rgba(59,130,246,.15)' : 'var(--bg)',
                  color: 'var(--text)', fontSize: 13, textTransform: 'capitalize',
                }}
              >{r}</button>
            ))}
          </div>
        )}

        {current.field === 'feeds' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {FEEDS.map(f => (
              <label key={f} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 14, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={selectedFeeds.includes(f)}
                  onChange={() => toggleFeed(f)}
                />
                {f}
              </label>
            ))}
          </div>
        )}

        {/* Navigation */}
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 24, gap: 12 }}>
          <button
            onClick={onComplete}
            style={{
              background: 'none', border: 'none', color: 'var(--text-secondary)',
              cursor: 'pointer', fontSize: 13,
            }}
          >Skip</button>
          <div style={{ display: 'flex', gap: 8 }}>
            {step > 0 && (
              <button
                onClick={() => setStep(s => s - 1)}
                className="btn btn-sm"
              >Back</button>
            )}
            <button
              onClick={isLast ? finish : () => setStep(s => s + 1)}
              className="btn btn-sm btn-primary"
            >{isLast ? 'Finish' : 'Next'}</button>
          </div>
        </div>
      </div>
    </div>
  );
}
