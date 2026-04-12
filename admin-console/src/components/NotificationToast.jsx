import { useState, useEffect, useRef, useCallback } from 'react';
import * as api from '../api.js';
import { getToken } from '../api.js';

const POLL_INTERVAL = 30_000;

export default function NotificationToast() {
  const [items, setItems] = useState([]);
  const idRef = useRef(0);
  const prevAlertCount = useRef(null);
  const prevFeedCount = useRef(null);

  const push = useCallback((message, kind = 'info') => {
    const id = ++idRef.current;
    setItems(prev => [...prev.slice(-4), { id, message, kind, ts: Date.now() }]);
    setTimeout(() => setItems(prev => prev.filter(n => n.id !== id)), 8000);
  }, []);

  const dismiss = useCallback((id) => {
    setItems(prev => prev.filter(n => n.id !== id));
  }, []);

  useEffect(() => {
    let mounted = true;
    const poll = async () => {
      if (!mounted || !getToken()) return;
      try {
        const [alerts, feeds] = await Promise.all([
          api.alertsCount().catch(() => null),
          api.feedStats().catch(() => null),
        ]);
        const alertCount = alerts?.count ?? alerts?.total ?? null;
        if (alertCount !== null && prevAlertCount.current !== null && alertCount > prevAlertCount.current) {
          push(`${alertCount - prevAlertCount.current} new alert(s) detected`, 'warning');
        }
        prevAlertCount.current = alertCount;

        const feedCount = feeds?.total_indicators ?? feeds?.total ?? null;
        if (feedCount !== null && prevFeedCount.current !== null && feedCount > prevFeedCount.current) {
          push(`${feedCount - prevFeedCount.current} new IoCs ingested from feeds`, 'info');
        }
        prevFeedCount.current = feedCount;
      } catch { /* ignore polling errors */ }
    };
    poll();
    const timer = setInterval(poll, POLL_INTERVAL);
    return () => { mounted = false; clearInterval(timer); };
  }, [push]);

  if (items.length === 0) return null;

  return (
    <div style={{
      position: 'fixed', bottom: 24, right: 24, zIndex: 9000,
      display: 'flex', flexDirection: 'column', gap: 8, maxWidth: 380,
    }}>
      {items.map(n => (
        <div
          key={n.id}
          role="status"
          style={{
            background: 'var(--bg-card)',
            border: `1px solid ${n.kind === 'warning' ? 'var(--warning)' : n.kind === 'error' ? 'var(--danger)' : 'var(--primary)'}`,
            borderRadius: 8, padding: '10px 14px', color: 'var(--text)',
            fontSize: 13, display: 'flex', alignItems: 'center', gap: 10,
            boxShadow: '0 4px 12px rgba(0,0,0,.2)',
            animation: 'fadeIn .25s ease',
          }}
        >
          <span style={{ flex: 1 }}>{n.message}</span>
          <button
            onClick={() => dismiss(n.id)}
            style={{
              background: 'none', border: 'none', color: 'var(--text-secondary)',
              cursor: 'pointer', fontSize: 16, lineHeight: 1, padding: 0,
            }}
            aria-label="Dismiss"
          >×</button>
        </div>
      ))}
    </div>
  );
}
