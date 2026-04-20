import { useCallback, useEffect, useState } from 'react';
import * as api from '../api.js';
import { formatRelativeTime } from './operatorUtils.js';

/**
 * Renders processes and socket tables for the local console host so a single-
 * machine deployment has the same operator visibility as a remote agent.
 *
 * Refreshes automatically every 15 seconds while mounted.
 */
export default function LocalConsoleInventory() {
  const [inventory, setInventory] = useState(null);
  const [status, setStatus] = useState('loading');
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    try {
      const data = await api.localConsoleInventory();
      setInventory(data);
      setStatus('ready');
      setError(null);
    } catch (err) {
      setStatus('error');
      setError(err?.message || 'Failed to load inventory');
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    const run = () => {
      if (!cancelled) {
        void load();
      }
    };
    const timer = setTimeout(run, 0);
    const id = setInterval(run, 15000);
    return () => {
      cancelled = true;
      clearTimeout(timer);
      clearInterval(id);
    };
  }, [load]);

  if (status === 'loading' && !inventory) {
    return (
      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-title">Host inventory</div>
        <div className="row-secondary">Collecting processes and sockets…</div>
      </div>
    );
  }
  if (status === 'error' && !inventory) {
    return (
      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-title">Host inventory</div>
        <div className="row-secondary">Inventory unavailable: {error}</div>
        <button className="btn btn-sm" onClick={load} style={{ marginTop: 8 }}>
          Retry
        </button>
      </div>
    );
  }

  const processes = Array.isArray(inventory?.processes) ? inventory.processes : [];
  const listening = Array.isArray(inventory?.listening_sockets) ? inventory.listening_sockets : [];
  const established = Array.isArray(inventory?.established_sockets)
    ? inventory.established_sockets
    : [];

  return (
    <div style={{ marginTop: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="card" data-testid="local-inventory-processes">
        <div className="card-header">
          <span className="card-title">
            Top processes ({processes.length}
            {inventory?.process_total ? ` of ${inventory.process_total} running` : ''})
          </span>
          <div className="btn-group">
            <span className="row-secondary">
              Updated {formatRelativeTime(inventory?.captured_at)}
            </span>
            <button className="btn btn-sm" onClick={load}>
              Refresh
            </button>
          </div>
        </div>
        {processes.length === 0 ? (
          <div className="row-secondary">
            No process data available. On macOS the console host needs permission to run{' '}
            <code>ps</code>; on Linux ensure <code>/proc</code> is readable.
          </div>
        ) : (
          <div className="desktop-table-only">
            <table>
              <thead>
                <tr>
                  <th>Process</th>
                  <th>PID</th>
                  <th>User</th>
                  <th>CPU %</th>
                  <th>Memory (MB)</th>
                </tr>
              </thead>
              <tbody>
                {processes.map((proc) => (
                  <tr key={`${proc.pid}-${proc.name}`}>
                    <td>
                      <div className="row-primary">{proc.name || '—'}</div>
                      <div className="row-secondary" title={proc.command}>
                        {proc.command?.length > 80
                          ? `${proc.command.slice(0, 80)}…`
                          : proc.command || '—'}
                      </div>
                    </td>
                    <td>{proc.pid}</td>
                    <td>{proc.user || '—'}</td>
                    <td>{(proc.cpu_pct ?? 0).toFixed(1)}</td>
                    <td>{(proc.memory_mb ?? 0).toFixed(1)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card" data-testid="local-inventory-sockets">
        <div className="card-header">
          <span className="card-title">
            Listening sockets ({listening.length}) · Established ({established.length})
          </span>
        </div>
        {listening.length === 0 && established.length === 0 ? (
          <div className="row-secondary">
            No sockets reported. macOS uses <code>lsof</code>, Linux uses <code>ss</code> — make
            sure one is on PATH for the console process.
          </div>
        ) : (
          <div className="desktop-table-only">
            <table>
              <thead>
                <tr>
                  <th>Proto</th>
                  <th>Local</th>
                  <th>Peer</th>
                  <th>State</th>
                  <th>Process</th>
                  <th>PID</th>
                </tr>
              </thead>
              <tbody>
                {[...listening, ...established].map((socket, index) => (
                  <tr key={`${socket.proto}-${socket.local_addr}-${index}`}>
                    <td>{socket.proto}</td>
                    <td>{socket.local_addr || '—'}</td>
                    <td>{socket.remote_addr || '—'}</td>
                    <td>{socket.state || '—'}</td>
                    <td>{socket.process || '—'}</td>
                    <td>{socket.pid ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
