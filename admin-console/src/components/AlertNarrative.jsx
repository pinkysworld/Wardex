/**
 * Renders a server-provided narrative describing why an alert fired, in plain
 * English. Falls back to nothing when `narrative` is absent so older alerts
 * keep their existing layout.
 */
export default function AlertNarrative({ narrative }) {
  if (!narrative || typeof narrative !== 'object') {
    return null;
  }

  const {
    headline,
    summary,
    observations,
    baseline_comparison: baselineComparison,
    time_window: timeWindow,
    involved_entities: involvedEntities,
    suggested_queries: suggestedQueries,
  } = narrative;

  if (!headline && !summary) {
    return null;
  }

  return (
    <div className="card" style={{ marginTop: 16 }} data-testid="alert-narrative">
      <div className="card-title" style={{ marginBottom: 8 }}>
        {headline || 'What happened'}
      </div>
      {summary && <div style={{ lineHeight: 1.6, fontSize: 14, marginBottom: 12 }}>{summary}</div>}

      {Array.isArray(observations) && observations.length > 0 && (
        <>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>Observations</div>
          <ul
            style={{
              margin: '0 0 12px',
              paddingLeft: 18,
              fontSize: 13,
              lineHeight: 1.7,
              color: 'var(--text)',
            }}
          >
            {observations.map((line, index) => (
              <li key={index}>{line}</li>
            ))}
          </ul>
        </>
      )}

      {baselineComparison && (
        <div style={{ marginBottom: 12 }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>Baseline comparison</div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            {baselineComparison}
          </div>
        </div>
      )}

      {timeWindow && (
        <div style={{ marginBottom: 12 }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>Time window</div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{timeWindow}</div>
        </div>
      )}

      {Array.isArray(involvedEntities) && involvedEntities.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>Involved entities</div>
          <div className="chip-row">
            {involvedEntities.map((entity, index) => (
              <span key={index} className="badge badge-info">
                {entity}
              </span>
            ))}
          </div>
        </div>
      )}

      {Array.isArray(suggestedQueries) && suggestedQueries.length > 0 && (
        <div>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>Suggested queries</div>
          <ul
            style={{
              margin: 0,
              paddingLeft: 18,
              fontSize: 13,
              lineHeight: 1.7,
              color: 'var(--text-secondary)',
            }}
          >
            {suggestedQueries.map((query, index) => (
              <li key={index}>
                <code>{query}</code>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
