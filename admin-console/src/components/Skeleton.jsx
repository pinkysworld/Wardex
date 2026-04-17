const ROW_WIDTHS = [68, 82, 74, 90, 76];

export function SkeletonRow({ cols = 5 }) {
  return (
    <tr className="skeleton-row" aria-hidden="true">
      {Array.from({ length: cols }, (_, i) => (
        <td key={i}>
          <div
            className="skeleton"
            style={{ height: 14, borderRadius: 4, width: `${ROW_WIDTHS[i % ROW_WIDTHS.length]}%` }}
          />
        </td>
      ))}
    </tr>
  );
}

export function SkeletonCard({ height = 80 }) {
  return (
    <div role="status" aria-label="Loading" aria-busy="true">
      <div
        className="skeleton"
        style={{ height, borderRadius: 'var(--radius)', marginBottom: 12 }}
      />
    </div>
  );
}
