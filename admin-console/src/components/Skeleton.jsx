export function SkeletonRow({ cols = 5 }) {
  return (
    <tr className="skeleton-row">
      {Array.from({ length: cols }, (_, i) => (
        <td key={i}><div className="skeleton" style={{ height: 14, borderRadius: 4, width: `${60 + Math.random() * 30}%` }} /></td>
      ))}
    </tr>
  );
}

export function SkeletonCard({ height = 80 }) {
  return <div className="skeleton" style={{ height, borderRadius: 'var(--radius)', marginBottom: 12 }} />;
}
