interface EvidenceChipProps { id: string; title?: string; }
export function EvidenceChip({ id, title }: EvidenceChipProps) {
  return <span className="chip" title={title}>{id}</span>;
}

interface EmptyStateProps { title?: string; message?: string; }
export function EmptyState({ title = 'No data', message }: EmptyStateProps) {
  return (
    <div className="empty-state">
      <strong>{title}</strong>
      {message && <p style={{ margin: '4px 0 0', fontSize: 13 }}>{message}</p>}
    </div>
  );
}

export function LoadingState({ lines = 3 }: { lines?: number }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, padding: '18px 0' }}>
      {Array.from({ length: lines }, (_, i) => (
        <div key={i} className="skeleton" style={{ height: 18, width: i === 0 ? '60%' : i % 2 === 0 ? '80%' : '70%' }} />
      ))}
    </div>
  );
}
