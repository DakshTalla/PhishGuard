export default function StatTile({ label, value, note }: { label: string; value: string; note?: string }) {
  return (
    <div className="rounded-2xl border border-line bg-surface p-4">
      <div className="text-xs text-muted">{label}</div>
      <div className="mt-1 text-2xl font-semibold">{value}</div>
      {note && <div className="mt-1 text-xs text-ink-2">{note}</div>}
    </div>
  );
}
