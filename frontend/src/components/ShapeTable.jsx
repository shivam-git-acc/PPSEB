export default function ShapeTable({ shapeTable }) {
  if (!shapeTable) return null;
  return (
    <div className="mono text-[11px] space-y-1">
      {Object.entries(shapeTable).map(([k, v]) => (
        <div key={k} className="flex justify-between gap-3 border-b border-ink-800/60 pb-1">
          <span className="text-ink-300">{k}</span>
          <span className="text-ink-500 text-right">{v}</span>
        </div>
      ))}
    </div>
  );
}
