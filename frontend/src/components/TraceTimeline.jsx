import { useEffect, useRef, useState } from "react";

const TYPE_STYLE = {
  compute: { label: "compute", dot: "bg-signal-blue", border: "border-ink-700" },
  correction: { label: "correction", dot: "bg-amber-400", border: "border-amber-600/50" },
  note: { label: "note", dot: "bg-ink-400", border: "border-ink-700" },
  threat_model: { label: "threat model", dot: "bg-signal-red", border: "border-signal-red/40" },
  matrix: { label: "matrix", dot: "bg-signal-blue", border: "border-ink-700" },
  norm: { label: "norm", dot: "bg-ink-300", border: "border-ink-700" },
  decision: { label: "decision", dot: "bg-signal-green", border: "border-signal-green/40" },
  result: { label: "result", dot: "bg-signal-green", border: "border-signal-green/50" },
};

function fmtNum(v) {
  if (typeof v !== "number") return String(v);
  if (Number.isInteger(v)) return v.toString();
  return v.toFixed(3);
}

function DataValue({ k, v }) {
  if (v === null || v === undefined) return <span className="text-ink-500">null</span>;
  if (Array.isArray(v)) {
    if (v.length > 0 && Array.isArray(v[0])) {
      // matrix preview
      return (
        <div className="overflow-x-auto mt-1">
          <table className="mono text-[11px] border-collapse">
            <tbody>
              {v.map((row, i) => (
                <tr key={i}>
                  {row.map((c, j) => (
                    <td key={j} className="px-1.5 py-0.5 border border-ink-800 text-ink-200 text-right">
                      {fmtNum(c)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    }
    return <span className="mono text-ink-200">[{v.slice(0, 16).map(fmtNum).join(", ")}{v.length > 16 ? ", …" : ""}]</span>;
  }
  if (typeof v === "object") {
    return (
      <div className="pl-3 border-l border-ink-800 mt-1 space-y-0.5">
        {Object.entries(v).map(([kk, vv]) => (
          <div key={kk} className="text-[12px]">
            <span className="text-ink-400">{kk}: </span>
            <DataValue k={kk} v={vv} />
          </div>
        ))}
      </div>
    );
  }
  if (typeof v === "boolean") {
    return <span className={v ? "text-signal-green" : "text-signal-red"}>{String(v)}</span>;
  }
  if (typeof v === "number") return <span className="mono text-ink-200">{fmtNum(v)}</span>;
  return <span className="mono text-ink-200 break-all">{String(v)}</span>;
}

function EventCard({ ev }) {
  const [open, setOpen] = useState(ev.type === "decision" || ev.type === "correction" || ev.type === "threat_model");
  const style = TYPE_STYLE[ev.type] || TYPE_STYLE.note;
  const hasData = ev.data && Object.keys(ev.data).length > 0;

  return (
    <div className={`trace-event-enter rounded-md border ${style.border} bg-ink-900/60 px-3 py-2`}>
      <button
        className="w-full flex items-start gap-2 text-left"
        onClick={() => setOpen((o) => !o)}
      >
        <span className={`mt-1.5 w-1.5 h-1.5 rounded-full shrink-0 ${style.dot}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[10px] uppercase tracking-wide text-ink-400">{style.label}</span>
            {ev.algo && <span className="text-[10px] uppercase tracking-wide text-ink-500">· {ev.algo}</span>}
            <span className="text-[10px] text-ink-600">#{ev.step}</span>
            {ev.type === "decision" && ev.data?.verdict && (
              <span className={`ml-auto text-[10px] px-1.5 py-0.5 rounded font-semibold ${
                String(ev.data.verdict).toLowerCase().includes("invalid") || String(ev.data.verdict).toLowerCase().includes("survives")
                  ? "bg-signal-red/20 text-signal-red"
                  : String(ev.data.verdict).toLowerCase().includes("broken")
                  ? "bg-amber-500/20 text-amber-400"
                  : "bg-signal-green/20 text-signal-green"
              }`}>
                {ev.data.verdict}
              </span>
            )}
          </div>
          <div className="text-sm text-ink-100 mt-0.5">{ev.title}</div>
          {ev.detail && <div className="text-xs text-ink-400 mt-0.5">{ev.detail}</div>}
        </div>
        {hasData && (
          <span className="text-ink-500 text-xs mt-1">{open ? "▾" : "▸"}</span>
        )}
      </button>
      {open && hasData && (
        <div className="mt-2 pl-3.5">
          {ev.type === "correction" ? (
            <div className="space-y-1.5 text-xs">
              <div><span className="text-amber-400 font-medium">paper says: </span><span className="text-ink-300">{ev.data.paper_says}</span></div>
              <div><span className="text-amber-400 font-medium">we do: </span><span className="text-ink-300">{ev.data.we_do}</span></div>
              <div><span className="text-amber-400 font-medium">because: </span><span className="text-ink-300">{ev.data.because}</span></div>
              {Object.entries(ev.data).filter(([k]) => !["paper_says", "we_do", "because"].includes(k)).map(([k, v]) => (
                <div key={k} className="text-[12px]"><span className="text-ink-500">{k}: </span><DataValue k={k} v={v} /></div>
              ))}
            </div>
          ) : (
            <div className="space-y-0.5">
              {Object.entries(ev.data).map(([k, v]) => (
                <div key={k} className="text-[12px]"><span className="text-ink-500">{k}: </span><DataValue k={k} v={v} /></div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function TraceTimeline({ events, title = "Trace" }) {
  const [visibleCount, setVisibleCount] = useState(0);
  const timerRef = useRef(null);

  useEffect(() => {
    setVisibleCount(0);
    if (!events || events.length === 0) return;
    let i = 0;
    const step = () => {
      i += 1;
      setVisibleCount(i);
      if (i < events.length) {
        const delay = events.length > 30 ? 25 : events.length > 12 ? 60 : 110;
        timerRef.current = setTimeout(step, delay);
      }
    };
    timerRef.current = setTimeout(step, 60);
    return () => clearTimeout(timerRef.current);
  }, [events]);

  const copyJson = () => {
    navigator.clipboard?.writeText(JSON.stringify(events, null, 2));
  };

  if (!events || events.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-ink-500 text-sm px-6 text-center">
        Run an operation to see its trace here — every step the backend takes, shown live.
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-3 py-2 border-b border-ink-800 shrink-0">
        <span className="text-xs uppercase tracking-wide text-ink-400">{title} · {events.length} step{events.length === 1 ? "" : "s"}</span>
        <button onClick={copyJson} className="text-[11px] text-ink-400 hover:text-ink-100 border border-ink-700 rounded px-2 py-0.5">
          copy JSON
        </button>
      </div>
      <div className="flex-1 overflow-y-auto px-3 py-3 space-y-2">
        {events.slice(0, visibleCount).map((ev, idx) => (
          <EventCard key={`${ev.step}-${idx}`} ev={ev} />
        ))}
      </div>
    </div>
  );
}
