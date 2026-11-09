import { useState } from "react";
import { Badge } from "./Section";

/* Event types come from ppseb/trace.py. Each gets a word, not only a colour,
   because the palette keeps red and green apart under deuteranopia. */
const KIND = {
  compute: { tone: "neutral", label: "compute" },
  correction: { tone: "amber", label: "correction" },
  note: { tone: "neutral", label: "note" },
  threat_model: { tone: "amber", label: "threat" },
  matrix: { tone: "neutral", label: "matrix" },
  norm: { tone: "blue", label: "norm" },
  decision: { tone: "blue", label: "decision" },
  result: { tone: "green", label: "result" },
};

function Summary({ data }) {
  if (!data || typeof data !== "object") return null;
  const entries = Object.entries(data).slice(0, 6);
  if (!entries.length) return null;
  return (
    <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 mono text-2xs text-ink-500">
      {entries.map(([k, v]) => {
        const text = Array.isArray(v) ? v.join(", ")
          : v && typeof v === "object" ? JSON.stringify(v) : String(v);
        return (
          <span key={k} className="truncate max-w-[28rem]">
            <span className="text-ink-600">{k}=</span>
            <span className="text-ink-300">{text.length > 90 ? `${text.slice(0, 90)}…` : text}</span>
          </span>
        );
      })}
    </div>
  );
}

export default function TraceTimeline({ trace, title = "Trace", empty = "No steps yet." }) {
  const [openSteps, setOpenSteps] = useState({});
  const events = Array.isArray(trace) ? trace : [];
  if (!events.length) {
    return <p className="text-2xs text-ink-500">{empty}</p>;
  }
  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <div className="text-2xs uppercase tracking-[0.08em] text-ink-500">{title}</div>
        <div className="text-2xs text-ink-600 mono">{events.length} steps · 1…{events.length}</div>
      </div>
      <ol className="relative border-l border-ink-800 ml-2 space-y-2 max-h-[26rem] overflow-y-auto pr-1">
        {events.map((e) => {
          const kind = KIND[e.type] ?? KIND.note;
          const open = Boolean(openSteps[e.step]);
          return (
            <li key={e.step} className="pl-4 relative">
              <span
                className={`absolute -left-[5px] top-2 h-2.5 w-2.5 rounded-full ring-2 ring-ink-950 ${
                  e.highlight ? "bg-accent" : "bg-ink-600"}`}
                aria-hidden
              />
              <button
                type="button"
                onClick={() => setOpenSteps((s) => ({ ...s, [e.step]: !s[e.step] }))}
                className="w-full text-left rounded-md hover:bg-white/[0.03] px-2 py-1 -mx-1"
                aria-expanded={open}
              >
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="mono text-2xs text-ink-600">#{e.step}</span>
                  <Badge tone={kind.tone}>{kind.label}</Badge>
                  <span className={`text-[13px] ${e.highlight ? "text-ink-100" : "text-ink-300"}`}>
                    {e.title}
                  </span>
                  {e.algo && <span className="text-2xs text-ink-600 mono">{e.algo}</span>}
                </div>
                {e.detail && (
                  <div className="text-2xs text-ink-500 mt-0.5 leading-relaxed">{e.detail}</div>
                )}
                {open ? <Summary data={e.data} /> : null}
              </button>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
