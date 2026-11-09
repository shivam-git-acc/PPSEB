import { useCallback, useState } from "react";
import { Card, ErrorBanner, Badge } from "../Section";
import TraceTimeline from "../TraceTimeline";

/* One call, its trace, and its error — kept together.
   R9.7: a failed step must leave the previous trace on screen, so the reader can
   see what happened *before* the failure. Clearing the list on error would hide
   exactly the context the failure needs. */
export function useOp() {
  const [state, setState] = useState({ result: null, trace: [], error: null, busy: false });

  const run = useCallback(async (fn) => {
    setState((s) => ({ ...s, busy: true, error: null }));
    try {
      const body = await fn();
      setState({ result: body.result, trace: body.trace ?? [], error: null, busy: false });
      return body.result;
    } catch (e) {
      setState((s) => ({ ...s, busy: false, error: String(e.message || e) }));
      return null;
    }
  }, []);

  return { ...state, run };
}

export function TraceCard({ op, title = "Trace", subtitle }) {
  return (
    <Card title={title} subtitle={subtitle}>
      <ErrorBanner message={op.error} />
      <div className="mt-2">
        <TraceTimeline trace={op.trace} />
      </div>
    </Card>
  );
}

export function KeyValues({ entries, columns = 2 }) {
  const rows = Object.entries(entries || {}).filter(([, v]) => v !== undefined);
  if (!rows.length) return <p className="text-2xs text-ink-500">Nothing yet.</p>;
  return (
    <dl className={`grid grid-cols-1 ${columns === 2 ? "md:grid-cols-2" : ""} gap-x-6 gap-y-1.5`}>
      {rows.map(([k, v]) => (
        <div key={k} className="flex items-baseline justify-between gap-3 border-b border-ink-800/60 py-1">
          <dt className="text-2xs text-ink-500">{k.replaceAll("_", " ")}</dt>
          <dd className="mono text-2xs text-ink-200 text-right break-all">
            {Array.isArray(v) ? (v.length ? v.join(", ") : "—")
              : typeof v === "object" && v !== null ? JSON.stringify(v)
                : String(v)}
          </dd>
        </div>
      ))}
    </dl>
  );
}

export function Verdict({ ok, yes = "PASS", no = "FAIL", children }) {
  return (
    <div className="flex items-center gap-2">
      <Badge tone={ok ? "green" : "red"}>{ok ? yes : no}</Badge>
      <span className="text-[13px] text-ink-300">{children}</span>
    </div>
  );
}
