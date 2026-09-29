import { useEffect, useRef, useState } from "react";
import {
  ResponsiveContainer, ScatterChart, Scatter, XAxis, YAxis, ZAxis, Tooltip, Legend,
  CartesianGrid, ReferenceArea, ReferenceLine, Cell as ReCell,
} from "recharts";
import { api } from "../api";
import { Card, Badge, PrimaryButton, ErrorBanner } from "../components/Section";

const OUTCOMES = {
  broke: { y: 1, label: "broke", colour: "#ef4444" },
  attack_failed: { y: 2, label: "attack ran, failed", colour: "#4ade80" },
  "timed_out (unmeasured)": { y: 3, label: "unmeasured (timeout)", colour: "#8a8a94" },
  "n/a (honest incorrect)": { y: 4, label: "n/a: honest incorrect", colour: "#4b4b55" },
  "n/a (H2)": { y: 4, label: "n/a: H2", colour: "#4b4b55" },
  untrusted: { y: 5, label: "untrusted", colour: "#f59e0b" },
  error: { y: 5, label: "error", colour: "#6b2426" },
};
const Y_TICKS = { 1: "broke", 2: "failed", 3: "unmeasured", 4: "n/a", 5: "untrusted" };

function parseGrid(text) {
  return text.split(",").map((pair) => pair.split(":").map((x) => parseInt(x.trim(), 10)))
    .filter(([n, q]) => Number.isFinite(n) && Number.isFinite(q));
}

function fmtBits(b) {
  return b == null ? "—" : `${b.toFixed(1)}`;
}

export default function SecurityBoundaryTab({ initialized }) {
  const [gridText, setGridText] = useState("4:257, 8:257, 4:1153, 8:1153, 4:4001, 8:4001, 16:12289, 8:40961");
  const [budget, setBudget] = useState(120);
  const [cellTimeout, setCellTimeout] = useState(1800);
  const [jobId, setJobId] = useState(null);
  const [snap, setSnap] = useState(null);
  const [error, setError] = useState(null);
  const [jobs, setJobs] = useState([]);
  const [selected, setSelected] = useState(null);
  const pollRef = useRef(null);

  useEffect(() => { api.boundaryJobs().then((r) => setJobs(r.result || [])).catch(() => {}); }, []);

  useEffect(() => {
    if (!jobId) return undefined;
    const tick = async () => {
      try {
        const r = await api.boundaryStatus(jobId);
        setSnap(r.result);
        if (r.result.status !== "running") {
          clearInterval(pollRef.current);
          api.boundaryJobs().then((j) => setJobs(j.result || [])).catch(() => {});
        }
      } catch (e) {
        setError(String(e.message || e));
        clearInterval(pollRef.current);
      }
    };
    tick();
    pollRef.current = setInterval(tick, 4000);
    return () => clearInterval(pollRef.current);
  }, [jobId]);

  const start = async () => {
    setError(null);
    setSelected(null);
    try {
      const r = await api.boundaryStart({
        grid: parseGrid(gridText), attack_budget_s: Number(budget), cell_timeout_s: Number(cellTimeout),
      });
      setSnap(null);
      setJobId(r.result.job_id);
    } catch (e) {
      setError(String(e.message || e));
    }
  };

  const cells = snap?.cells ?? [];
  const points = cells.filter((c) => c.bits != null).map((c) => ({
    ...c, x: c.bits, y: (OUTCOMES[c.outcome] ?? OUTCOMES.error).y,
    colour: (OUTCOMES[c.outcome] ?? OUTCOMES.error).colour,
  }));
  const brokeBits = cells.filter((c) => c.outcome === "broke" && c.bits != null).map((c) => c.bits);
  const maxBroke = brokeBits.length ? Math.max(...brokeBits) : null;
  const sized = cells.filter((c) => c.bits != null && c.trapdoor_bytes != null)
    .map((c) => ({ ...c, x: c.bits, y: c.trapdoor_bytes }));

  return (
    <div className="space-y-5 max-w-5xl">
      <Card title="Security Boundary"
        subtitle="Where does the public-key-only attack (no secret key) succeed, against an estimated bit-security axis?">
        <p className="text-sm text-ink-300 leading-relaxed">
          Each point is one (n, q). The x-axis is an <b>estimate</b> of how much lattice reduction it takes to
          find, from the public key alone, a basis as good as the honest key holder's. The y-axis is the{" "}
          <b>measured</b> outcome of actually running that attack under a fixed budget. The two are kept
          separate: a point that ran out of budget is <b>unmeasured</b>, never "secure".
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs mt-4">
          <label className="block md:col-span-3"><div className="text-ink-400 mb-1">grid as n:q pairs</div>
            <input value={gridText} onChange={(e) => setGridText(e.target.value)}
              className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-full" /></label>
          <label className="block"><div className="text-ink-400 mb-1">attack budget per cell (s)</div>
            <input type="number" value={budget} onChange={(e) => setBudget(e.target.value)}
              className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-full" /></label>
          <label className="block"><div className="text-ink-400 mb-1">hard cell timeout (s)</div>
            <input type="number" value={cellTimeout} onChange={(e) => setCellTimeout(e.target.value)}
              className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-full" /></label>
          <div className="flex items-end">
            <PrimaryButton onClick={start} disabled={!initialized || snap?.status === "running"}>
              {snap?.status === "running" ? `Running… ${snap.done}/${snap.total}` : "Run boundary sweep"}
            </PrimaryButton>
          </div>
        </div>
        <ErrorBanner message={error} />
        {snap && (
          <div className="text-xs text-ink-500 mono mt-3">
            {snap.job_id} · {snap.status} · {snap.done}/{snap.total} cells · {snap.elapsed_s?.toFixed(0)}s
            {cells[0]?.estimate && <> · estimator: {cells[0].estimate.backend}</>}
          </div>
        )}
        {jobs.length > 0 && (
          <div className="mt-2 flex gap-2 flex-wrap text-xs">
            <span className="text-ink-500">Past runs:</span>
            {jobs.map((j) => (
              <button key={j.job_id} onClick={() => { setSelected(null); setJobId(j.job_id); }}
                className="mono text-ink-400 hover:text-ink-200 underline">{j.job_id} ({j.done}/{j.total})</button>
            ))}
          </div>
        )}
      </Card>

      {points.length > 0 && (
        <Card title="Estimated security (bits) vs measured attack outcome"
          subtitle="Red = the public key alone gave a working trapdoor. Grey = the attack ran out of budget: unmeasured, not secure.">
          <ResponsiveContainer width="100%" height={300}>
            <ScatterChart margin={{ top: 10, right: 20, bottom: 28, left: 8 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2a2a30" />
              {maxBroke != null && (
                <ReferenceArea x1={0} x2={maxBroke} fill="#ef4444" fillOpacity={0.09}
                  label={{ value: `empirically broken ≤ ~${maxBroke.toFixed(0)} bits`, fill: "#ef4444", fontSize: 11, position: "insideTopLeft" }} />
              )}
              <XAxis type="number" dataKey="x" name="estimated bits" stroke="#8a8a94" fontSize={11}
                domain={[0, "dataMax + 10"]}
                label={{ value: "estimated security (bits, core-SVP)", position: "insideBottom", offset: -14, fill: "#8a8a94", fontSize: 11 }} />
              <YAxis type="number" dataKey="y" stroke="#8a8a94" fontSize={11} domain={[0.5, 5.5]}
                ticks={[1, 2, 3, 4, 5]} tickFormatter={(v) => Y_TICKS[v] ?? ""} width={96} />
              <ZAxis range={[90, 90]} />
              <Tooltip
                contentStyle={{ background: "#16161a", border: "1px solid #2a2a30", fontSize: 12 }}
                formatter={(_v, _n, p) => {
                  const c = p.payload;
                  return [`n=${c.n}, q=${c.q}, m=${c.m} — ${c.outcome}${c.beta_used ? `, broke at BKZ-${c.beta_used}` : ""}`, "cell"];
                }} />
              <Scatter name="(n, q) cells" data={points} onClick={(p) => setSelected(p)}>
                {points.map((p) => (
                  <ReCell key={`${p.n}-${p.q}`} fill={p.colour}
                    stroke={p.paper_demo ? "#e5e5ea" : undefined} strokeWidth={p.paper_demo ? 2 : 0} />
                ))}
              </Scatter>
            </ScatterChart>
          </ResponsiveContainer>
          <div className="flex gap-4 flex-wrap text-[11px] mt-1">
            {Object.entries(OUTCOMES).filter(([k]) => k !== "n/a (H2)" && k !== "error").map(([k, v]) => (
              <span key={k} className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-full inline-block" style={{ background: v.colour }} />
                <span className="text-ink-500">{v.label}</span>
              </span>
            ))}
            <span className="flex items-center gap-1.5">
              <span className="w-3 h-3 rounded-full inline-block border-2" style={{ borderColor: "#e5e5ea" }} />
              <span className="text-ink-500">paper's demo parameters</span>
            </span>
          </div>
          {cells.some((c) => c.paper_demo && c.outcome === "broke") && (
            <div className="text-xs text-signal-red bg-signal-red/10 border border-signal-red/30 rounded px-3 py-2.5 mt-3">
              The paper's own demonstration parameters (q=257) sit inside the broken region: the public key alone
              yields a working trapdoor there, so its forward-security and confidentiality claims are vacuous at
              the parameters it evaluates.
            </div>
          )}
        </Card>
      )}

      {sized.length > 0 && (
        <Card title="Cost of reaching higher estimated security"
          subtitle="Trapdoor size (m·⌈log2 q⌉/8 bytes) against the same bit axis — the paper's efficiency figures live at the low-bit end.">
          <ResponsiveContainer width="100%" height={250}>
            <ScatterChart margin={{ top: 10, right: 20, bottom: 28, left: 8 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2a2a30" />
              <XAxis type="number" dataKey="x" stroke="#8a8a94" fontSize={11} domain={[0, "dataMax + 10"]}
                label={{ value: "estimated security (bits)", position: "insideBottom", offset: -14, fill: "#8a8a94", fontSize: 11 }} />
              <YAxis type="number" dataKey="y" stroke="#8a8a94" fontSize={11}
                label={{ value: "trapdoor bytes", angle: -90, position: "insideLeft", fill: "#8a8a94", fontSize: 11 }} />
              <ZAxis range={[80, 80]} />
              <Tooltip contentStyle={{ background: "#16161a", border: "1px solid #2a2a30", fontSize: 12 }}
                formatter={(v, _n, p) => [`n=${p.payload.n}, q=${p.payload.q}: ${v} bytes`, "trapdoor"]} />
              <Scatter data={sized} fill="#5b9dff" />
            </ScatterChart>
          </ResponsiveContainer>
        </Card>
      )}

      {snap?.conclusion && (
        <Card title="Conclusion (measured outcome, estimated axis)">
          <p className="text-sm text-ink-200 leading-relaxed">{snap.conclusion}</p>
          <div className="text-xs text-amber-400 bg-amber-500/10 border border-amber-600/30 rounded px-3 py-2.5 mt-3 leading-relaxed">
            ⚠ The bit axis is an estimate from the root-Hermite fit, asymptotic and unreliable at these small
            dimensions — measured breaks happen at far smaller block sizes than it predicts. Never read a
            timed-out cell as secure.
          </div>
        </Card>
      )}

      {cells.length > 0 && (
        <Card title="Per-cell detail">
          <div className="overflow-x-auto">
            <table className="w-full text-xs mono">
              <thead>
                <tr className="text-left text-ink-500 uppercase">
                  <th className="pb-2 pr-3">n</th><th className="pb-2 pr-3">q</th><th className="pb-2 pr-3">m</th>
                  <th className="pb-2 pr-3">bits (est)</th><th className="pb-2 pr-3">β needed (est)</th>
                  <th className="pb-2 pr-3">outcome</th><th className="pb-2 pr-3">β used</th>
                  <th className="pb-2 pr-3">target norm</th><th className="pb-2 pr-3">bytes</th>
                  <th className="pb-2">runtime</th>
                </tr>
              </thead>
              <tbody>
                {cells.map((c) => (
                  <tr key={`${c.n}-${c.q}`} className="border-t border-ink-800 cursor-pointer hover:bg-ink-800/40"
                    onClick={() => setSelected(c)}>
                    <td className="py-1.5 pr-3">{c.n}{c.paper_demo ? " *" : ""}</td>
                    <td className="py-1.5 pr-3">{c.q}</td>
                    <td className="py-1.5 pr-3">{c.m}</td>
                    <td className="py-1.5 pr-3">{fmtBits(c.bits)}</td>
                    <td className="py-1.5 pr-3">{c.estimate?.beta ?? (c.estimate?.below_fit_range ? "<50" : "—")}</td>
                    <td className="py-1.5 pr-3" style={{ color: (OUTCOMES[c.outcome] ?? OUTCOMES.error).colour }}>{c.outcome}</td>
                    <td className="py-1.5 pr-3">{c.beta_used ?? "—"}</td>
                    <td className="py-1.5 pr-3">{c.target_norm ? c.target_norm.toFixed(2) : "—"}</td>
                    <td className="py-1.5 pr-3">{c.trapdoor_bytes}</td>
                    <td className="py-1.5">{c.runtime_s ? `${c.runtime_s.toFixed(0)}s` : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="text-[11px] text-ink-500 mt-2">* the paper's demonstration parameters</div>
        </Card>
      )}

      {selected && (
        <Card title={`n=${selected.n}, q=${selected.q} — detail`}>
          <div className="text-xs space-y-2">
            <div className="text-ink-300">
              outcome <span style={{ color: (OUTCOMES[selected.outcome] ?? OUTCOMES.error).colour }}>{selected.outcome}</span>
              {selected.gate_failed_checks?.length > 0 && <> · honest gate failed: <span className="mono">{selected.gate_failed_checks.join(", ")}</span></>}
              {selected.control && <> · control {selected.control.passed ? "PASSED (untrusted)" : "failed, as required"}</>}
              {selected.honest_trapdoor_s != null && <> · one Trapdoor call {selected.honest_trapdoor_s.toFixed(2)}s</>}
            </div>
            {selected.estimate && (
              <div className="text-ink-400">
                estimate: backend <span className="mono">{selected.estimate.backend}</span>, target norm{" "}
                <span className="mono">{selected.estimate.target_norm?.toFixed(2)}</span>, Gaussian heuristic{" "}
                <span className="mono">{selected.estimate.gaussian_heuristic?.toFixed(2)}</span>, required δ₀{" "}
                <span className="mono">{selected.estimate.required_delta0?.toFixed(5)}</span>
                {selected.estimate.fit_valid ? "" : " (outside the fit's reliable range)"}
                <div className="mt-1 text-ink-500">{selected.estimate.note}</div>
              </div>
            )}
            {selected.attempts?.length > 0 && (
              <table className="mono text-[11px]">
                <thead><tr className="text-left text-ink-500"><th className="pr-3">BKZ β</th><th className="pr-3">basis GS</th><th className="pr-3">N0* / N0</th><th className="pr-3">break</th><th>time</th></tr></thead>
                <tbody>
                  {selected.attempts.map((a) => (
                    <tr key={a.beta} className="text-ink-300">
                      <td className="pr-3">{a.beta}</td>
                      <td className="pr-3">{a.gs_norm.toFixed(2)}</td>
                      <td className="pr-3">{a.N0_star ?? "—"} / {a.N0_legit}</td>
                      <td className={`pr-3 ${a.break ? "text-signal-red" : ""}`}>{String(a.break)}</td>
                      <td>{a.runtime_s.toFixed(1)}s</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </Card>
      )}
    </div>
  );
}
