import { useEffect, useRef, useState } from "react";
import {
  ResponsiveContainer, ScatterChart, Scatter, XAxis, YAxis, ZAxis, Tooltip,
  CartesianGrid, ReferenceArea, Cell as ReCell,
} from "recharts";
import { api } from "../api";
import { Card, Badge, PrimaryButton, SecondaryButton, ErrorBanner } from "../components/Section";

const OUTCOMES = {
  broke: { y: 1, label: "broke", colour: "#d03b3b" },
  attack_failed: { y: 2, label: "attack ran, failed", colour: "#0ca30c" },
  "timed_out (unmeasured)": { y: 3, label: "unmeasured (timeout)", colour: "#6f7a8d" },
  "n/a (honest incorrect)": { y: 4, label: "n/a: honest incorrect", colour: "#2b3241" },
  "n/a (H2)": { y: 4, label: "n/a: H2", colour: "#2b3241" },
  untrusted: { y: 5, label: "untrusted", colour: "#fab219" },
  error: { y: 5, label: "error", colour: "#7a3138" },
};
const STOLEN_COLOURS = { broke: "#d95926", attack_failed: "#0ca30c", "timed_out (unmeasured)": "#6f7a8d" };
const Y_TICKS = { 1: "broke", 2: "failed", 3: "unmeasured", 4: "n/a", 5: "untrusted" };
const VERDICT_TONE = {
  "BROKEN (public-key only)": "red",
  "forward-security break (stolen key REQUIRED)": "amber",
  "unmeasured (timeout)": "neutral",
  "attack failed (secure vs both, this budget)": "green",
  untrusted: "amber",
  "n/a (not attacked)": "neutral",
};
const WIDE_GRID = [4, 8, 16].flatMap((n) => [257, 1153, 4001, 12289, 40961].map((q) => `${n}:${q}`)).join(", ");

function parseGrid(text) {
  return text.split(",").map((pair) => pair.split(":").map((x) => parseInt(x.trim(), 10)))
    .filter(([n, q]) => Number.isFinite(n) && Number.isFinite(q));
}

const fmtBits = (b) => (b == null ? "—" : b.toFixed(1));

function outcomeOf(c) { return OUTCOMES[c.outcome] ?? OUTCOMES.error; }

function NumberField({ label, value, onChange }) {
  return (
    <label className="block"><div className="text-ink-400 mb-1">{label}</div>
      <input type="number" value={value} onChange={(e) => onChange(e.target.value)}
        className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-full" /></label>
  );
}

export default function SecurityBoundaryTab({ initialized }) {
  const [gridText, setGridText] = useState(WIDE_GRID);
  const [budget, setBudget] = useState(600);
  const [cellTimeout, setCellTimeout] = useState(2400);
  const [maxHours, setMaxHours] = useState(9);
  const [runStolen, setRunStolen] = useState(true);
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

  const start = async (resumeId = null) => {
    setError(null);
    setSelected(null);
    try {
      const r = await api.boundaryStart({
        grid: parseGrid(gridText), attack_budget_s: Number(budget), cell_timeout_s: Number(cellTimeout),
        max_hours: Number(maxHours), run_stolen: runStolen, job_id: resumeId,
      });
      if (!resumeId) setSnap(null);
      setJobId(r.result.job_id);
    } catch (e) {
      setError(String(e.message || e));
    }
  };

  const cells = snap?.cells ?? [];
  const running = snap?.status === "running";
  const withBits = cells.filter((c) => c.bits != null);
  const pkPoints = withBits.map((c) => ({ ...c, x: c.bits, y: outcomeOf(c).y - 0.13, colour: outcomeOf(c).colour }));
  const stolenPoints = withBits.filter((c) => c.stolen_outcome).map((c) => ({
    ...c, x: c.bits, y: (OUTCOMES[c.stolen_outcome] ?? OUTCOMES.error).y + 0.13,
    colour: STOLEN_COLOURS[c.stolen_outcome] ?? "#7a3138",
  }));
  const brokeBits = cells.filter((c) => c.outcome === "broke" && c.bits != null).map((c) => c.bits);
  const maxBroke = brokeBits.length ? Math.max(...brokeBits) : null;
  const sized = withBits.filter((c) => c.trapdoor_bytes != null).map((c) => ({ ...c, x: c.bits, y: c.trapdoor_bytes }));
  const tally = snap?.stolen_key_tally;

  return (
    <div className="space-y-4">
      <Card title="Security Boundary"
        subtitle="Public-key-only vs stolen-key attack, on one estimated bit-security axis">
        <p className="text-[13px] text-ink-300 leading-relaxed max-w-3xl">
          Two attacks per (n, q), same frozen database: public key alone, and a stolen sk<sub>r|J</sub> pulled
          backward. The x-axis is <b className="text-ink-100">estimated</b>; the outcome is{" "}
          <b className="text-ink-100">measured</b>. A cell the public key already breaks counts as redundant
          theft, not a forward-security break — and a cell that ran out of budget is unmeasured, never secure.
        </p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs mt-4">
          <label className="block col-span-2 md:col-span-4"><div className="text-ink-400 mb-1">grid as n:q pairs</div>
            <input value={gridText} onChange={(e) => setGridText(e.target.value)}
              className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-full" /></label>
          <NumberField label="attack budget / cell (s)" value={budget} onChange={setBudget} />
          <NumberField label="hard cell timeout (s)" value={cellTimeout} onChange={setCellTimeout} />
          <NumberField label="overall cap (hours)" value={maxHours} onChange={setMaxHours} />
          <label className="flex items-end gap-2 pb-1.5 text-ink-300">
            <input type="checkbox" checked={runStolen} onChange={(e) => setRunStolen(e.target.checked)} />
            run the stolen-key attack
          </label>
        </div>
        <div className="flex gap-3 items-center mt-3">
          <PrimaryButton onClick={() => start(null)} disabled={!initialized || running}>
            {running ? `Running… ${snap.units_done}/${snap.units_total} units` : "Run wide sweep"}
          </PrimaryButton>
          {jobId && !running && (
            <SecondaryButton onClick={() => start(jobId)}>Resume {jobId} (skips finished cells)</SecondaryButton>
          )}
          <span className="text-xs text-ink-500">Checkpointed per cell — you can close the tab.</span>
        </div>
        <ErrorBanner message={error} />
        {snap && (
          <div className="text-xs text-ink-500 mono mt-3">
            {snap.job_id} · {snap.status} · {snap.done}/{snap.total} cells ({snap.units_done}/{snap.units_total} units)
            · {snap.elapsed_s?.toFixed(0)}s{cells[0]?.estimate && <> · estimator: {cells[0].estimate.backend}</>}
          </div>
        )}
        {snap?.stopped_early && (
          <div className="text-xs text-amber-400 bg-amber-500/10 border border-amber-600/30 rounded px-3 py-2 mt-2">
            ⚠ {snap.stopped_early}
          </div>
        )}
        {snap?.config?.q_substitution_note && (
          <div className="text-[11px] text-ink-500 mt-2 leading-relaxed">
            Deviation from the patch, stated: {snap.config.q_substitution_note}
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

      {pkPoints.length > 0 && (
        <Card title="Estimated security (bits) vs measured outcome — both attacks"
          subtitle="Circle = public key only. Triangle = stolen key. Red/orange = the attack got a working trapdoor; grey = out of budget, i.e. unmeasured.">
          <ResponsiveContainer width="100%" height={320}>
            <ScatterChart margin={{ top: 10, right: 20, bottom: 28, left: 8 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--grid)" />
              {maxBroke != null && (
                <ReferenceArea x1={0} x2={maxBroke} fill="#d03b3b" fillOpacity={0.09}
                  label={{ value: `public key alone breaks ≤ ~${maxBroke.toFixed(0)} bits`, fill: "#d03b3b", fontSize: 11, position: "insideTopLeft" }} />
              )}
              <XAxis type="number" dataKey="x" name="estimated bits" stroke="#6f7a8d" fontSize={11}
                domain={[0, "dataMax + 10"]}
                label={{ value: "estimated security (bits, core-SVP)", position: "insideBottom", offset: -14, fill: "#6f7a8d", fontSize: 11 }} />
              <YAxis type="number" dataKey="y" stroke="#6f7a8d" fontSize={11} domain={[0.5, 5.5]}
                ticks={[1, 2, 3, 4, 5]} tickFormatter={(v) => Y_TICKS[v] ?? ""} width={96} />
              <ZAxis range={[90, 90]} />
              <Tooltip
                contentStyle={{ background: "#141721", border: "1px solid #2a2a30", fontSize: 12 }}
                formatter={(_v, name, p) => {
                  const c = p.payload;
                  const isPk = name === "public key only";
                  const outcome = isPk ? c.outcome : c.stolen_outcome;
                  const beta = isPk ? c.pk_beta : c.stolen_beta;
                  return [`n=${c.n}, q=${c.q}, m=${c.m} — ${outcome}${beta ? `, at BKZ-${beta}` : ""}`, name];
                }} />
              <Scatter name="public key only" data={pkPoints} shape="circle" onClick={(p) => setSelected(p)}>
                {pkPoints.map((p) => (
                  <ReCell key={`pk-${p.n}-${p.q}`} fill={p.colour}
                    stroke={p.paper_demo ? "#a4aec0" : undefined} strokeWidth={p.paper_demo ? 2 : 0} />
                ))}
              </Scatter>
              <Scatter name="stolen key" data={stolenPoints} shape="triangle" onClick={(p) => setSelected(p)}>
                {stolenPoints.map((p) => (
                  <ReCell key={`st-${p.n}-${p.q}`} fill={p.colour}
                    stroke={p.paper_demo ? "#a4aec0" : undefined} strokeWidth={p.paper_demo ? 2 : 0} />
                ))}
              </Scatter>
            </ScatterChart>
          </ResponsiveContainer>
          <div className="flex gap-4 flex-wrap text-[11px] mt-1">
            <span className="flex items-center gap-1.5">
              <span className="w-3 h-3 rounded-full inline-block" style={{ background: "#d03b3b" }} />
              <span className="text-ink-500">public key alone broke it</span></span>
            <span className="flex items-center gap-1.5">
              <span className="w-3 h-3 inline-block" style={{ background: "#d95926", clipPath: "polygon(50% 0, 100% 100%, 0 100%)" }} />
              <span className="text-ink-500">stolen key broke it</span></span>
            <span className="flex items-center gap-1.5">
              <span className="w-3 h-3 rounded-full inline-block" style={{ background: "#0ca30c" }} />
              <span className="text-ink-500">attack ran, failed</span></span>
            <span className="flex items-center gap-1.5">
              <span className="w-3 h-3 rounded-full inline-block" style={{ background: "#6f7a8d" }} />
              <span className="text-ink-500">unmeasured (timeout)</span></span>
            <span className="flex items-center gap-1.5">
              <span className="w-3 h-3 rounded-full inline-block border-2" style={{ borderColor: "#a4aec0" }} />
              <span className="text-ink-500">paper's demo parameters</span></span>
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

      {tally && (
        <Card title="Does the stolen key help?"
          subtitle="A forward-security break requires the public key to FAIL and the stolen key to succeed — everything else is redundant theft or unmeasured.">
          <div className="flex gap-3 flex-wrap mb-4">
            <Badge tone={tally.stolen_helps.length ? "amber" : "green"}>
              stolen key required: {tally.stolen_helps.length}/{tally.considered}
            </Badge>
            <Badge tone="red">both broke (theft redundant): {tally.both_broke.length}</Badge>
            <Badge tone="red">public key only: {tally.pk_only.length}</Badge>
            <Badge tone="green">neither broke: {tally.neither.length}</Badge>
            <Badge tone="neutral">unmeasured: {tally.unmeasured.length}</Badge>
            <Badge tone="neutral">excluded (untrusted / n/a): {tally.excluded.length}</Badge>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2">
            {cells.map((c) => (
              <button key={`${c.n}-${c.q}`} onClick={() => setSelected(c)}
                className="border border-ink-800 rounded px-2.5 py-2 text-left hover:border-ink-600">
                <div className="mono text-[11px] text-ink-300">n={c.n}, q={c.q}</div>
                <div className="flex gap-1.5 mt-1.5 text-[10px]">
                  <span className={c.pk_broke ? "text-signal-red" : "text-ink-500"}>
                    {c.pk_broke ? "● pk broke" : "○ pk"}
                  </span>
                  <span className={c.stolen_broke ? "text-amber-400" : "text-ink-500"}>
                    {c.stolen_broke ? "▲ stolen broke" : "△ stolen"}
                  </span>
                </div>
                <div className="text-[10px] mt-1" style={{ color: c.stolen_helps ? "#d95926" : "#6f7a8d" }}>
                  {c.stolen_helps ? "stolen key REQUIRED" : c.verdict}
                </div>
              </button>
            ))}
          </div>
          <p className="text-xs text-ink-400 mt-3 leading-relaxed">
            In {tally.stolen_helps.length} of {tally.considered} cells where both attacks ran, the stolen key
            succeeded where the public key alone failed (genuine forward-security break); in{" "}
            {tally.both_broke.length} cells both broke (stolen key redundant); in {tally.neither.length} cells
            neither broke within budget. {tally.unmeasured.length} cell(s) are unmeasured and{" "}
            {tally.excluded.length} excluded — neither counts as security.
          </p>
        </Card>
      )}

      {sized.length > 0 && (
        <Card title="Cost of reaching higher estimated security"
          subtitle="Trapdoor size (m·⌈log2 q⌉/8 bytes) against the same bit axis — the paper's efficiency figures live at the low-bit end.">
          <ResponsiveContainer width="100%" height={250}>
            <ScatterChart margin={{ top: 10, right: 20, bottom: 28, left: 8 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--grid)" />
              <XAxis type="number" dataKey="x" stroke="#6f7a8d" fontSize={11} domain={[0, "dataMax + 10"]}
                label={{ value: "estimated security (bits)", position: "insideBottom", offset: -14, fill: "#6f7a8d", fontSize: 11 }} />
              <YAxis type="number" dataKey="y" stroke="#6f7a8d" fontSize={11}
                label={{ value: "trapdoor bytes", angle: -90, position: "insideLeft", fill: "#6f7a8d", fontSize: 11 }} />
              <ZAxis range={[80, 80]} />
              <Tooltip contentStyle={{ background: "#141721", border: "1px solid #2a2a30", fontSize: 12 }}
                formatter={(v, _n, p) => [`n=${p.payload.n}, q=${p.payload.q}: ${v} bytes`, "trapdoor"]} />
              <Scatter data={sized} fill="#3987e5" />
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
                  <th className="pb-2 pr-3">bits (est)</th>
                  <th className="pb-2 pr-3">pk attack</th><th className="pb-2 pr-3">β</th>
                  <th className="pb-2 pr-3">stolen attack</th><th className="pb-2 pr-3">β</th>
                  <th className="pb-2 pr-3">verdict</th>
                  <th className="pb-2 pr-3">rep</th><th className="pb-2">runtime</th>
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
                    <td className="py-1.5 pr-3" style={{ color: outcomeOf(c).colour }}>{c.pk_outcome ?? c.outcome}</td>
                    <td className="py-1.5 pr-3">{c.pk_beta ?? "—"}</td>
                    <td className="py-1.5 pr-3" style={{ color: STOLEN_COLOURS[c.stolen_outcome] ?? "#6f7a8d" }}>
                      {c.stolen_outcome ?? "—"}</td>
                    <td className="py-1.5 pr-3">{c.stolen_beta ?? "—"}</td>
                    <td className="py-1.5 pr-3">
                      <Badge tone={VERDICT_TONE[c.verdict] ?? "neutral"}>{c.verdict ?? "—"}</Badge>
                    </td>
                    <td className="py-1.5 pr-3">{c.repeats ?? 1}</td>
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
          <div className="text-xs space-y-3">
            <div className="text-ink-300">
              verdict <span style={{ color: selected.stolen_helps ? "#d95926" : outcomeOf(selected).colour }}>{selected.verdict}</span>
              {selected.gate_failed_checks?.length > 0 && <> · honest gate failed: <span className="mono">{selected.gate_failed_checks.join(", ")}</span></>}
              {selected.control && <> · control {selected.control.passed ? "PASSED (untrusted)" : "failed, as required"}</>}
              {selected.honest_trapdoor_s != null && <> · one Trapdoor call {selected.honest_trapdoor_s.toFixed(2)}s</>}
              {selected.periods_back != null && <> · attacked period {selected.target_period} ({selected.periods_back} back)</>}
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
            {[["Attack 1 — public key only", selected.pk_attempts],
              ["Attack 2 — stolen sk_r|J, transformed backward", selected.stolen_attempts]]
              .filter(([, rows]) => rows?.length).map(([title, rows]) => (
              <div key={title}>
                <div className="text-ink-400 mb-1">{title}</div>
                <table className="mono text-[11px]">
                  <thead><tr className="text-left text-ink-500">
                    <th className="pr-3">BKZ β</th><th className="pr-3">basis GS</th><th className="pr-3">L1 norm ok</th>
                    <th className="pr-3">N0* / N0</th><th className="pr-3">break</th><th>time</th></tr></thead>
                  <tbody>
                    {rows.map((a) => (
                      <tr key={a.beta} className="text-ink-300">
                        <td className="pr-3">{a.beta}</td>
                        <td className="pr-3">{a.gs_norm != null ? a.gs_norm.toFixed(2) : (a.error ?? "—")}</td>
                        <td className="pr-3">{a.level1_norm_ok == null ? "—" : String(a.level1_norm_ok)}</td>
                        <td className="pr-3">{a.N0_star ?? "—"} / {a.N0_legit ?? "—"}</td>
                        <td className={`pr-3 ${a.break ? "text-signal-red" : ""}`}>{String(!!a.break)}</td>
                        <td>{a.runtime_s?.toFixed(1)}s</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))}
            {selected.repeat_outcomes && (
              <div className="text-ink-500">
                repeats: {selected.repeat_outcomes.map((r) => `seed ${r.seed}: pk ${r.pk}, stolen ${r.stolen}`).join(" · ")}
              </div>
            )}
          </div>
        </Card>
      )}
    </div>
  );
}
