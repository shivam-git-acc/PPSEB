import { useEffect, useRef, useState } from "react";
import {
  ResponsiveContainer, LineChart, Line, BarChart, Bar, ScatterChart, Scatter,
  XAxis, YAxis, ZAxis, Tooltip, CartesianGrid, ReferenceLine, Legend, Cell as ReCell,
} from "recharts";
import { api } from "../api";
import { Card, Badge, PrimaryButton, ErrorBanner } from "../components/Section";

const AXIS = { stroke: "#8a8a94", fontSize: 11 };
const TIP = { background: "#16161a", border: "1px solid #2a2a30", fontSize: 12 };
const label = (value, angle = 0, position = "insideBottom") =>
  ({ value, angle, position, offset: angle ? 0 : -14, fill: "#8a8a94", fontSize: 11 });

function Field({ label: text, value, onChange, ...rest }) {
  return (
    <label className="block"><div className="text-ink-400 mb-1">{text}</div>
      <input type="number" value={value} onChange={(e) => onChange(e.target.value)} {...rest}
        className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-full" /></label>
  );
}

export default function RecoveryTab({ initialized, onTrace }) {
  const [records, setRecords] = useState(30);
  const [samples, setSamples] = useState(50);
  const [repeats, setRepeats] = useState(3);
  const [jobId, setJobId] = useState(null);
  const [snap, setSnap] = useState(null);
  const [error, setError] = useState(null);
  const poll = useRef(null);

  useEffect(() => {
    if (!jobId) return undefined;
    const tick = async () => {
      try {
        const r = await api.recoveryStatus(jobId);
        setSnap(r.result);
        if (r.result.status !== "running") {
          clearInterval(poll.current);
          if (r.result.result?.trace) onTrace?.(r.result.result.trace, "Recovery Analysis");
        }
      } catch (e) { setError(String(e.message || e)); clearInterval(poll.current); }
    };
    tick();
    poll.current = setInterval(tick, 3000);
    return () => clearInterval(poll.current);
  }, [jobId, onTrace]);

  const start = async () => {
    setError(null); setSnap(null);
    try {
      const r = await api.recoveryStart({
        records_per_period: Number(records), samples: Number(samples), repeats: Number(repeats),
      });
      setJobId(r.result.job_id);
    } catch (e) { setError(String(e.message || e)); }
  };

  const res = snap?.result;
  const running = snap?.status === "running";
  const corr = res?.correlations_all;
  const hist = res?.plot2_margin_histograms;

  return (
    <div className="space-y-5 max-w-5xl">
      <Card title="Recovery Analysis"
        subtitle="What actually decides break vs no-break: the realized trapdoor, not the basis bound">
        <p className="text-sm text-ink-300 leading-relaxed">
          The attack displays used to report the basis Gram-Schmidt norm, and it does not predict
          recovery — a basis at GS 6.24 recovered every time while one at GS 5.29 recovered a
          quarter of the time. The GS norm is a <b>distributional bound</b> on what SamplePre will
          produce. Verify consumes <b>one realized trapdoor</b>, and accepts exactly when every
          coordinate of CT₁ − Trapᵀ·CT₂ lands within q/4 of q/2. So this measures ‖Trap‖ and the
          resulting <b>decode margin</b> per attempt, over many draws, and shows which variable
          the outcome actually follows.
        </p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs mt-4">
          <Field label="records / period" value={records} onChange={setRecords} min={2} max={60} />
          <Field label="trapdoor samples" value={samples} onChange={setSamples} min={2} max={400} />
          <Field label="repeats" value={repeats} onChange={setRepeats} min={1} max={10} />
          <div className="flex items-end">
            <PrimaryButton onClick={start} disabled={!initialized || running}>
              {running ? `Measuring… ${snap.done ?? 0}/${snap.total ?? "?"}` : "Run measurement"}
            </PrimaryButton>
          </div>
        </div>
        <ErrorBanner message={error} />
        {snap && (
          <div className="text-xs text-ink-500 mono mt-3">
            {snap.job_id} · {snap.status} · {snap.stage} · {snap.elapsed_s?.toFixed(0)}s
            {res && <> · {res.n_attempts} attempts</>}
          </div>
        )}
      </Card>

      {res && (
        <>
          <Card title="Plot 1 — recovery rate vs realized ‖Trap‖"
            subtitle="Binned by quantile; each point is the fraction of attempts in that bin whose search returned the doctor's own record.">
            <ResponsiveContainer width="100%" height={260}>
              <LineChart data={res.plot1_recovery_vs_trap_norm} margin={{ top: 10, right: 20, bottom: 28, left: 8 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2a2a30" />
                <XAxis type="number" dataKey="center" domain={["dataMin", "dataMax"]} {...AXIS}
                  label={label("realized ‖Trap‖")} />
                <YAxis domain={[0, 1]} {...AXIS} label={label("recovery rate", -90, "insideLeft")} />
                <Tooltip contentStyle={TIP}
                  formatter={(v, n, p) => [`${(v * 100).toFixed(0)}% of ${p.payload.n} attempts`, "recovered"]}
                  labelFormatter={(v) => `‖Trap‖ ≈ ${Number(v).toFixed(0)}`} />
                <Line type="monotone" dataKey="rate" stroke="#ef4444" strokeWidth={2} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </Card>

          <Card title="Plot 2 — decode margin, recovered vs failed"
            subtitle="The mechanistic proof: the margin is the deciding line, not a correlate of it.">
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={hist.bins} margin={{ top: 10, right: 20, bottom: 28, left: 8 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2a2a30" />
                <XAxis type="number" dataKey="center" domain={["dataMin", "dataMax"]} {...AXIS}
                  label={label("decode margin  (q/4 − worst coordinate's distance from q/2)")} />
                <YAxis {...AXIS} label={label("attempts", -90, "insideLeft")} />
                <Tooltip contentStyle={TIP} labelFormatter={(v) => `margin ≈ ${Number(v).toFixed(0)}`} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <ReferenceLine x={0} stroke="#e5e5ea" strokeDasharray="4 3"
                  label={{ value: "margin = 0", fill: "#e5e5ea", fontSize: 11, position: "top" }} />
                <Bar dataKey="recovered" name="recovered" fill="#ef4444" />
                <Bar dataKey="failed" name="failed" fill="#4ade80" />
              </BarChart>
            </ResponsiveContainer>
            <div className="flex gap-3 flex-wrap mt-2">
              <Badge tone={hist.target_match_matches_margin ? "green" : "amber"}>
                margin &gt; 0 ⟺ Verify accepts: {String(hist.target_match_matches_margin)} over {hist.n} attempts
              </Badge>
              {hist.false_accepts > 0 && (
                <Badge tone="amber">{hist.false_accepts} false accept(s) — a decoy matched first</Badge>
              )}
            </div>
          </Card>

          <Card title="Plot 3 — the falsifier: recovery vs basis GS norm"
            subtitle="Same y-axis, the OLD variable on x. If the basis norm predicted recovery this would descend cleanly. It does not.">
            <ResponsiveContainer width="100%" height={260}>
              <ScatterChart margin={{ top: 10, right: 20, bottom: 28, left: 8 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2a2a30" />
                <XAxis type="number" dataKey="basis_gs" {...AXIS} domain={["dataMin - 0.3", "dataMax + 0.3"]}
                  label={label("attack basis Gram-Schmidt norm")} />
                <YAxis type="number" dataKey="recovery_rate" domain={[0, 1]} {...AXIS}
                  label={label("recovery rate", -90, "insideLeft")} />
                <ZAxis range={[90, 90]} />
                <Tooltip contentStyle={TIP}
                  formatter={(_v, _n, p) => [`${p.payload.attack} period ${p.payload.period}: `
                    + `GS ${p.payload.basis_gs.toFixed(2)} → ${(p.payload.recovery_rate * 100).toFixed(0)}%`, "cell"]} />
                <Scatter data={res.plot3_cells}>
                  {res.plot3_cells.map((c, idx) => (
                    <ReCell key={idx} fill={c.attack === "public_key" ? "#5b9dff" : "#fb923c"} />
                  ))}
                </Scatter>
              </ScatterChart>
            </ResponsiveContainer>
            <div className="flex gap-4 flex-wrap text-[11px] mt-1">
              <span className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-full inline-block" style={{ background: "#5b9dff" }} />
                <span className="text-ink-500">public-key attack</span></span>
              <span className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-full inline-block" style={{ background: "#fb923c" }} />
                <span className="text-ink-500">stolen-key attack</span></span>
            </div>
            {corr && (
              <div className="text-xs text-ink-300 mt-3 leading-relaxed">
                Correlation with recovery, over the same {corr.n_attempts} attempts:{" "}
                <span className="mono">realized ‖Trap‖ r={corr.trap_norm?.toFixed(2)}</span>,{" "}
                <span className="mono">decode margin r={corr.margin?.toFixed(2)}</span>,{" "}
                <span className="mono text-ink-500">basis GS norm r={corr.basis_gs?.toFixed(2)}</span>.
              </div>
            )}
          </Card>

          {res.sigma_sweep?.length > 0 && (
            <Card title="Plot 4 — the controlled law: recovery vs the attacker's sampling σ"
              subtitle="One fixed basis. Only σ changes, so ‖Trap‖ grows, the margin shrinks, and the rate walks down.">
              <ResponsiveContainer width="100%" height={260}>
                <LineChart data={res.sigma_sweep} margin={{ top: 10, right: 40, bottom: 28, left: 8 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#2a2a30" />
                  <XAxis type="number" dataKey="sigma" {...AXIS} domain={["dataMin", "dataMax"]}
                    label={label("attacker's sampling σ")} />
                  <YAxis yAxisId="rate" domain={[0, 1]} {...AXIS} label={label("recovery rate", -90, "insideLeft")} />
                  <YAxis yAxisId="margin" orientation="right" {...AXIS} />
                  <Tooltip contentStyle={TIP} labelFormatter={(v) => `σ = ${Number(v).toFixed(1)}`} />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  <ReferenceLine yAxisId="margin" y={0} stroke="#4b4b55" strokeDasharray="4 3" />
                  <Line yAxisId="rate" type="monotone" dataKey="recovery_rate" name="recovery rate"
                    stroke="#ef4444" strokeWidth={2} dot={{ r: 3 }} />
                  <Line yAxisId="margin" type="monotone" dataKey="mean_margin" name="mean decode margin"
                    stroke="#5b9dff" strokeWidth={2} strokeDasharray="5 3" dot={{ r: 3 }} />
                </LineChart>
              </ResponsiveContainer>
              <Badge tone={res.sigma_sweep_monotone ? "green" : "amber"}>
                recovery rate monotone in σ: {String(res.sigma_sweep_monotone)}
              </Badge>
            </Card>
          )}

          <Card title="Per-cell detail">
            <div className="overflow-x-auto">
              <table className="w-full text-xs mono">
                <thead><tr className="text-left text-ink-500 uppercase">
                  <th className="pb-2 pr-3">attack</th><th className="pb-2 pr-3">rep</th>
                  <th className="pb-2 pr-3">period</th><th className="pb-2 pr-3">recovery rate</th>
                  <th className="pb-2 pr-3">mean ‖Trap‖</th><th className="pb-2 pr-3">mean margin</th>
                  <th className="pb-2 pr-3 text-ink-600">basis GS (bound)</th><th className="pb-2">honest GS</th>
                </tr></thead>
                <tbody>
                  {res.cells.map((c, i) => (
                    <tr key={i} className="border-t border-ink-800">
                      <td className="py-1.5 pr-3 text-ink-300">{c.attack}</td>
                      <td className="py-1.5 pr-3 text-ink-500">{c.repeat}</td>
                      <td className="py-1.5 pr-3 text-ink-500">{c.period}</td>
                      <td className="py-1.5 pr-3 text-signal-red">
                        {c.recovery_rate != null ? `${(c.recovery_rate * 100).toFixed(0)}%` : (c.error ?? "—")}
                      </td>
                      <td className="py-1.5 pr-3">{c.mean_trap_norm?.toFixed(1) ?? "—"}</td>
                      <td className="py-1.5 pr-3" style={{ color: c.mean_margin > 0 ? "#4ade80" : "#f59e0b" }}>
                        {c.mean_margin != null ? c.mean_margin.toFixed(1) : "—"}
                      </td>
                      <td className="py-1.5 pr-3 text-ink-600">{c.basis_gs?.toFixed(2) ?? "—"}</td>
                      <td className="py-1.5 text-ink-500">{c.honest_gs?.toFixed(2) ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="text-[11px] text-ink-500 mt-2">
              The basis GS column is a distributional bound — it does not predict recovery; see Plot 3.
            </p>
          </Card>

          <Card title="Conclusion (every number from this run)">
            <p className="text-sm text-ink-200 leading-relaxed">{res.statement}</p>
          </Card>
        </>
      )}
    </div>
  );
}
