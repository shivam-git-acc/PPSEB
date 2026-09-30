import { useEffect, useRef, useState } from "react";
import {
  ResponsiveContainer, LineChart, Line, BarChart, Bar, ScatterChart, Scatter,
  XAxis, YAxis, ZAxis, Tooltip, CartesianGrid, ReferenceLine, Legend, Cell as ReCell,
} from "recharts";
import { api } from "../api";
import { Card, Badge, PrimaryButton, ErrorBanner } from "../components/Section";

const AXIS = { stroke: "#6f7a8d", fontSize: 11 };
const TIP = { background: "#141721", border: "1px solid #2a3040", borderRadius: 10,
              fontSize: 12, color: "#e8ecf4" };
const label = (value, angle = 0, position = "insideBottom") =>
  ({ value, angle, position, offset: angle ? 0 : -14, fill: "#6f7a8d", fontSize: 11 });

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
    <div className="space-y-4">
      <Card title="Recovery Analysis"
        subtitle="What actually decides break vs no-break: the realized trapdoor, not the basis bound">
        <p className="text-[13px] text-ink-300 leading-relaxed max-w-3xl">
          The basis Gram-Schmidt norm is a <b className="text-ink-100">bound on the distribution</b> SamplePre
          draws from. Verify consumes <b className="text-ink-100">one realized trapdoor</b>. So recovery follows
          ‖Trap‖ and the decode margin — not the basis norm, which here correlates the wrong way.
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
                <CartesianGrid strokeDasharray="3 3" stroke="var(--grid)" />
                <XAxis type="number" dataKey="center" domain={["dataMin", "dataMax"]} {...AXIS}
                  label={label("realized ‖Trap‖")} />
                <YAxis domain={[0, 1]} {...AXIS} label={label("recovery rate", -90, "insideLeft")} />
                <Tooltip contentStyle={TIP}
                  formatter={(v, n, p) => [`${(v * 100).toFixed(0)}% of ${p.payload.n} attempts`, "recovered"]}
                  labelFormatter={(v) => `‖Trap‖ ≈ ${Number(v).toFixed(0)}`} />
                <Line type="monotone" dataKey="rate" stroke="#d03b3b" strokeWidth={2} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </Card>

          <Card title="Plot 2 — decode margin, recovered vs failed"
            subtitle="The mechanistic proof: the margin is the deciding line, not a correlate of it.">
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={hist.bins} margin={{ top: 10, right: 20, bottom: 28, left: 8 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--grid)" />
                <XAxis type="number" dataKey="center" domain={["dataMin", "dataMax"]} {...AXIS}
                  label={label("decode margin  (q/4 − worst coordinate's distance from q/2)")} />
                <YAxis {...AXIS} label={label("attempts", -90, "insideLeft")} />
                <Tooltip contentStyle={TIP} labelFormatter={(v) => `margin ≈ ${Number(v).toFixed(0)}`} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <ReferenceLine x={0} stroke="#a4aec0" strokeDasharray="4 3"
                  label={{ value: "margin = 0", fill: "#a4aec0", fontSize: 11, position: "top" }} />
                <Bar dataKey="recovered" name="recovered" fill="#d03b3b" />
                <Bar dataKey="failed" name="failed" fill="#0ca30c" />
              </BarChart>
            </ResponsiveContainer>
            <div className="flex gap-3 flex-wrap mt-2">
              <Badge tone={hist.target_match_matches_margin ? "green" : "amber"}>
                margin &gt; 0 ⟺ Verify accepts: {String(hist.target_match_matches_margin)} over {hist.n} attempts
              </Badge>
              {hist.false_accepts > 0 && (
                <Badge tone="amber">{hist.false_accepts} false accept(s) — a decoy matched first</Badge>
              )}
              {hist.zero_margin > 0 && (
                <Badge tone="neutral">{hist.zero_margin} attempt(s) at margin exactly 0</Badge>
              )}
            </div>
            <p className="text-[11px] text-ink-500 mt-2 leading-relaxed">
              Bins are anchored so 0 is an edge and each bar covers (lo, hi]. Verify accepts only
              when the worst coordinate is <i>strictly</i> inside q/4, so a margin of exactly 0 is a
              failure and is drawn to the left of the line with the other failures.
            </p>
          </Card>

          <Card title="Plot 3 — the falsifier: recovery vs basis GS norm"
            subtitle="Same y-axis, the OLD variable on x. If the basis norm predicted recovery this would descend cleanly. It does not.">
            <ResponsiveContainer width="100%" height={260}>
              <ScatterChart margin={{ top: 10, right: 20, bottom: 28, left: 8 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--grid)" />
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
                    <ReCell key={idx} fill={c.attack === "public_key" ? "#3987e5" : "#d95926"} />
                  ))}
                </Scatter>
              </ScatterChart>
            </ResponsiveContainer>
            <div className="flex gap-4 flex-wrap text-[11px] mt-1">
              <span className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-full inline-block" style={{ background: "#3987e5" }} />
                <span className="text-ink-500">public-key attack</span></span>
              <span className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-full inline-block" style={{ background: "#d95926" }} />
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
            <Card title="Recovery vs the attacker's sampling σ"
              subtitle="One fixed basis; only σ changes. Two measures, two panels — never two y-scales on one chart.">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                <div>
                  <div className="text-2xs uppercase tracking-[0.08em] text-ink-500 mb-1">Recovery rate</div>
                  <ResponsiveContainer width="100%" height={200}>
                    <LineChart data={res.sigma_sweep} margin={{ top: 8, right: 16, bottom: 26, left: 4 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--grid)" />
                      <XAxis type="number" dataKey="sigma" {...AXIS} domain={["dataMin", "dataMax"]}
                        label={label("attacker σ")} />
                      <YAxis domain={[0, 1]} {...AXIS} width={38} />
                      <Tooltip contentStyle={TIP} labelFormatter={(v) => `σ = ${Number(v).toFixed(1)}`} />
                      <Line type="monotone" dataKey="recovery_rate" name="recovery rate"
                        stroke="#d03b3b" strokeWidth={2} dot={{ r: 3.5 }} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
                <div>
                  <div className="text-2xs uppercase tracking-[0.08em] text-ink-500 mb-1">Mean decode margin</div>
                  <ResponsiveContainer width="100%" height={200}>
                    <LineChart data={res.sigma_sweep} margin={{ top: 8, right: 16, bottom: 26, left: 4 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--grid)" />
                      <XAxis type="number" dataKey="sigma" {...AXIS} domain={["dataMin", "dataMax"]}
                        label={label("attacker σ")} />
                      <YAxis {...AXIS} width={38} />
                      <Tooltip contentStyle={TIP} labelFormatter={(v) => `σ = ${Number(v).toFixed(1)}`} />
                      <ReferenceLine y={0} stroke="#a4aec0" strokeDasharray="4 3" />
                      <Line type="monotone" dataKey="mean_margin" name="mean margin"
                        stroke="#3987e5" strokeWidth={2} dot={{ r: 3.5 }} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
              <div className="mt-3">
                <Badge tone={res.sigma_sweep_monotone ? "green" : "amber"}>
                  recovery monotone in σ: {String(res.sigma_sweep_monotone)}
                </Badge>
              </div>
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
                      <td className="py-1.5 pr-3" style={{ color: c.mean_margin > 0 ? "#35c235" : "#fab219" }}>
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
