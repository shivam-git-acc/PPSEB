import { useState } from "react";
import {
  ResponsiveContainer, BarChart, Bar, LineChart, Line, XAxis, YAxis, Tooltip, Legend,
  CartesianGrid, ReferenceLine, ReferenceDot,
} from "recharts";
import { api } from "../api";
import { Card, Badge, PrimaryButton, SecondaryButton, ErrorBanner } from "../components/Section";

function verdictTone(v) {
  if (v === "BROKEN (trivial transform)") return "red";
  if (v === "BROKEN (after LLL reduction)") return "amber";
  if (v.startsWith("survives")) return "green";
  if (v.startsWith("correctness lost")) return "neutral";
  return "neutral";
}

function verdictRowClass(v) {
  if (v.startsWith("correctness lost")) return "bg-ink-800/50 text-ink-500";
  if (v.startsWith("BROKEN")) return "bg-signal-red/5";
  return "";
}

export default function ForwardSecTab({ onTrace, initialized }) {
  const [J, setJ] = useState(5);
  const [variant, setVariant] = useState("low_norm");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  const [sweepJ, setSweepJ] = useState(3);
  const [sweepLoading, setSweepLoading] = useState(false);
  const [sweepError, setSweepError] = useState(null);
  const [sweepResult, setSweepResult] = useState(null);

  const [fairnessJ, setFairnessJ] = useState(2);
  const [fairnessLoading, setFairnessLoading] = useState(false);
  const [fairnessError, setFairnessError] = useState(null);
  const [fairnessResult, setFairnessResult] = useState(null);

  const run = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.attackForward({ J, h1_variant: variant, seed: Math.floor(Math.random() * 1e6) });
      setResult(res.result);
      onTrace(res.trace);
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      setLoading(false);
    }
  };

  const runSweep = async () => {
    setSweepLoading(true);
    setSweepError(null);
    try {
      const res = await api.attackForwardSweep({ J: sweepJ, seed: Math.floor(Math.random() * 1e6) });
      setSweepResult(res.result);
    } catch (e) {
      setSweepError(String(e.message || e));
    } finally {
      setSweepLoading(false);
    }
  };

  const runFairness = async () => {
    setFairnessLoading(true);
    setFairnessError(null);
    try {
      const res = await api.attackForwardFairness({ J: fairnessJ, seed: Math.floor(Math.random() * 1e6) });
      setFairnessResult(res.result);
    } catch (e) {
      setFairnessError(String(e.message || e));
    } finally {
      setFairnessLoading(false);
    }
  };

  const isNaive = result?.h1_variant === "naive_uniform";

  const chartDataLowNorm = result?.rows.map((r) => ({
    name: `period ${r.period}`,
    legit: r.legit_gram_schmidt_norm,
    trivial: r.candidate_trivial_gram_schmidt_norm,
    afterLll: r.candidate_after_lll_gram_schmidt_norm,
  })) ?? [];

  const chartDataNaive = result?.rows.map((r) => ({
    name: `period ${r.period}`,
    period: r.period,
    legit: r.legit_gram_schmidt_norm,
  })) ?? [];

  const collapseRow = result?.correctness_lost_at != null
    ? chartDataNaive.find((r) => r.period === result.correctness_lost_at)
    : null;

  const sweepMeasured = sweepResult?.rows.filter((r) => !r.error && !r.skipped) ?? [];
  const sweepChartData = sweepMeasured.map((r) => ({
    name: `n=${r.n}`,
    numBroken: r.num_broken,
    minAfterLll: r.min_after_lll,
    threshold: r.threshold,
  }));

  const fairnessMeasured = fairnessResult?.rows.filter((r) => !r.error && !r.skipped) ?? [];
  const fairnessNs = [...new Set(fairnessMeasured.map((r) => r.n))];
  const fairnessChartData = fairnessNs.map((n) => {
    const row = { name: `n=${n}` };
    for (const cfg of ["LLL_vs_LLL", "BKZ_defender_only", "BKZ_vs_BKZ"]) {
      const match = fairnessMeasured.find((r) => r.n === n && r.config === cfg);
      row[cfg] = match ? match.num_broken : 0;
    }
    return row;
  });

  return (
    <div className="space-y-5 max-w-4xl">
      <Card title="Forward-Security Norm Experiment" subtitle="The H1 dilemma: the paper specifies no construction, and the two natural choices fail differently">
        <p className="text-sm text-ink-300 leading-relaxed">
          Stealing the CURRENT trapdoor sk_rJ must not reveal any EARLIER sk_ri. Consecutive
          periods are related by a public invertible R, so a candidate for any earlier basis is
          computable from public data alone plus the stolen sk_rJ — always. Every candidate is
          measured twice: once as a plain balanced representative (entries mapped into
          (-q/2, q/2], since only residues mod q are meaningful), then again after LLL-reducing
          it — the same finishing step NewBasisDel itself applies. Before judging the attacker at
          all, the LEGITIMATE chain's own basis is checked against an explicit, justified
          usability threshold at every period — if the scheme itself can't produce a usable
          trapdoor, the forward-security question doesn't even apply. Every number below is
          <b> derived from the measured run</b>, never assumed.
        </p>
      </Card>

      <Card title="Run experiment">
        <div className="flex items-end gap-4 flex-wrap">
          <label className="block">
            <div className="text-xs text-ink-400 mb-1">Periods (J)</div>
            <input type="number" min={1} max={12} value={J} onChange={(e) => setJ(Number(e.target.value))}
              className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-20" />
          </label>
          <label className="block">
            <div className="text-xs text-ink-400 mb-1">H1 variant</div>
            <select value={variant} onChange={(e) => setVariant(e.target.value)}
              className="text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5">
              <option value="low_norm">low-norm (I + N)</option>
              <option value="naive_uniform">naive uniform-invertible</option>
            </select>
          </label>
          <PrimaryButton onClick={run} disabled={!initialized || loading}>
            {loading ? "Running…" : "Run experiment"}
          </PrimaryButton>
        </div>
        {!initialized && <div className="text-xs text-ink-500 mt-2">Initialize params in the left rail first.</div>}
        <ErrorBanner message={error} />
      </Card>

      {result && (
        <>
          <Card title={result.headline}>
            <div className="mono text-xs text-ink-100 mb-2">
              threshold = {result.threshold_info.threshold.toFixed(3)}
              {" "}(binding: {result.threshold_info.binding_bound}; C={result.threshold_info.C},
              {" "}m={result.threshold_info.m}, sigma={result.threshold_info.sigma}, q={result.threshold_info.q})
            </div>
            <div className="mono text-[11px] text-ink-500 mb-2">
              sampling cap {result.threshold_info.sampling_cap.toFixed(3)} · decode cap {result.threshold_info.decode_cap.toFixed(3)}
              {" · "}<span className="text-ink-600">literal-textbook comparison (C=1, decode noise=sigma): threshold would be {result.threshold_info.threshold_C1_sigma_naive.toFixed(3)}</span>
            </div>
            <p className="text-xs text-ink-500 leading-relaxed">{result.threshold_info.note}</p>
          </Card>

          {isNaive ? (
            <Card title="Legitimate chain health" subtitle="naive_uniform: the legit basis vs threshold — the attacker's candidate isn't a meaningful comparison once correctness has already collapsed">
              <ResponsiveContainer width="100%" height={260}>
                <LineChart data={chartDataNaive}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#242c38" />
                  <XAxis dataKey="name" tick={{ fill: "#94a1b3", fontSize: 11 }} />
                  <YAxis scale="log" domain={["auto", "auto"]} tick={{ fill: "#94a1b3", fontSize: 11 }} allowDataOverflow />
                  <Tooltip contentStyle={{ background: "#141924", border: "1px solid #242c38", fontSize: 12 }} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  <ReferenceLine y={result.threshold_info.sampling_cap} stroke="#6b7788" strokeDasharray="2 3"
                    label={{ value: `sampling cap ${result.threshold_info.sampling_cap.toFixed(2)}`, position: "insideBottomRight", fill: "#6b7788", fontSize: 9 }} />
                  <ReferenceLine y={result.threshold_info.decode_cap} stroke="#6b7788" strokeDasharray="2 3"
                    label={{ value: `decode cap ${result.threshold_info.decode_cap.toFixed(2)}`, position: "insideBottomRight", fill: "#6b7788", fontSize: 9 }} />
                  <ReferenceLine y={result.threshold_info.threshold} stroke="#f2685c" strokeDasharray="4 3"
                    label={{ value: `usability ≈ ${result.threshold_info.threshold.toFixed(2)} (${result.threshold_info.binding_bound} bound)`, position: "insideTopRight", fill: "#f2685c", fontSize: 10 }} />
                  <Line type="monotone" dataKey="legit" name="legit ‖GS(sk_ri)‖" stroke="#3ecf8e" strokeWidth={2} dot />
                  {collapseRow && (
                    <ReferenceDot x={collapseRow.name} y={collapseRow.legit} r={6} fill="#f2685c" stroke="none"
                      label={{ value: `correctness lost (period ${result.correctness_lost_at})`, position: "top", fill: "#f2685c", fontSize: 10 }} />
                  )}
                </LineChart>
              </ResponsiveContainer>
            </Card>
          ) : (
            <Card title="Norm comparison" subtitle="legit basis vs attacker's candidate — trivial (balanced) and after LLL re-reduction — vs usability threshold (log scale)">
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={chartDataLowNorm}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#242c38" />
                  <XAxis dataKey="name" tick={{ fill: "#94a1b3", fontSize: 11 }} />
                  <YAxis scale="log" domain={["auto", "auto"]} tick={{ fill: "#94a1b3", fontSize: 11 }} allowDataOverflow />
                  <Tooltip contentStyle={{ background: "#141924", border: "1px solid #242c38", fontSize: 12 }} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  <ReferenceLine y={result.threshold_info.sampling_cap} stroke="#6b7788" strokeDasharray="2 3"
                    label={{ value: `sampling cap ${result.threshold_info.sampling_cap.toFixed(2)}`, position: "insideBottomRight", fill: "#6b7788", fontSize: 9 }} />
                  <ReferenceLine y={result.threshold_info.decode_cap} stroke="#6b7788" strokeDasharray="2 3"
                    label={{ value: `decode cap ${result.threshold_info.decode_cap.toFixed(2)}`, position: "insideBottomRight", fill: "#6b7788", fontSize: 9 }} />
                  <ReferenceLine y={result.threshold_info.threshold} stroke="#f2685c" strokeDasharray="4 3"
                    label={{ value: `usability ≈ ${result.threshold_info.threshold.toFixed(2)} (${result.threshold_info.binding_bound} bound)`, position: "insideTopRight", fill: "#f2685c", fontSize: 10 }} />
                  <Bar dataKey="legit" name="legit ‖GS(sk_ri)‖" fill="#3ecf8e" />
                  <Bar dataKey="trivial" name="candidate, trivial (balanced)" fill="#94a1b3" />
                  <Bar dataKey="afterLll" name="candidate, after LLL reduction" fill="#f2b544" />
                </BarChart>
              </ResponsiveContainer>
            </Card>
          )}

          <Card title="Per-period verdict table">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-ink-500 text-xs uppercase">
                    <th className="pb-2 pr-4">period</th>
                    <th className="pb-2 pr-4">periods back</th>
                    <th className="pb-2 pr-4">legit ‖GS‖</th>
                    <th className="pb-2 pr-4">legit usable?</th>
                    <th className="pb-2 pr-4">candidate ‖GS‖ (trivial)</th>
                    <th className="pb-2 pr-4">candidate ‖GS‖ (after LLL)</th>
                    <th className="pb-2">verdict</th>
                  </tr>
                </thead>
                <tbody className="mono">
                  {result.rows.map((r) => (
                    <tr key={r.period} className={`border-t border-ink-800 ${verdictRowClass(r.verdict)}`}>
                      <td className="py-1.5 pr-4">{r.period}</td>
                      <td className="py-1.5 pr-4">{r.periods_back}</td>
                      <td className="py-1.5 pr-4">{r.legit_gram_schmidt_norm.toFixed(2)}</td>
                      <td className={`py-1.5 pr-4 ${r.legit_usable ? "text-signal-green" : "text-signal-red"}`}>
                        {String(r.legit_usable)}
                      </td>
                      <td className="py-1.5 pr-4">{r.candidate_trivial_gram_schmidt_norm.toFixed(2)}</td>
                      <td className="py-1.5 pr-4">{r.candidate_after_lll_gram_schmidt_norm.toFixed(2)}</td>
                      <td className="py-1.5"><Badge tone={verdictTone(r.verdict)}>{r.verdict}</Badge></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          {result.scaling_caveat && (
            <div className="text-xs text-amber-400 bg-amber-500/10 border border-amber-600/30 rounded px-3 py-2.5 leading-relaxed">
              ⚠ {result.scaling_caveat}
            </div>
          )}

          <Card title="Finding 2 — the H1 dilemma (both natural instantiations lose)">
            <p className="text-sm text-ink-300 leading-relaxed">{result.conclusion}</p>
            <p className="text-xs text-ink-500 mt-2">
              The paper specifies no H1 construction; this dilemma is a consequence of that
              omission, and the security proof's silence on H1's distribution is load-bearing.
            </p>
          </Card>
        </>
      )}

      <Card title="Dimension-scaling sweep" subtitle="Does the low_norm LLL break survive as n grows, or is it a low-dimension artifact?">
        <p className="text-sm text-ink-300 leading-relaxed mb-3">
          Runs the same audited reduction at n ∈ {"{"}4, 6, 8{"}"} (m re-derived per n, low_norm H1
          only) and counts how many earlier periods break after LLL at each n. A fixed sigma
          confounds this: the legit basis's own norm grows with m while a fixed threshold
          doesn't, so the legit chain can lose usability before any attack is even considered.
          Fixed with sigma scaled to the measured root-basis quality per dimension, plus a
          stronger reduction (BKZ via fpylll if installed, else LLL at delta=0.99) applied to the
          legitimate chain's own basis only — never to the attacker's recovered candidate, which
          still only gets plain LLL. This is slower — our from-scratch NewBasisDel measured ~3s
          per period at n=4 (m=72), ~12s at n=6 (m=108), ~38s at n=8 (m=144) — so it runs behind
          this separate button, bounded by an explicit time budget rather than hanging.
        </p>
        <div className="flex items-end gap-4 flex-wrap">
          <label className="block">
            <div className="text-xs text-ink-400 mb-1">Periods (J)</div>
            <input type="number" min={2} max={6} value={sweepJ} onChange={(e) => setSweepJ(Number(e.target.value))}
              className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-20" />
          </label>
          <SecondaryButton onClick={runSweep} disabled={!initialized || sweepLoading}>
            {sweepLoading ? "Running sweep (can take a few minutes)…" : "Run scaling sweep"}
          </SecondaryButton>
        </div>
        <ErrorBanner message={sweepError} />

        {sweepResult && (
          <div className="mt-4 space-y-4">
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={sweepChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#242c38" />
                <XAxis dataKey="name" tick={{ fill: "#94a1b3", fontSize: 11 }} />
                <YAxis tick={{ fill: "#94a1b3", fontSize: 11 }} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#141924", border: "1px solid #242c38", fontSize: 12 }} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                <Bar dataKey="numBroken" name="periods broken after LLL" fill="#f2b544" />
              </BarChart>
            </ResponsiveContainer>

            <div className="overflow-x-auto">
              <table className="w-full text-sm mono">
                <thead>
                  <tr className="text-left text-ink-500 text-xs uppercase">
                    <th className="pb-2 pr-4">n</th>
                    <th className="pb-2 pr-4">m</th>
                    <th className="pb-2 pr-4">sigma</th>
                    <th className="pb-2 pr-4">legit ‖GS‖ (root)</th>
                    <th className="pb-2 pr-4">reduction</th>
                    <th className="pb-2 pr-4">threshold</th>
                    <th className="pb-2 pr-4">correctness lost at</th>
                    <th className="pb-2 pr-4">#broken</th>
                    <th className="pb-2 pr-4">min after-LLL ‖GS‖</th>
                    <th className="pb-2">runtime</th>
                  </tr>
                </thead>
                <tbody>
                  {sweepResult.rows.map((r) => (
                    <tr key={r.n} className="border-t border-ink-800">
                      <td className="py-1.5 pr-4">{r.n}</td>
                      {r.error ? (
                        <td className="py-1.5 text-signal-red" colSpan={9}>invalid params: {r.error}</td>
                      ) : r.skipped ? (
                        <td className="py-1.5 text-ink-500" colSpan={9}>skipped — {r.note}</td>
                      ) : (
                        <>
                          <td className="py-1.5 pr-4">{r.m}</td>
                          <td className="py-1.5 pr-4">{r.sigma.toFixed(2)}</td>
                          <td className={`py-1.5 pr-4 ${r.root_legit_gs <= r.threshold ? "text-signal-green" : "text-signal-red"}`}>
                            {r.root_legit_gs.toFixed(2)}
                          </td>
                          <td className="py-1.5 pr-4 text-ink-500 text-[11px]">{r.legit_reduction_method}</td>
                          <td className="py-1.5 pr-4">{r.threshold.toFixed(2)}</td>
                          <td className="py-1.5 pr-4">{r.correctness_lost_at ?? "—"}</td>
                          <td className="py-1.5 pr-4">{r.num_broken}</td>
                          <td className="py-1.5 pr-4">{r.min_after_lll != null ? r.min_after_lll.toFixed(2) : "—"}</td>
                          <td className="py-1.5">{r.runtime_s.toFixed(1)}s</td>
                        </>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="flex items-center gap-2">
              <Badge tone={sweepResult.confound_resolved ? "green" : "amber"}>
                {sweepResult.confound_resolved ? "confound resolved" : "confound NOT resolved"}
              </Badge>
              <span className="text-xs text-ink-500">{sweepResult.resolution_summary}</span>
            </div>

            <div className="flex items-start gap-3">
              <Badge tone={sweepResult.trend === "never_broken" || sweepResult.trend === "shrinking" ? "green" : sweepResult.trend === "flat_or_growing" ? "amber" : "neutral"}>
                {sweepResult.trend}
              </Badge>
              <p className="text-sm text-ink-300">{sweepResult.trend_text}</p>
            </div>

            {sweepResult.confound_resolved && sweepResult.rows.some((r) => !r.error && !r.skipped && r.num_broken === 0) && (
              <p className="text-xs text-ink-500 leading-relaxed border-t border-ink-800 pt-3">
                Note: this sweep may show FEWER breaks than the main experiment above at the same
                n. That's not a contradiction — the sweep additionally re-reduces the legitimate
                chain's own stored basis (root and every delegated period) with the strongest
                reduction available, since an honest key holder is entitled to the best basis they
                can compute; the main experiment does not. The difference itself is a finding:
                periodic strong reduction of one's own trapdoor is a real, honest mitigation for
                the practical break, though it does not remove the underlying structural fact that
                R has a computable (if large) public inverse.
              </p>
            )}

            {sweepResult.confound_note && (
              <div className="text-xs text-amber-400 bg-amber-500/10 border border-amber-600/30 rounded px-3 py-2.5 leading-relaxed">
                ⚠ {sweepResult.confound_note}
              </div>
            )}
            {sweepResult.scaling_caveat && (
              <div className="text-xs text-amber-400 bg-amber-500/10 border border-amber-600/30 rounded px-3 py-2.5 leading-relaxed">
                ⚠ {sweepResult.scaling_caveat}
              </div>
            )}
          </div>
        )}
        {!initialized && <div className="text-xs text-ink-500 mt-2">Initialize params in the left rail first.</div>}
      </Card>

      <Card title="Fairness comparison: give the attacker BKZ too" subtitle="Closes the &quot;defender got BKZ, attacker only got LLL&quot; asymmetry — the last step to make a no-break result unimpeachable">
        <p className="text-sm text-ink-300 leading-relaxed mb-3">
          Runs three configs per n: <span className="mono text-ink-200">LLL_vs_LLL</span> (the
          original apples-to-apples), <span className="mono text-ink-200">BKZ_defender_only</span>
          {" "}(the scaling-sweep state above — legit chain strengthened, attacker still only LLL),
          and <span className="mono text-ink-200">BKZ_vs_BKZ</span> — the SAME reducer
          (strong_reduce) passed to both the legitimate chain and the attacker's recovery. The
          BKZ_vs_BKZ row is the authoritative fairness verdict; the other two are shown for
          context only. Two full chain builds per n (LLL_vs_LLL needs its own; BKZ_defender_only
          and BKZ_vs_BKZ share one), so this is slower still than the scaling sweep above.
        </p>
        <div className="flex items-end gap-4 flex-wrap">
          <label className="block">
            <div className="text-xs text-ink-400 mb-1">Periods (J)</div>
            <input type="number" min={2} max={4} value={fairnessJ} onChange={(e) => setFairnessJ(Number(e.target.value))}
              className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-20" />
          </label>
          <SecondaryButton onClick={runFairness} disabled={!initialized || fairnessLoading}>
            {fairnessLoading ? "Running fairness comparison (can take several minutes)…" : "Run fairness comparison"}
          </SecondaryButton>
        </div>
        <ErrorBanner message={fairnessError} />

        {fairnessResult && (
          <div className="mt-4 space-y-4">
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={fairnessChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#242c38" />
                <XAxis dataKey="name" tick={{ fill: "#94a1b3", fontSize: 11 }} />
                <YAxis tick={{ fill: "#94a1b3", fontSize: 11 }} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#141924", border: "1px solid #242c38", fontSize: 12 }} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                <Bar dataKey="LLL_vs_LLL" name="LLL vs LLL" fill="#94a1b3" />
                <Bar dataKey="BKZ_defender_only" name="BKZ defender only" fill="#f2b544" />
                <Bar dataKey="BKZ_vs_BKZ" name="BKZ vs BKZ (fair)" fill="#3ecf8e" />
              </BarChart>
            </ResponsiveContainer>

            <div className="overflow-x-auto">
              <table className="w-full text-sm mono">
                <thead>
                  <tr className="text-left text-ink-500 text-xs uppercase">
                    <th className="pb-2 pr-4">n</th>
                    <th className="pb-2 pr-4">config</th>
                    <th className="pb-2 pr-4">legit reducer</th>
                    <th className="pb-2 pr-4">attacker reducer</th>
                    <th className="pb-2 pr-4">threshold</th>
                    <th className="pb-2 pr-4">correctness lost at</th>
                    <th className="pb-2 pr-4">#broken</th>
                    <th className="pb-2 pr-4">min after-reduction ‖GS‖</th>
                    <th className="pb-2">runtime</th>
                  </tr>
                </thead>
                <tbody>
                  {fairnessResult.rows.map((r, idx) => (
                    <tr key={idx} className={`border-t border-ink-800 ${r.config === "BKZ_vs_BKZ" ? "bg-signal-blue/5" : ""}`}>
                      <td className="py-1.5 pr-4">{r.n}</td>
                      {r.error ? (
                        <td className="py-1.5 text-signal-red" colSpan={8}>invalid params: {r.error}</td>
                      ) : r.skipped ? (
                        <td className="py-1.5 text-ink-500" colSpan={8}>skipped — {r.note}</td>
                      ) : (
                        <>
                          <td className="py-1.5 pr-4">{r.config}</td>
                          <td className="py-1.5 pr-4 text-[11px] text-ink-500">{r.legit_reducer_method}</td>
                          <td className="py-1.5 pr-4 text-[11px] text-ink-500">{r.attacker_reducer_method}</td>
                          <td className="py-1.5 pr-4">{r.threshold.toFixed(2)}</td>
                          <td className="py-1.5 pr-4">{r.correctness_lost_at ?? "—"}</td>
                          <td className="py-1.5 pr-4">{r.num_broken}</td>
                          <td className="py-1.5 pr-4">{r.min_after_reduction != null ? r.min_after_reduction.toFixed(2) : "—"}</td>
                          <td className="py-1.5">{r.runtime_s.toFixed(1)}s</td>
                        </>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="flex items-start gap-3">
              <Badge tone={fairnessResult.verdict === "resists_symmetric_bkz" ? "green" : fairnessResult.verdict === "broken_under_symmetric_bkz" ? "red" : "neutral"}>
                {fairnessResult.verdict}
              </Badge>
              <p className="text-sm text-ink-300">{fairnessResult.verdict_text}</p>
            </div>

            {fairnessResult.caveats.map((c, i) => (
              <div key={i} className="text-xs text-amber-400 bg-amber-500/10 border border-amber-600/30 rounded px-3 py-2.5 leading-relaxed">
                ⚠ {c}
              </div>
            ))}
          </div>
        )}
        {!initialized && <div className="text-xs text-ink-500 mt-2">Initialize params in the left rail first.</div>}
      </Card>
    </div>
  );
}
