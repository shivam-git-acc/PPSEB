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

export default function ForwardSecTab({ onTrace, initialized, params }) {
  const currentN = params?.n ?? 4;

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

  const [e2eJ, setE2eJ] = useState(3);
  const [e2eLoading, setE2eLoading] = useState(false);
  const [e2eError, setE2eError] = useState(null);
  const [e2eResult, setE2eResult] = useState(null);
  const [e2eSelectedPeriod, setE2eSelectedPeriod] = useState(null);

  // A single result at some J and a comparison table at a DIFFERENT J
  // shown together was PATCH 06's on-screen contradiction. Both runs
  // share this one J input; changing it (or n) invalidates whichever
  // stale result(s) were computed at the old value so the two panels can
  // never disagree about which experiment they're showing.
  const setE2eJSafe = (val) => {
    setE2eJ(val);
    setE2eResult(null);
    setE2eMultiResult(null);
  };

  const [e2eNList, setE2eNList] = useState(`${currentN},${currentN + 4}`);

  const [e2eMultiLoading, setE2eMultiLoading] = useState(false);
  const [e2eMultiError, setE2eMultiError] = useState(null);
  const [e2eMultiResult, setE2eMultiResult] = useState(null);

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

  const runE2E = async () => {
    setE2eLoading(true);
    setE2eError(null);
    setE2eSelectedPeriod(null);
    try {
      const res = await api.attackForwardE2E({ J: e2eJ, n: currentN, seed: Math.floor(Math.random() * 1e6), reducer_name: "bkz" });
      setE2eResult(res.result);
      onTrace(res.trace);
    } catch (e) {
      setE2eError(String(e.message || e));
    } finally {
      setE2eLoading(false);
    }
  };

  const e2eNValues = e2eNList
    .split(",")
    .map((s) => parseInt(s.trim(), 10))
    .filter((v) => Number.isFinite(v) && v > 0);

  const runE2EMulti = async () => {
    if (e2eNValues.length === 0) {
      setE2eMultiError("Enter at least one valid n (comma-separated).");
      return;
    }
    setE2eMultiLoading(true);
    setE2eMultiError(null);
    try {
      const res = await api.attackForwardE2EMulti({ J: e2eJ, n_values: e2eNValues, seed: Math.floor(Math.random() * 1e6), reducer_name: "bkz" });
      setE2eMultiResult(res.result);
      onTrace(res.trace);
    } catch (e) {
      setE2eMultiError(String(e.message || e));
    } finally {
      setE2eMultiLoading(false);
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

      <Card title="End-to-end attack" subtitle="Upgrades the norm proxy above to a FUNCTIONAL demonstration: real search, real decrypt, on a frozen database">
        <p className="text-sm text-ink-300 leading-relaxed mb-3">
          Builds the honest doctor's real searchable database at every period and FREEZES it,
          evolves the key forward to period J (where it gets stolen), then lets the attacker —
          holding only the stolen key and public data — reconstruct an earlier basis and run the
          <b> exact same</b> search and decrypt code the doctor used, against the untouched frozen
          ciphertexts. The attacker never regenerates anything — success means the SAME sequence
          number N0 the doctor found (Level 2), and optionally the SAME plaintext (Level 3). This
          can show the norm proxy above was wrong in either direction.
        </p>
        <div className="flex items-end gap-4 flex-wrap">
          <label className="block">
            <div className="text-xs text-ink-400 mb-1">Periods (J)</div>
            <input type="number" min={2} max={4} value={e2eJ} onChange={(e) => setE2eJSafe(Number(e.target.value))}
              className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-20" />
          </label>
          <div className="text-xs text-ink-500">
            n = <span className="mono text-ink-300">{currentN}</span> (left-rail parameter)
          </div>
          <PrimaryButton onClick={runE2E} disabled={!initialized || e2eLoading}>
            {e2eLoading ? "Running (builds + attacks every period)…" : `Run end-to-end attack (n=${currentN}, J=${e2eJ})`}
          </PrimaryButton>
          <label className="block">
            <div className="text-xs text-ink-400 mb-1">Compare n values (comma-separated)</div>
            <input type="text" value={e2eNList} onChange={(e) => { setE2eNList(e.target.value); setE2eMultiResult(null); }}
              className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-28" />
          </label>
          <SecondaryButton onClick={runE2EMulti} disabled={!initialized || e2eMultiLoading}>
            {e2eMultiLoading ? `Comparing n=${e2eNList} at J=${e2eJ} (can take a few minutes)…` : `Compare dimensions (n=${e2eNList}, J=${e2eJ})`}
          </SecondaryButton>
        </div>
        <ErrorBanner message={e2eError} />

        {e2eResult && (
          <div className="mt-4 space-y-4">
            <div className="text-xs text-ink-500">
              Run at <span className="mono text-ink-300">n={e2eResult.n}, J={e2eResult.J}</span>, reducer <span className="mono text-ink-300">{e2eResult.reducer_name}</span>
            </div>

            <div className={`text-xs rounded px-3 py-2 border ${e2eResult.control_ok ? "border-ink-700 text-ink-400" : "border-signal-red bg-signal-red/10 text-signal-red"}`}>
              Negative control (garbage basis, no secret): {e2eResult.control_ok
                ? "failed Level 2 as expected — this run's verdict is trustworthy."
                : `UNEXPECTEDLY PASSED at period(s) ${JSON.stringify(e2eResult.control_passed_periods)} — this run is UNTRUSTWORTHY, do not trust the verdict below.`}
            </div>

            <div className="text-xs text-ink-500 leading-relaxed border-l-2 border-ink-700 pl-3">
              {e2eResult.level3_reachable_in_principle
                ? "Paper audit: Decrypt(CM0, j, SK_r||j) takes only the period secret key — Level 3 is reachable in principle if the recovered basis is short enough."
                : "Paper audit: Level 3 is not reachable by this attack (a separate secret Decrypt needs is untouched by the forward-security break)."}
            </div>

            {/* timeline */}
            <div className="flex items-center overflow-x-auto pb-2">
              {e2eResult.rows.map((r, idx) => {
                const both = r.level2_search_break && r.level3_plaintext_break;
                const broke = r.level2_search_break;
                const selected = e2eSelectedPeriod === r.period;
                const toneClass = both
                  ? "border-signal-blue/70 bg-signal-blue/10"
                  : broke
                  ? "border-signal-green/70 bg-signal-green/10"
                  : "border-ink-700 bg-ink-900";
                return (
                  <div key={r.period} className="flex items-center shrink-0">
                    <button
                      onClick={() => {
                        setE2eSelectedPeriod(r.period);
                        // eslint-disable-next-line no-console
                        console.log(`[end-to-end] period ${r.period} full row:`, r);
                      }}
                      className={`flex flex-col items-center justify-center w-24 h-16 rounded border-2 transition-colors ${
                        selected ? "border-signal-blue" : toneClass
                      }`}
                    >
                      <span className="text-xs text-ink-300">period {r.period}</span>
                      <span className="text-[10px] text-ink-500">frozen DB</span>
                      <span className={`text-[10px] font-medium ${both ? "text-signal-blue" : broke ? "text-signal-green" : "text-ink-500"}`}>
                        {both ? "L2+L3 broken" : broke ? "L2 broken" : "survives"}
                      </span>
                    </button>
                    {idx < e2eResult.rows.length - 1 && <div className="w-6 h-px bg-ink-700 mx-1" />}
                  </div>
                );
              })}
              <div className="w-6 h-px bg-signal-red/60 mx-1" />
              <div className="flex flex-col items-center justify-center w-32 h-16 rounded border-2 border-signal-red/60 bg-signal-red/10 shrink-0">
                <span className="text-xs text-signal-red">period {e2eResult.J}</span>
                <span className="text-[10px] text-signal-red">attacker steals SK here</span>
              </div>
            </div>

            {e2eSelectedPeriod != null && (() => {
              const row = e2eResult.rows.find((r) => r.period === e2eSelectedPeriod);
              if (!row) return null;
              return (
                <div className="trace-event-enter border border-ink-800 rounded-lg p-4 space-y-3">
                  <div className="text-sm text-ink-200">
                    Honest doctor at period {row.period} found N0=<span className="mono">{row.N0_legit}</span> using
                    the real SK_r|{row.period}. Attacker, with only SK_r|{e2eResult.J} from {row.periods_back} period(s)
                    later, reached back and {row.level2_search_break ? <b className="text-signal-green">recovered the SAME N0</b> : <b className="text-ink-400">could not reproduce it</b>}.
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                    <div className="border border-ink-800 rounded p-2">
                      <div className="text-ink-500 uppercase text-[10px] mb-1">L1 · period-basis norm</div>
                      <Badge tone={row.level1_norm_ok ? "green" : "amber"}>{row.level1_norm_ok ? "short enough" : "exceeds threshold"}</Badge>
                      <div className="mono text-ink-400 mt-1">{row.gs_norm.toFixed(2)} vs {row.threshold.toFixed(2)}</div>
                    </div>
                    <div className="border border-ink-800 rounded p-2">
                      <div className="text-ink-500 uppercase text-[10px] mb-1">L2 · search</div>
                      <Badge tone={row.level2_search_break ? "green" : "neutral"}>{row.level2_search_break ? "SEARCH RECOVERED" : "failed / no match"}</Badge>
                      <div className="mono text-ink-400 mt-1">N0*={String(row.N0_star)} vs N0={String(row.N0_legit)}</div>
                    </div>
                    <div className="border border-ink-800 rounded p-2">
                      <div className="text-ink-500 uppercase text-[10px] mb-1">L3 · decrypt</div>
                      <Badge tone={row.level3_plaintext_break ? "green" : "neutral"}>
                        {row.level3_plaintext_break ? "PLAINTEXT RECOVERED" : row.level3_reachable === false ? "not reachable" : "not reached"}
                      </Badge>
                    </div>
                    <div className="border border-ink-800 rounded p-2">
                      <div className="text-ink-500 uppercase text-[10px] mb-1">reducer</div>
                      <div className="mono text-ink-300">{row.reducer_method}</div>
                    </div>
                  </div>
                  <div className="border-t border-ink-800 pt-3">
                    <div className="text-ink-500 uppercase text-[10px] mb-2">
                      Word-basis cross-check (what SamplePre actually consumes, one delegation past the period basis)
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                      <div className="border border-ink-800 rounded p-2">
                        <div className="text-ink-500 uppercase text-[10px] mb-1">period_gs (attacker)</div>
                        <div className="mono text-ink-300">{row.gs_norm.toFixed(2)}</div>
                        <div className="text-ink-600 text-[10px]">vs threshold {row.threshold.toFixed(2)}</div>
                      </div>
                      <div className="border border-ink-800 rounded p-2">
                        <div className="text-ink-500 uppercase text-[10px] mb-1">honest word_gs (reference)</div>
                        <div className="mono text-ink-300">{row.honest_word_gs?.toFixed(2)}</div>
                        <div className="text-ink-600 text-[10px]">known usable: the honest search works</div>
                      </div>
                      <div className="border border-ink-800 rounded p-2">
                        <div className="text-ink-500 uppercase text-[10px] mb-1">attacker word_gs</div>
                        <div className="mono text-ink-300">{row.word_gs != null ? row.word_gs.toFixed(2) : "—"}</div>
                        <div className="text-ink-600 text-[10px]">
                          ratio {row.word_ratio != null ? row.word_ratio.toFixed(2) : "—"} vs factor {row.word_factor} → {row.word_pred_usable ? "comparable" : "not comparable"}
                        </div>
                      </div>
                      <div className="border border-ink-800 rounded p-2">
                        <div className="text-ink-500 uppercase text-[10px] mb-1">word_gs_error</div>
                        <div className="mono text-ink-400 text-[10px] break-words">{row.word_gs_error ?? "none"}</div>
                      </div>
                    </div>
                    <div className="mt-2 text-xs">
                      <Badge tone={row.l2_matches_wordpred === false ? "amber" : row.l2_matches_wordpred === true ? "green" : "neutral"}>
                        {row.l2_matches_wordpred === false ? "DISAGREE — inspect" : row.l2_matches_wordpred === true ? "agree" : "n/a (off-lattice)"}
                      </Badge>
                      <span className="text-ink-400 ml-2">
                        {row.l2_matches_wordpred === false && row.word_pred_usable === false && row.level2_search_break
                          ? `Direction: Level 2 measured a BREAK, but the attacker's word basis is ${row.word_ratio != null ? row.word_ratio.toFixed(2) : "?"}x the honest doctor's (over the ${row.word_factor}x factor), so the break is not corroborated and is excluded from any verdict. Not a survival either — a same-N0 recovery was measured.`
                          : row.l2_matches_wordpred === false && row.word_pred_usable && !row.level2_search_break
                          ? "Direction: the attacker's word basis is comparable to the honest doctor's, but Level 2 measured NO break. The basis looks usable yet the search failed — a legitimate survival, recorded for inspection."
                          : row.l2_matches_wordpred === true
                          ? "The independent word-basis prediction and the measured Level 2 outcome agree."
                          : ""}
                      </span>
                    </div>
                  </div>

                  <div className="border-t border-ink-800 pt-3">
                    <div className="text-ink-500 uppercase text-[10px] mb-2">
                      Negative controls at THIS period (not the run-level aggregate)
                    </div>
                    <div className="grid grid-cols-2 gap-3 text-xs">
                      <div className={`border rounded p-2 ${row.control_garbage_passed ? "border-signal-red bg-signal-red/10" : "border-ink-800"}`}>
                        <div className="text-ink-500 uppercase text-[10px] mb-1">garbage basis (no secret)</div>
                        <Badge tone={row.control_garbage_passed ? "red" : "green"}>
                          {row.control_garbage_passed ? "UNEXPECTEDLY PASSED" : "failed, as required"}
                        </Badge>
                      </div>
                      <div className={`border rounded p-2 ${row.control_wrong_period_passed ? "border-signal-red bg-signal-red/10" : "border-ink-800"}`}>
                        <div className="text-ink-500 uppercase text-[10px] mb-1">wrong-period key (SK_r|{e2eResult.J})</div>
                        <Badge tone={row.control_wrong_period_passed ? "red" : "green"}>
                          {row.control_wrong_period_passed ? "UNEXPECTEDLY PASSED" : "failed, as required"}
                        </Badge>
                      </div>
                    </div>
                    {!row.control_ok_this_period && (
                      <p className="text-xs text-signal-red mt-2">
                        A negative control passed at THIS period — the Level 2 match here is vacuous, not a genuine break.
                      </p>
                    )}
                  </div>
                </div>
              );
            })()}

            <div className="flex items-start gap-3">
              <Badge tone={!e2eResult.control_ok ? "red" : e2eResult.any_l2_break ? "green" : "neutral"}>
                {!e2eResult.control_ok ? "UNTRUSTWORTHY" : e2eResult.any_l2_break ? "BROKEN (functional)" : "SURVIVES (functional)"}
              </Badge>
              <p className="text-sm text-ink-300">{e2eResult.conclusion}</p>
            </div>

            {e2eResult.caveats.map((c, i) => (
              <div key={i} className="text-xs text-amber-400 bg-amber-500/10 border border-amber-600/30 rounded px-3 py-2.5 leading-relaxed">
                ⚠ {c}
              </div>
            ))}
          </div>
        )}

        {e2eMultiError && <ErrorBanner message={e2eMultiError} />}
        {e2eMultiResult && (
          <Card title={`Dimension comparison — J=${e2eMultiResult.J}`} className="mt-4">
            <div className="overflow-x-auto">
              <table className="w-full text-sm mono">
                <thead>
                  <tr className="text-left text-ink-500 text-xs uppercase">
                    <th className="pb-2 pr-4">n</th>
                    <th className="pb-2 pr-4">J</th>
                    <th className="pb-2 pr-4">control</th>
                    <th className="pb-2 pr-4">any L2 break?</th>
                    <th className="pb-2">broken periods (L2 / L3)</th>
                  </tr>
                </thead>
                <tbody>
                  {e2eMultiResult.per_n.map((r) => (
                    <tr key={r.n} className="border-t border-ink-800">
                      <td className="py-1.5 pr-4">{r.n}</td>
                      {r.error ? (
                        <td className="py-1.5 text-signal-red" colSpan={4}>error: {r.error}</td>
                      ) : (
                        <>
                          <td className="py-1.5 pr-4">{r.J}</td>
                          <td className={`py-1.5 pr-4 ${r.control_ok ? "text-ink-500" : "text-signal-red font-semibold"}`}>
                            {r.control_ok ? "held" : "FAILED"}
                          </td>
                          <td className={`py-1.5 pr-4 ${!r.control_ok ? "text-signal-red" : r.any_l2_break ? "text-signal-green" : "text-ink-500"}`}>
                            {!r.control_ok ? "untrustworthy" : String(r.any_l2_break)}
                          </td>
                          <td className="py-1.5">{JSON.stringify(r.broken_periods_l2)} / {JSON.stringify(r.broken_periods_l3)}</td>
                        </>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="text-sm text-ink-300 mt-3">{e2eMultiResult.summary}</p>
          </Card>
        )}

        {!initialized && <div className="text-xs text-ink-500 mt-2">Initialize params in the left rail first.</div>}
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
