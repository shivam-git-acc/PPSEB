import { useState } from "react";
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Legend, CartesianGrid, ReferenceLine,
} from "recharts";
import { api } from "../api";
import { Card, Badge, PrimaryButton, ErrorBanner } from "../components/Section";

function verdictTone(v) {
  if (v === "BROKEN (trivial)") return "red";
  if (v === "BROKEN (after LLL reduction)") return "amber";
  if (v.startsWith("survives")) return "green";
  return "neutral";
}

export default function ForwardSecTab({ onTrace, initialized }) {
  const [J, setJ] = useState(4);
  const [variant, setVariant] = useState("low_norm");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

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

  const chartData = result?.rows.map((r) => ({
    name: `period ${r.period}`,
    legit: r.legit_gram_schmidt_norm,
    trivial: r.candidate_trivial_gram_schmidt_norm,
    afterLll: r.candidate_after_lll_gram_schmidt_norm,
  })) ?? [];

  return (
    <div className="space-y-5 max-w-4xl">
      <Card title="Forward-Security Norm Experiment">
        <p className="text-sm text-ink-300 leading-relaxed">
          Stealing the CURRENT trapdoor sk_rJ must not reveal any EARLIER sk_ri. Consecutive
          periods are related by a public low-norm R, so a candidate for any earlier basis is
          computable from public data alone plus the stolen sk_rJ — always. Every candidate is
          measured twice: once as a plain balanced representative (entries mapped into
          (-q/2, q/2], since only residues mod q are meaningful), then again after LLL-reducing
          it — the same finishing step NewBasisDel itself applies. The verdict below is
          <b> derived from those measured norms</b>, never assumed.
        </p>
      </Card>

      <Card title="Run experiment">
        <div className="flex items-end gap-4 flex-wrap">
          <label className="block">
            <div className="text-xs text-ink-400 mb-1">Periods (J)</div>
            <input type="number" min={1} max={8} value={J} onChange={(e) => setJ(Number(e.target.value))}
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
          <Card title="Norm comparison" subtitle="legit basis vs attacker's candidate — trivial (balanced) and after LLL re-reduction — vs usability threshold (log scale)">
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#242c38" />
                <XAxis dataKey="name" tick={{ fill: "#94a1b3", fontSize: 11 }} />
                <YAxis scale="log" domain={["auto", "auto"]} tick={{ fill: "#94a1b3", fontSize: 11 }} allowDataOverflow />
                <Tooltip contentStyle={{ background: "#141924", border: "1px solid #242c38", fontSize: 12 }} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                <ReferenceLine y={result.rows[0]?.usability_threshold} stroke="#f2685c" strokeDasharray="4 3"
                  label={{ value: "usability threshold (q/4)", position: "insideTopRight", fill: "#f2685c", fontSize: 10 }} />
                <Bar dataKey="legit" name="legit ‖GS(sk_ri)‖" fill="#3ecf8e" />
                <Bar dataKey="trivial" name="candidate, trivial (balanced)" fill="#94a1b3" />
                <Bar dataKey="afterLll" name="candidate, after LLL reduction" fill="#f2b544" />
              </BarChart>
            </ResponsiveContainer>
          </Card>

          <Card title="Per-period verdict table">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-ink-500 text-xs uppercase">
                    <th className="pb-2 pr-4">period</th>
                    <th className="pb-2 pr-4">periods back</th>
                    <th className="pb-2 pr-4">legit ‖GS‖</th>
                    <th className="pb-2 pr-4">candidate ‖GS‖ (trivial)</th>
                    <th className="pb-2 pr-4">candidate ‖GS‖ (after LLL)</th>
                    <th className="pb-2 pr-4">in lattice?</th>
                    <th className="pb-2">verdict</th>
                  </tr>
                </thead>
                <tbody className="mono">
                  {result.rows.map((r) => (
                    <tr key={r.period} className="border-t border-ink-800">
                      <td className="py-1.5 pr-4">{r.period}</td>
                      <td className="py-1.5 pr-4">{r.periods_back}</td>
                      <td className="py-1.5 pr-4">{r.legit_gram_schmidt_norm.toFixed(2)}</td>
                      <td className="py-1.5 pr-4">{r.candidate_trivial_gram_schmidt_norm.toFixed(2)}</td>
                      <td className="py-1.5 pr-4">{r.candidate_after_lll_gram_schmidt_norm.toFixed(2)}</td>
                      <td className="py-1.5 pr-4">{String(r.membership_ok)}</td>
                      <td className="py-1.5"><Badge tone={verdictTone(r.verdict)}>{r.verdict}</Badge></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          <Card title="Overall verdict">
            <div className="flex items-start gap-3">
              <Badge tone={result.any_period_broken ? "red" : "green"}>
                {result.any_period_broken ? "BROKEN" : "SURVIVES THIS ATTACK"}
              </Badge>
              <p className="text-sm text-ink-300">{result.overall_verdict}</p>
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
