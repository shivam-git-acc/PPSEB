import { useEffect, useState } from "react";
import { api } from "../api";
import { Card, Badge, Value, Stat, ErrorBanner } from "../components/Section";

const fmt = (v, upper) => (v == null ? "—" : `${upper ? "≤" : ""}${v.toFixed(1)}`);

function Verdict({ row }) {
  if (row.guaranteed_bits == null) return <Badge tone="neutral">unquantified</Badge>;
  if (row.guaranteed_bits <= 0) return <Badge tone="red">vacuous</Badge>;
  if (row.negligible) return <Badge tone="red">negligible</Badge>;
  if (!row.meets_target) return <Badge tone="amber">below 128</Badge>;
  return <Badge tone="green">≥ 128</Badge>;
}

export default function ProofTab({ goTo }) {
  const [r, setR] = useState(null);
  const [error, setError] = useState(null);
  const [open, setOpen] = useState(null);

  useEffect(() => {
    api.proofAnalysis().then((res) => setR(res.result)).catch((e) => setError(String(e.message || e)));
  }, []);

  if (error) return <Card title="Proof Analysis"><ErrorBanner message={error} /></Card>;
  if (!r) return <Card title="Proof Analysis"><p className="text-2xs text-ink-500">Loading…</p></Card>;

  const red = r.reduction, cov = r.coverage;
  const paper = red.rows.find((x) => x.paper_params);

  return (
    <div className="space-y-4">
      <Card title="Proof Analysis"
        subtitle="Two attacks on the paper's Section 5 proof itself, rather than on the scheme.">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <Stat label="Guaranteed at paper params"
            value={paper?.guaranteed_bits == null ? "—" : `${paper.lwe_is_upper_bound ? "≤" : ""}${paper.guaranteed_bits.toFixed(1)}`}
            tone="break" hint="bits, from Theorem 1's own bound" />
          <Stat label="Reduction gives away" value={paper ? paper.loss_bits.toFixed(1) : "—"}
            hint="log₂(2m) bits" />
          <Stat label="Threats the model expresses" value={`${cov.covered}/${cov.total}`}
            tone="break" hint="the one it proves" />
          <Stat label="Rows with a measured attack" value={`${cov.measured_rows}/${cov.total}`}
            hint="run a tab to populate more" />
        </div>
      </Card>

      <Card title="A · Reduction loss — what Theorem 1 actually guarantees"
        subtitle="Adv_IND ≤ 2m · Adv_LWE, so the scheme's guarantee is the LWE hardness minus log₂(2m) bits.">
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead>
              <tr className="text-left text-2xs uppercase tracking-[0.08em] text-ink-500">
                <th className="pb-2 pr-4 font-medium">n</th><th className="pb-2 pr-4 font-medium">q</th>
                <th className="pb-2 pr-4 font-medium">m</th>
                <th className="pb-2 pr-4 font-medium">LWE bits (est)</th>
                <th className="pb-2 pr-4 font-medium">loss log₂(2m)</th>
                <th className="pb-2 pr-4 font-medium">guaranteed</th>
                <th className="pb-2 font-medium">verdict</th>
              </tr>
            </thead>
            <tbody>
              {red.rows.map((row) => (
                <tr key={`${row.n}-${row.q}`} className="border-t border-ink-800/70">
                  <td className="py-2 pr-4 mono text-ink-200">{row.n}{row.paper_params ? " *" : ""}</td>
                  <td className="py-2 pr-4 mono text-ink-300">{row.q}</td>
                  <td className="py-2 pr-4 mono text-ink-400">{row.m}</td>
                  <td className="py-2 pr-4 mono text-ink-300">{fmt(row.lwe_bits, row.lwe_is_upper_bound)}</td>
                  <td className="py-2 pr-4 mono text-ink-400">{row.loss_bits.toFixed(1)}</td>
                  <td className="py-2 pr-4">
                    {row.guaranteed_bits == null
                      ? <span className="text-ink-600">—</span>
                      : <Value tone={row.negligible || row.guaranteed_bits <= 0 ? "break" : "neutral"}>
                          {fmt(row.guaranteed_bits, row.lwe_is_upper_bound)}
                        </Value>}
                  </td>
                  <td className="py-2"><Verdict row={row} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="text-[11px] text-ink-500 mt-2">* the paper's demonstration parameters</div>

        <p className="text-[13px] text-ink-200 leading-relaxed max-w-4xl mt-4 pt-4 border-t border-ink-800">
          {red.statement}
        </p>
        <div className="mt-4 space-y-2 max-w-4xl">
          <p className="text-2xs text-signal-amber bg-signal-amber/10 ring-1 ring-inset ring-signal-amber/25
                        rounded-lg px-3 py-2 leading-relaxed">{red.honesty}</p>
          <p className="text-2xs text-ink-500 leading-relaxed">{red.first_order_note}</p>
          <p className="text-2xs text-ink-500 leading-relaxed">{red.estimator_caveat}</p>
        </div>
      </Card>

      <Card title="B · Coverage map — which threats the security game can even express"
        subtitle={`${cov.column_labels.attack}  ·  ${cov.column_labels.model}`}>
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead>
              <tr className="text-left text-2xs uppercase tracking-[0.08em] text-ink-500">
                <th className="pb-2 pr-4 font-medium">Threat</th>
                <th className="pb-2 pr-4 font-medium">Demonstrated here</th>
                <th className="pb-2 pr-4 font-medium">In the model?</th>
                <th className="pb-2 font-medium">Why not (proof text)</th>
              </tr>
            </thead>
            <tbody>
              {cov.rows.map((row) => (
                <tr key={row.threat} className="border-t border-ink-800/70 align-top cursor-pointer
                                                hover:bg-white/[0.03]"
                  onClick={() => setOpen(open === row.threat ? null : row.threat)}>
                  <td className="py-2.5 pr-4 text-ink-100 font-medium">{row.threat}</td>
                  <td className="py-2.5 pr-4">
                    {row.attack.status === "measured"
                      ? <Value tone="break" className="!text-[12px]">{row.attack.summary}</Value>
                      : row.attack.status === "missing"
                        ? <button onClick={(e) => { e.stopPropagation(); goTo?.(
                            { "Public-Key": "pkbreak", Ledger: "ledger", KGA: "kga",
                              "Forward Security": "forward" }[row.tab]); }}
                            className="text-2xs text-accent hover:text-accent-soft underline">
                            {row.attack.summary}
                          </button>
                        : <span className="text-2xs text-ink-500">{row.attack.summary}</span>}
                  </td>
                  <td className="py-2.5 pr-4">
                    <Badge tone={row.covered === "yes" ? "green" : row.covered === "partial" ? "amber" : "red"}>
                      {row.covered}
                    </Badge>
                  </td>
                  <td className="py-2.5 text-2xs text-ink-400 leading-relaxed max-w-md">
                    {open === row.threat ? row.model_evidence
                      : `${row.model_evidence.slice(0, 92)}${row.model_evidence.length > 92 ? "…" : ""}`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-2xs text-ink-500 mt-3 leading-relaxed max-w-4xl">{cov.reading_note}</p>
      </Card>

      <Card title="What the two halves add up to">
        <ol className="max-w-4xl space-y-2.5 list-decimal pl-5">
          {cov.meta_findings.map((m) => (
            <li key={m} className="text-[13px] text-ink-200 leading-relaxed">{m}</li>
          ))}
        </ol>
      </Card>
    </div>
  );
}
