import { Card, Badge } from "../components/Section";
import ArchDiagram from "./ArchDiagram";

const FINDINGS = [
  {
    id: "spec", tone: "blue", n: "01", verdict: "Certain",
    title: "KeyExt is not executable as printed",
    line: "Algorithm 2 has two circular dependencies — line 6 uses the key it produces, line 7 uses the basis it produces.",
    stat: "2 circular lines",
  },
  {
    id: "kga", tone: "red", n: "02", verdict: "Demonstrated",
    title: "Keyword guessing recovers the query",
    line: "Encrypt and Verify are both public, and a trapdoor is a transaction. A dictionary is enough.",
    stat: "public data only",
  },
  {
    id: "pkbreak", tone: "red", n: "03", verdict: "Measured",
    title: "The public key alone reads every record",
    line: "At the paper's own parameters a basis built from pk recovers all disease tags and plaintexts at LLL effort.",
    stat: "8/8 records",
  },
  {
    id: "forward", tone: "amber", n: "04", verdict: "Measured",
    title: "Forward security fails on its own terms",
    line: "A stolen period key reconstructs an earlier one indistinguishable in quality from the honest key.",
    stat: "ratio ≈ 1.0",
  },
];

export default function OverviewTab({ goTo }) {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <Card title="The scheme" className="lg:col-span-5">
          <p className="text-[13px] text-ink-300 leading-relaxed">
            PPSEB (Xu et al., 2022) is lattice-based searchable encryption for e-health records, with a
            time-evolving key for forward security and the search step on a blockchain.
          </p>
          <ul className="mt-4 space-y-2.5">
            {[
              ["Postquantum", "resistant to keyword-guessing attacks"],
              ["Forward secure", "a stolen key reveals nothing earlier"],
              ["Well defined", "a working key-evolution algorithm"],
            ].map(([k, v]) => (
              <li key={k} className="flex gap-3 items-baseline">
                <span className="text-[13px] font-medium text-ink-100 w-28 shrink-0">{k}</span>
                <span className="text-[13px] text-ink-400">{v}</span>
              </li>
            ))}
          </ul>
          <p className="text-2xs text-ink-500 mt-4 pt-3 border-t border-ink-800">
            This lab implements a corrected version of that core at tiny parameters and tests all three
            claims live. Nothing on any screen is mocked in the frontend.
          </p>
        </Card>

        <Card title="Architecture" subtitle="The doctor drives the chain; it is not downstream of it."
          className="lg:col-span-7">
          <div className="flex justify-center"><ArchDiagram /></div>
        </Card>
      </div>

      <Card title="What we found" subtitle="Each one runs live on its own tab." pad={false}>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 divide-y md:divide-y-0 md:divide-x divide-ink-800">
          {FINDINGS.map((f) => (
            <button key={f.id} onClick={() => goTo(f.id)}
              className="text-left p-5 hover:bg-white/[0.03] transition-colors group">
              <div className="flex items-center gap-2.5">
                <span className="mono text-2xs text-ink-600">{f.n}</span>
                <Badge tone={f.tone}>{f.verdict}</Badge>
              </div>
              <h3 className="text-[14px] font-semibold text-ink-100 mt-3 leading-snug">{f.title}</h3>
              <p className="text-2xs text-ink-400 mt-2 leading-relaxed">{f.line}</p>
              <div className="mt-4 flex items-center justify-between">
                <span className="mono text-[13px] text-ink-200">{f.stat}</span>
                <span className="text-2xs text-ink-600 group-hover:text-accent transition-colors">Open →</span>
              </div>
            </button>
          ))}
        </div>
      </Card>
    </div>
  );
}
