import { useState } from "react";
import { api } from "../api";
import { Card, Badge, PrimaryButton, ErrorBanner } from "../components/Section";

function Norms({ norms }) {
  const rows = [
    ["lattice's expected shortest vector (Gaussian heuristic)", norms.gaussian_heuristic],
    ["honest doctor's SECRET basis", norms.honest_basis_gs],
    ["basis recovered from the PUBLIC key", norms.recovered_basis_gs],
  ];
  return (
    <div className="text-xs">
      <div className="text-ink-500 uppercase text-[10px] mb-2">Basis quality (Gram-Schmidt norm — smaller is better)</div>
      {rows.map(([label, v]) => (
        <div key={label} className="flex items-center gap-2 mb-1">
          <div className="w-72 text-ink-400">{label}</div>
          <div className="mono text-ink-200 w-14 text-right">{v?.toFixed(2)}</div>
          <div className="flex-1 h-2 bg-ink-800 rounded overflow-hidden max-w-[220px]">
            <div className="h-full bg-signal-blue/70" style={{ width: `${Math.min(100, (v / 5) * 100)}%` }} />
          </div>
        </div>
      ))}
      <p className="text-ink-500 mt-2 leading-relaxed">
        The public basis is as short as the secret one — at these parameters the secret key confers no advantage.
      </p>
    </div>
  );
}

export default function PublicKeyBreakTab({ initialized }) {
  const [n, setN] = useState(4);
  const [q, setQ] = useState(257);
  const [records, setRecords] = useState(8);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [res, setRes] = useState(null);

  const run = async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await api.pkDemoRun({ n: Number(n), q: Number(q), records: Number(records),
        seed: Math.floor(Math.random() * 1e6) });
      setRes(r.result);
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      setLoading(false);
    }
  };

  const level3Ok = res?.level3?.filter((r) => r.ok) ?? [];

  return (
    <div className="space-y-5 max-w-4xl">
      <Card title="Public-Key Break"
        subtitle="Recover which disease each encrypted record is tagged with, holding only the public key">
        <p className="text-sm text-ink-300 leading-relaxed">
          The doctor encrypts a small database: each record carries a disease keyword. The attacker gets the
          public key, the public ciphertext database and a list of diseases — diseases are low-entropy and
          enumerable, so the list is public knowledge. No secret key, no captured trapdoor, no TrapGen. The
          attack builds a lattice basis from the public key alone, reduces it at LLL-level effort, and makes
          one trapdoor per disease to search the database.
        </p>
        <div className="flex items-end gap-4 flex-wrap mt-4">
          <label className="block"><div className="text-xs text-ink-400 mb-1">n</div>
            <input type="number" min={2} max={16} value={n} onChange={(e) => setN(e.target.value)}
              className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-20" /></label>
          <label className="block"><div className="text-xs text-ink-400 mb-1">q</div>
            <input type="number" value={q} onChange={(e) => setQ(e.target.value)}
              className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-24" /></label>
          <label className="block"><div className="text-xs text-ink-400 mb-1">records</div>
            <input type="number" min={2} max={10} value={records} onChange={(e) => setRecords(e.target.value)}
              className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-20" /></label>
          <PrimaryButton onClick={run} disabled={!initialized || loading}>
            {loading ? "Attacking (~35s)…" : "Attack with public key only"}
          </PrimaryButton>
          {!initialized && <span className="text-xs text-ink-500">Initialize params in the left rail first.</span>}
        </div>
        <ErrorBanner message={error} />
      </Card>

      {res && (
        <>
          <Card title="What the attacker holds">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div>
                <div className="text-ink-500 uppercase text-[10px] mb-2">Available</div>
                {res.attacker_inputs.map((i) => (
                  <div key={i} className="text-signal-green mb-1">✓ {i}</div>
                ))}
              </div>
              <div>
                <div className="text-ink-500 uppercase text-[10px] mb-2">Withheld</div>
                {res.withheld_from_attacker.map((i) => (
                  <div key={i} className="text-ink-500 mb-1 line-through">🔒 {i}</div>
                ))}
              </div>
            </div>
            <div className="mt-4 border-t border-ink-800 pt-4"><Norms norms={res.norms} /></div>
          </Card>

          <Card title={`Recovered from public data vs the truth — ${res.attack.recovered}/${res.attack.total} records`}>
            <div className="flex items-center gap-3 mb-4 flex-wrap">
              <Badge tone={res.attack.recovered === res.attack.total ? "red" : res.attack.recovered ? "amber" : "green"}>
                {res.attack.recovered}/{res.attack.total} disease tags recovered
              </Badge>
              <Badge tone={res.control.recovered === 0 ? "green" : "red"}>
                control (unrelated basis): {res.control.recovered}/{res.control.total}
              </Badge>
              <Badge tone={level3Ok.length ? "red" : "neutral"}>
                {level3Ok.length ? `${level3Ok.length}/${res.level3.length} full plaintexts decrypted` : "no plaintext recovered"}
              </Badge>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm mono">
                <thead>
                  <tr className="text-left text-ink-500 text-xs uppercase">
                    <th className="pb-2 pr-4">record</th>
                    <th className="pb-2 pr-4">recovered from public key</th>
                    <th className="pb-2 pr-4">true disease</th>
                    <th className="pb-2">match</th>
                  </tr>
                </thead>
                <tbody>
                  {res.attack.rows.map((row) => (
                    <tr key={row.record} className="border-t border-ink-800">
                      <td className="py-1.5 pr-4 text-ink-400">#{row.record}</td>
                      <td className={`py-1.5 pr-4 ${row.correct ? "text-signal-red" : "text-ink-400"}`}>
                        {row.recovered.length ? row.recovered.join(", ") : "—"}
                      </td>
                      <td className="py-1.5 pr-4 text-ink-300">{row.true_disease}</td>
                      <td className="py-1.5">
                        {row.correct ? <span className="text-signal-red">✓ recovered</span>
                          : row.collision_ambiguous ? <span className="text-amber-400">ambiguous (H2 collision)</span>
                          : <span className="text-ink-500">✗</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {res.h2_collisions.length > 0 && (
              <p className="text-xs text-amber-400 mt-3">
                Dictionary words sharing an H2 tag ({res.h2_collisions.map((c) => c.join("/")).join("; ")}) cannot be
                told apart by any searcher, honest or not; those records are marked ambiguous rather than scored.
              </p>
            )}
          </Card>

          <Card title="Full record plaintext (a separate, stronger claim)"
            subtitle="Only reported when Decrypt with the attack-derived basis actually round-trips">
            {level3Ok.length === 0 ? (
              <p className="text-sm text-ink-400">
                The record plaintext did not decrypt with this basis — the record decode bound is stricter than the
                keyword test. Only the disease tag was recovered.
                {res.honest_checks && !res.honest_checks.decrypt_ok &&
                  " The honest doctor's own decryption also fails at these parameters, so that limit is the scheme's, not the attack's."}
              </p>
            ) : (
              <div className="space-y-1">
                {level3Ok.map((r) => (
                  <div key={r.record} className="text-sm">
                    <span className="text-ink-500 mono">#{r.record}</span>{" "}
                    <span className="text-signal-red mono">{r.recovered_plaintext}</span>
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card title="Conclusion">
            <p className="text-sm text-ink-200 leading-relaxed">{res.conclusion}</p>
            <div className="text-xs text-amber-400 bg-amber-500/10 border border-amber-600/30 rounded px-3 py-2.5 mt-3 leading-relaxed">
              ⚠ Demonstrated at n={res.n}, q={res.q}{res.paper_params ? " — the paper's own parameters" : ""}, where the
              attack is LLL-level (BKZ β={res.beta}). At larger parameters its cost grows; see the Security Boundary tab
              for where it stops being measurable.
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
