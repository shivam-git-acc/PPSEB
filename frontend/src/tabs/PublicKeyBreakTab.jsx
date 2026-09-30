import { useState } from "react";
import { api } from "../api";
import { Card, Badge, Value, PrimaryButton, ErrorBanner } from "../components/Section";

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
  const doctorTotal = res ? Object.keys(res.honest_decrypt ?? {}).length : 0;
  const doctorOk = res?.honest_decrypt_count ?? 0;

  return (
    <div className="space-y-4">
      <Card title="Public-Key Break"
        subtitle="Recover which disease each encrypted record is tagged with, holding only the public key">
        <p className="text-[13px] text-ink-300 leading-relaxed max-w-3xl">
          Holding only the <b className="text-ink-100">public key</b>, the stored ciphertexts and a list of
          diseases, the attacker builds a basis, mints one trapdoor per disease and reads every record's tag.
          No secret key, no captured trapdoor.
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
          {!initialized && <span className="text-2xs text-ink-500">Set parameters in the header bar first.</span>}
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
              <Badge tone={doctorOk === doctorTotal ? "green" : "amber"}>
                doctor (true secret key): {doctorOk}/{doctorTotal} decrypted
              </Badge>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-[13px] mono">
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
                      <td className="py-1.5 pr-4">
                        {row.recovered.length
                          ? <Value tone={row.correct ? "break" : "warn"}>{row.recovered.join(", ")}</Value>
                          : <span className="text-ink-600">—</span>}
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
            subtitle="Attacker's public-key basis vs the doctor's true secret key, on the same records">
            <div className="overflow-x-auto">
              <table className="w-full text-[13px] mono">
                <thead>
                  <tr className="text-left text-ink-500 text-xs uppercase">
                    <th className="pb-2 pr-4">record</th>
                    <th className="pb-2 pr-4">bits</th>
                    <th className="pb-2 pr-4">attacker (public key only)</th>
                    <th className="pb-2 pr-4">doctor (true secret key)</th>
                    <th className="pb-2">recovered plaintext</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.keys(res.honest_decrypt ?? {}).map((key) => {
                    const id = Number(key);
                    const att = res.level3.find((r) => r.record === id);
                    const doc = res.honest_decrypt[key];
                    return (
                      <tr key={id} className="border-t border-ink-800">
                        <td className="py-1.5 pr-4 text-ink-400">#{id}</td>
                        <td className="py-1.5 pr-4 text-ink-500">{att?.bits ?? "—"}</td>
                        <td className={`py-1.5 pr-4 ${att?.ok ? "text-signal-red" : "text-ink-500"}`}>
                          {att ? (att.ok ? "✓ decrypted" : "✗ failed") : "tag not recovered"}
                        </td>
                        <td className={`py-1.5 pr-4 ${doc ? "text-signal-green" : "text-amber-400"}`}>
                          {doc ? "✓ decrypted" : "✗ failed"}
                        </td>
                        <td className="py-1.5">{att?.recovered_plaintext
                          ? <Value tone="break" className="max-w-[26rem] truncate">{att.recovered_plaintext}</Value>
                          : <span className="text-ink-600">—</span>}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <p className="text-xs text-ink-400 mt-3 leading-relaxed">
              Each record is ~{res.level3[0]?.bits ?? 330} separate one-bit LWE ciphertexts, and every bit must
              decode correctly for the record to match — versus {res.n && "30"} slots for the keyword test. A single
              wrong bit fails the record.
              {doctorOk < doctorTotal
                ? " The doctor fails on some records too, with the true secret key, so those failures are the scheme's noise setting at these parameters rather than a limit of the attack."
                : " The doctor decrypts every record, so any attacker failure here is down to the attack-derived basis being slightly worse."}
            </p>
          </Card>

          <Card title="Conclusion">
            <p className="text-[13px] text-ink-200 leading-relaxed max-w-4xl">{res.conclusion}</p>
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
