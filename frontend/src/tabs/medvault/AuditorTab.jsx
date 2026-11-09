import { useEffect, useState } from "react";
import { api } from "../../api";
import { Card, Badge, Stat, PrimaryButton, SecondaryButton, ErrorBanner } from "../../components/Section";
import { useOp, TraceCard, Verdict } from "../../components/medvault/shared";

const ATTACKS = [
  ["Keyword-guessing", "offline dictionary attack on the public key"],
  ["Ciphertext plant", "an entry that matches every search"],
  ["Replay (search)", "re-send a captured search request"],
  ["Replay (retrieval)", "re-send a captured fetch to pull the record again"],
  ["Access pattern", "what the ledger reveals"],
];

/* The harness reports each attack in its own shape. This turns all five into
   (baseline, hardened, did the hardened path hold?) so the table can be read
   at a glance without pretending the four measurements are identical. */
function attackRows(results) {
  const kga = results.kga ?? {};
  return [
    { name: ATTACKS[0][0], hint: ATTACKS[0][1],
      a: `${kga.mode_A?.outsider?.success_rate_pct ?? "?"}% recovered`,
      b: `${kga.mode_B?.outsider?.success_rate_pct ?? "?"}% recovered`,
      held: kga.mode_B?.outsider?.success_rate_pct === 0 },
    { name: ATTACKS[1][0], hint: ATTACKS[1][1],
      a: `planted hit: ${results.plant?.A?.appears_in_search}`,
      b: `planted hit: ${results.plant?.B?.appears_in_search}`,
      held: results.plant?.B?.appears_in_search === false },
    { name: ATTACKS[2][0], hint: ATTACKS[2][1],
      a: `replay accepted: ${results.replay?.A?.replay_ok}`,
      b: `replay accepted: ${results.replay?.B?.replay_ok}`,
      held: results.replay?.B?.replay_ok === false },
    { name: ATTACKS[3][0], hint: ATTACKS[3][1],
      a: `ciphertext handed over again: ${results.retrieval_replay?.A?.replay_ok}`,
      b: `handed over again: ${results.retrieval_replay?.B?.replay_ok}` +
         (results.retrieval_replay?.B?.replay_reason ? ` (${results.retrieval_replay.B.replay_reason})` : ""),
      held: results.retrieval_replay?.B?.replay_ok === false },
    { name: ATTACKS[4][0], hint: ATTACKS[4][1],
      a: `token on chain: ${results.access_pattern?.A?.token_on_chain}`,
      b: `token on chain: ${results.access_pattern?.B?.token_on_chain}`,
      held: results.access_pattern?.B?.token_on_chain === false },
  ];
}

function AttackRow({ row }) {
  return (
    <tr className="border-t border-ink-800/70">
      <td className="py-2 pr-3">
        <div className="text-[13px] text-ink-200">{row.name}</div>
        <div className="text-2xs text-ink-600">{row.hint}</div>
      </td>
      <td className="py-2 pr-3 mono text-2xs text-ink-400">{row.a}</td>
      <td className="py-2 pr-3 mono text-2xs text-ink-300">{row.b}</td>
      <td className="py-2">
        <Badge tone={row.held ? "green" : "red"}>{row.held ? "blocked" : "succeeded"}</Badge>
      </td>
    </tr>
  );
}

export default function AuditorTab() {
  const [audit, setAudit] = useState(null);
  const [matrix, setMatrix] = useState(null);
  const [zk, setZk] = useState(null);
  const [busy, setBusy] = useState(false);
  const attacks = useOp();

  const load = async () => {
    try {
      const [a, z] = await Promise.all([api.mvAudit(), api.mvZk()]);
      setAudit(a.result);
      setZk(z.result);
    } catch { /* nothing to show yet */ }
  };
  useEffect(() => { load(); }, []);

  const runAttacks = async () => {
    setBusy(true);
    const body = await attacks.run(() => api.mvAttack({ kind: "all", mode: "both", attacker: "outsider" }));
    setBusy(false);
    if (body) setMatrix(body.results);
  };

  const chain = audit?.chain ?? [];
  const state = audit?.state;

  return (
    <div className="space-y-4">
      <Card
        title="Auditor — what the system publishes, and what it costs"
        subtitle="A passive observer sees commitments, epochs and event types. No tokens, no record ids, no keywords."
        actions={<>
          <SecondaryButton onClick={load}>Refresh</SecondaryButton>
          <PrimaryButton onClick={runAttacks} disabled={busy}>
            {busy ? "Running…" : "Run every attack"}
          </PrimaryButton>
        </>}
      >
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <Stat label="Ledger backend" value={state?.backend ?? "—"} />
          <Stat label="Audit events" value={state?.audit_events ?? "—"} />
          <Stat label="Search commitments" value={state?.search_commitments ?? "—"} />
          <Stat label="Nullifiers" value={state?.nullifiers ?? "—"} hint="one per accepted proof" />
        </div>
        <ErrorBanner message={attacks.error} />
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card title="Chain log" subtitle="Everything a passive chain observer can read.">
          {chain.length ? (
            <div className="overflow-auto max-h-80">
              <table className="w-full text-[13px]">
                <thead>
                  <tr className="text-left text-2xs uppercase tracking-[0.08em] text-ink-500">
                    <th className="pb-2 pr-3 font-medium">#</th>
                    <th className="pb-2 pr-3 font-medium">Type</th>
                    <th className="pb-2 pr-3 font-medium">Epoch</th>
                    <th className="pb-2 font-medium">Hash</th>
                  </tr>
                </thead>
                <tbody>
                  {chain.map((e, i) => (
                    <tr key={`${e.type}-${i}`} className="border-t border-ink-800/70">
                      <td className="py-1.5 pr-3 mono text-ink-600">{e.event_id ?? e.block ?? i + 1}</td>
                      <td className="py-1.5 pr-3 text-ink-300">{e.type}</td>
                      <td className="py-1.5 pr-3 mono text-ink-500">{e.epoch ?? "—"}</td>
                      <td className="py-1.5 mono text-2xs text-ink-500">{(e.data_hash ?? "").slice(0, 24)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <p className="text-2xs text-ink-500">No events yet — upload or grant first.</p>}
        </Card>

        <Card title="Zero-knowledge authorisation" subtitle={zk?.label ?? "checking…"}>
          {zk ? (
            <div className="space-y-2 text-[13px] text-ink-300">
              <Verdict ok={zk.available}>
                {zk.available ? "circuit built and used" : "circuit not built — signed fallback is labelled, not claimed"}
              </Verdict>
              <div className="grid grid-cols-2 gap-3 mt-3">
                <Stat label="Constraints" value={zk.circuit?.constraints ?? "—"} />
                <Stat label="Tree depth" value={zk.circuit?.depth ?? "—"} hint="consent leaves" />
                <Stat label="Proving key" value={zk.circuit?.zkey_bytes ? `${(zk.circuit.zkey_bytes / 1e6).toFixed(1)} MB` : "—"} />
                <Stat label="Nullifiers used" value={zk.nullifiers_consumed} />
              </div>
              <p className="text-2xs text-ink-500 leading-relaxed mt-3">
                Public: {zk.public_inputs.join(", ")}. Private: {zk.private_inputs.join(", ")}.
                {" "}Groth16 over BN254 is classical, and the setup here is an unaudited single-party dev
                ceremony — {zk.circuit?.trusted_setup ?? "not suitable for real use"}.
              </p>
            </div>
          ) : <p className="text-2xs text-ink-500">Waiting for the backend…</p>}
        </Card>
      </div>

      {matrix && (
        <Card title="Attack harness — baseline vs hardened" subtitle="Each cell is measured on a fresh world, not asserted.">
          <div className="overflow-auto">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="text-left text-2xs uppercase tracking-[0.08em] text-ink-500">
                  <th className="pb-2 pr-3 font-medium">Attack</th>
                  <th className="pb-2 pr-3 font-medium">Mode A (PPSEB)</th>
                  <th className="pb-2 pr-3 font-medium">Mode B (MedVault)</th>
                  <th className="pb-2 font-medium">Hardened path</th>
                </tr>
              </thead>
              <tbody>
                {attackRows(matrix).map((row) => <AttackRow key={row.name} row={row} />)}
              </tbody>
            </table>
          </div>
          <p className="text-2xs text-ink-500 mt-3 leading-relaxed">
            An insider who holds a capability still matches keywords inside their own scope — that is
            the documented limit, not a bug. What closes is the outsider and keyless-server path.
          </p>
        </Card>
      )}

      <TraceCard op={attacks} title="Attack harness trace" subtitle="One event per measured step." />
    </div>
  );
}
