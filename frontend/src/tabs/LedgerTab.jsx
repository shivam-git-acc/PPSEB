import { useState } from "react";
import {
  ResponsiveContainer, BarChart, Bar, LineChart, Line, XAxis, YAxis, Tooltip,
  CartesianGrid, ReferenceLine, Legend,
} from "recharts";
import { api } from "../api";
import { Card, Badge, Value, Stat, PrimaryButton, ErrorBanner, inputCls } from "../components/Section";

const AXIS = { stroke: "#6f7a8d", fontSize: 11 };
const TIP = { background: "#141721", border: "1px solid #2a3040", borderRadius: 10,
              fontSize: 12, color: "#e8ecf4" };
const pct = (x) => (x == null ? "—" : `${(x * 100).toFixed(0)}%`);

function Head({ title, kind, children }) {
  return (
    <Card title={title}
      actions={<Badge tone={kind === "integrity" ? "amber" : "red"}>
        {kind === "integrity" ? "integrity / DoS" : "confidentiality"}
      </Badge>}>
      {children}
    </Card>
  );
}

export default function LedgerTab({ initialized }) {
  const [records, setRecords] = useState(20);
  const [queries, setQueries] = useState(300);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [r, setR] = useState(null);

  const run = async () => {
    setBusy(true); setError(null);
    try {
      const res = await api.ledgerRun({ records: Number(records), queries: Number(queries) });
      setR(res.result);
    } catch (e) { setError(String(e.message || e)); } finally { setBusy(false); }
  };

  const t1 = r?.tier1, t2 = r?.tier2, rep = r?.replay, pl = r?.plant;

  return (
    <div className="space-y-4">
      <Card title="Ledger Attacks"
        subtitle="No crypto break, no secret. These exploit the public chain and two checks the paper never specifies."
        actions={
          <>
            <label className="flex items-center gap-1.5 text-2xs text-ink-400">
              records
              <input type="number" value={records} onChange={(e) => setRecords(e.target.value)}
                className={`${inputCls} w-16`} />
            </label>
            <label className="flex items-center gap-1.5 text-2xs text-ink-400">
              queries
              <input type="number" value={queries} onChange={(e) => setQueries(e.target.value)}
                className={`${inputCls} w-20`} />
            </label>
            <PrimaryButton onClick={run} disabled={busy || !initialized}>
              {busy ? "Running…" : "Run all three"}
            </PrimaryButton>
          </>
        }>
        <p className="text-[13px] text-ink-300 leading-relaxed max-w-3xl">
          Classical PEKS leaks the access pattern to <b className="text-ink-100">one private server</b>.
          Putting verification on a public chain broadcasts it to{" "}
          <b className="text-ink-100">everyone</b>. The paper's contribution is what makes this leakage
          public — and none of it depends on n or q.
        </p>
        <ErrorBanner message={error} />
        {!initialized && <p className="text-2xs text-ink-500 mt-2">Set parameters in the header bar first.</p>}
      </Card>

      {r && (
        <>
          <Head title="A · Replay — a trapdoor is a public transaction" kind="confidentiality">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
              <div className="lg:col-span-2 space-y-3">
                <div className="flex items-center gap-3 flex-wrap text-[13px]">
                  <span className="text-ink-500">doctor's search returned</span>
                  <Value>{rep.doctor_matched.map((x) => `#${x}`).join(", ") || "—"}</Value>
                  <span className="text-ink-500">replayed by the attacker</span>
                  <Value tone={rep.identical ? "break" : "warn"}>
                    {rep.replay_matched.map((x) => `#${x}`).join(", ") || "—"}
                  </Value>
                </div>
                <div className="flex gap-2 flex-wrap">
                  <Badge tone={rep.identical ? "red" : "green"}>
                    {rep.identical ? "identical result" : "different result"}
                  </Badge>
                  <Badge tone={rep.control_ok ? "green" : "red"}>
                    control: random trapdoor matched {rep.control_random_trapdoor_matched.length}
                  </Badge>
                  <Badge tone="neutral">no secret used</Badge>
                </div>
                <p className="text-2xs text-ink-400 leading-relaxed max-w-2xl">{rep.note}</p>
              </div>
              <div className="rounded-lg bg-white/[0.03] ring-1 ring-inset ring-ink-800 p-4">
                <div className="text-2xs uppercase tracking-[0.08em] text-ink-500 mb-2">
                  Ciphertext obtained
                </div>
                {rep.records_fetched.map((f) => (
                  <div key={f.record_id} className="mono text-2xs text-ink-300">
                    #{f.record_id} · CT {f.ct_fingerprint} · CM {f.cm_fingerprint} · {f.cm_bits} bits
                  </div>
                ))}
              </div>
            </div>
          </Head>

          <Head title="B · Access-pattern leakage" kind="confidentiality">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
              <Stat label="Transactions" value={t1.transactions} />
              <Stat label="Groups recovered" value={`${t1.partition_purity.pure}/${t1.partition_purity.groups}`}
                tone="break" hint="each holds exactly one disease" />
              <Stat label="Labelling" value={pct(t2.accuracy)} tone={t2.beats_baseline ? "break" : "neutral"}
                hint={`chance ${pct(t2.baseline.mean)}`} />
              <Stat label="Never accessed" value={t1.never_accessed.length} hint="cold records" />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
              <div>
                <div className="text-2xs uppercase tracking-[0.08em] text-ink-500 mb-2">
                  Tier 1 — access count per encrypted record
                </div>
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={t1.histogram} margin={{ top: 4, right: 8, bottom: 20, left: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--grid)" />
                    <XAxis dataKey="record" {...AXIS} />
                    <YAxis {...AXIS} width={34} />
                    <Tooltip contentStyle={TIP} />
                    <Bar dataKey="accesses" fill="#3987e5" radius={[3, 3, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
                <p className="text-2xs text-ink-500 mt-1">
                  No prior and no key: the ledger alone says which records are hot.
                </p>
              </div>

              <div>
                <div className="text-2xs uppercase tracking-[0.08em] text-ink-500 mb-2">
                  Tier 2 — labelling accuracy vs chance, by observations
                </div>
                <ResponsiveContainer width="100%" height={200}>
                  <LineChart data={r.accuracy_vs_queries} margin={{ top: 4, right: 8, bottom: 20, left: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--grid)" />
                    <XAxis dataKey="queries" {...AXIS} />
                    <YAxis domain={[0, 1]} {...AXIS} width={34} />
                    <Tooltip contentStyle={TIP} />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                    <Line type="monotone" dataKey="purity" name="group purity" stroke="#0ca30c"
                      strokeWidth={2} dot={{ r: 3 }} />
                    <Line type="monotone" dataKey="accuracy" name="labelling" stroke="#d03b3b"
                      strokeWidth={2} dot={{ r: 3 }} />
                    <Line type="monotone" dataKey="baseline" name="chance" stroke="#6f7a8d"
                      strokeWidth={1.5} strokeDasharray="4 3" dot={false} />
                  </LineChart>
                </ResponsiveContainer>
                <p className="text-2xs text-ink-500 mt-1 leading-relaxed">
                  Purity is flat at 100% — the partition is certain. Labelling is the brittle half.
                </p>
              </div>
            </div>

            <div className="mt-5 grid grid-cols-1 lg:grid-cols-2 gap-5">
              <div>
                <div className="text-2xs uppercase tracking-[0.08em] text-ink-500 mb-2">
                  Recovered groups vs truth
                </div>
                <div className="overflow-x-auto max-h-64">
                  <table className="w-full text-[13px]">
                    <thead><tr className="text-left text-2xs uppercase tracking-[0.08em] text-ink-500">
                      <th className="pb-2 pr-3 font-medium">Rec</th><th className="pb-2 pr-3 font-medium">Hits</th>
                      <th className="pb-2 pr-3 font-medium">Guess</th><th className="pb-2 font-medium">Truth</th>
                    </tr></thead>
                    <tbody>
                      {t2.rows.map((row) => (
                        <tr key={row.record} className="border-t border-ink-800/70">
                          <td className="py-1.5 pr-3 mono text-ink-500">#{row.record}</td>
                          <td className="py-1.5 pr-3 mono text-ink-400">{row.accesses}</td>
                          <td className="py-1.5 pr-3">
                            <Value tone={row.correct ? "break" : "neutral"}>{row.guess}</Value>
                          </td>
                          <td className="py-1.5 mono text-ink-300">{row.truth}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
              <div className="space-y-3">
                <div className="rounded-lg bg-white/[0.03] ring-1 ring-inset ring-ink-800 p-4">
                  <div className="text-2xs uppercase tracking-[0.08em] text-ink-500 mb-2">
                    Is it better than guessing?
                  </div>
                  <div className="flex items-baseline gap-4">
                    <div><div className="text-2xl font-semibold tnum text-[#e55757]">{pct(t2.accuracy)}</div>
                      <div className="text-2xs text-ink-500">frequency analysis</div></div>
                    <div className="text-ink-600 text-xl">vs</div>
                    <div><div className="text-2xl font-semibold tnum text-ink-300">{pct(t2.baseline.mean)}</div>
                      <div className="text-2xs text-ink-500">chance (p95 {pct(t2.baseline.p95)})</div></div>
                  </div>
                  <p className="text-2xs mt-2" style={{ color: t2.beats_baseline ? "#35c235" : "#fab219" }}>
                    {t2.verdict}
                  </p>
                </div>
                <div className="rounded-lg bg-white/[0.03] ring-1 ring-inset ring-ink-800 p-4">
                  <div className="text-2xs uppercase tracking-[0.08em] text-ink-500 mb-1">
                    When the attacker's prior is wrong
                  </div>
                  <div className="text-[13px] text-ink-200">
                    {pct(r.tier2_off_distribution.accuracy)} accuracy, down from {pct(t2.accuracy)}
                  </div>
                  <p className="text-2xs text-ink-500 mt-1">
                    Queries drawn from a distribution unlike the assumed prevalence table.
                  </p>
                </div>
                <p className="text-2xs text-ink-500 leading-relaxed">{t2.cascade_note}</p>
                <p className="text-2xs text-ink-500 leading-relaxed border-t border-ink-800 pt-3">
                  {r.tier2_measured_range}
                </p>
              </div>
            </div>
          </Head>

          <Head title="C · Universal-ciphertext plant" kind="integrity">
            <div className="flex gap-2 flex-wrap mb-4">
              <Badge tone={pl.planted_matches_every_search ? "red" : "green"}>
                planted entry matched {pl.searches}/{pl.searches} searches
              </Badge>
              <Badge tone={pl.control_matches_nothing ? "green" : "red"}>
                control: random ciphertext matched nothing
              </Badge>
              <Badge tone="neutral">reveals no keyword</Badge>
            </div>
            <div className="overflow-x-auto max-h-56">
              <table className="w-full text-[13px]">
                <thead><tr className="text-left text-2xs uppercase tracking-[0.08em] text-ink-500">
                  <th className="pb-2 pr-4 font-medium">Search</th>
                  <th className="pb-2 pr-4 font-medium">Real hits</th>
                  <th className="pb-2 pr-4 font-medium">Poisoned</th>
                  <th className="pb-2 font-medium">Control</th>
                </tr></thead>
                <tbody>
                  {pl.rows.map((row) => (
                    <tr key={row.keyword} className="border-t border-ink-800/70">
                      <td className="py-1.5 pr-4 mono text-ink-300">{row.keyword}</td>
                      <td className="py-1.5 pr-4 mono text-ink-500">
                        {row.real_hits.map((x) => `#${x}`).join(" ") || "—"}
                      </td>
                      <td className="py-1.5 pr-4">
                        <Value tone="break">{row.planted_hits.map((x) => `#${x}`).join(" ")}</Value>
                      </td>
                      <td className="py-1.5 mono text-ink-600">{row.control_hits.length ? row.control_hits.join(" ") : "none"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="text-2xs text-ink-400 mt-3 leading-relaxed max-w-3xl">{pl.threat_model}</p>
          </Head>

          <Card title="Why this is the blockchain's fault">
            <p className="text-[13px] text-ink-200 leading-relaxed max-w-4xl">{r.framing}</p>
            <p className="text-2xs text-ink-500 mt-3">
              Trapdoor stability check: {r.trapdoor_stability.reproduced}/{r.trapdoor_stability.redraws} redraws
              reproduced their own match set, so replaying measured match sets in the query log is sound.
            </p>
          </Card>
        </>
      )}
    </div>
  );
}
