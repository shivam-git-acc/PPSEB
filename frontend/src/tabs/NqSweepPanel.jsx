import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { Card, Badge, PrimaryButton, ErrorBanner } from "../components/Section";

const HATCH = "repeating-linear-gradient(45deg, rgba(120,120,135,0.35) 0 4px, transparent 4px 9px)";

const VERDICTS = {
  "BROKEN (public-key only)": { bg: "bg-signal-red/35", text: "text-signal-red", short: "BROKEN: public key only" },
  "forward-security break (stolen key)": { bg: "bg-orange-500/30", text: "text-orange-300", short: "break: stolen key" },
  "attack failed (secure vs these attacks)": { bg: "bg-signal-green/25", text: "text-signal-green", short: "attacks failed" },
  "untested (timeout)": { bg: "bg-ink-700", text: "text-ink-400", short: "untested (timeout)" },
  "n/a (honest incorrect)": { bg: "bg-ink-900", text: "text-ink-400", short: "n/a: honest incorrect", hatch: true },
  "n/a (H2)": { bg: "bg-ink-900", text: "text-ink-400", short: "n/a: H2", hatch: true },
  untrusted: { bg: "bg-amber-500/25", text: "text-amber-400", short: "untrusted" },
  error: { bg: "bg-ink-800", text: "text-signal-red", short: "error" },
};

const GATE = ["kernel_ok", "match_ok", "nonmatch_ok", "search_ok", "decrypt_ok", "period_usable"];
const GATE_LABEL = {
  kernel_ok: "A·T ≡ 0",
  match_ok: "matching → 1",
  nonmatch_ok: "non-matching → 0",
  search_ok: "search returns correct N0",
  decrypt_ok: "decrypt round-trips",
  period_usable: "period basis < threshold",
};

function parseList(s) {
  return s.split(",").map((x) => parseInt(x.trim(), 10)).filter((x) => Number.isFinite(x) && x > 1);
}

function Tick({ ok }) {
  return <span className={ok ? "text-signal-green" : "text-signal-red"}>{ok ? "✓" : "✗"}</span>;
}

function CellDetail({ cell }) {
  return (
    <div className="border border-ink-800 rounded-lg p-4 space-y-3 text-xs">
      <div className="text-sm text-ink-200">
        n={cell.n}, q={cell.q}: <span className={VERDICTS[cell.verdict]?.text}>{cell.verdict}</span>
      </div>
      <div className="text-ink-400">
        m = <span className="mono text-ink-200">{cell.m}</span> (2·n·⌈log2 q⌉ = {cell.m_expected}; lower bound 2·n·log2 q ={" "}
        {cell.m_lower_bound?.toFixed(1)}) <Tick ok={cell.m_matches_formula && cell.m_above_lower_bound} />
        {" · "}runtime {cell.runtime_s?.toFixed(0)}s
      </div>
      {cell.h2_error && <div className="text-ink-400">H2: {cell.h2_error}</div>}
      {cell.error && <pre className="text-signal-red whitespace-pre-wrap">{cell.error}</pre>}
      {cell.timed_out && <div className="text-ink-400">Stopped at the per-cell timeout. Untested, not evidence of security.</div>}
      {(cell.repeats || []).map((r) => (
        <div key={r.seed} className="border-t border-ink-800 pt-3">
          <div className="text-ink-400 mb-2">
            repeat seed {r.seed} · correctness gate <Tick ok={r.gate_ok} />{" "}
            {r.threshold != null && <>· threshold {r.threshold.toFixed(1)}</>}
          </div>
          <div className="overflow-x-auto">
            <table className="mono text-[11px]">
              <thead>
                <tr className="text-left text-ink-500">
                  <th className="pr-3">period</th>
                  {GATE.map((g) => <th key={g} className="pr-3">{GATE_LABEL[g]}</th>)}
                  <th className="pr-3">word_gs vs thr (not gated)</th>
                  <th className="pr-3">public-key attack N0* / N0</th>
                  <th className="pr-3">stolen-key attack N0* / N0</th>
                  <th>control</th>
                </tr>
              </thead>
              <tbody>
                {r.periods.map((pe) => (
                  <tr key={pe.period} className="text-ink-300">
                    <td className="pr-3">{pe.period}</td>
                    {GATE.map((g) => <td key={g} className="pr-3"><Tick ok={pe.checks[g]} /></td>)}
                    <td className="pr-3">{pe.checks.word_gs.toFixed(0)} / {pe.checks.threshold.toFixed(0)}</td>
                    <td className={`pr-3 ${pe.attack1?.break ? "text-signal-red" : ""}`}>
                      {pe.attack1 ? `${pe.attack1.N0_star ?? "—"} / ${pe.attack1.N0_legit}${pe.attack1.break ? " BREAK" : ""}` : "not run"}
                    </td>
                    <td className={`pr-3 ${pe.attack2?.break ? "text-orange-300" : ""}`}>
                      {pe.attack2 ? `${pe.attack2.N0_star ?? "—"} / ${pe.attack2.N0_legit}${pe.attack2.break ? " BREAK" : ""}` : "not run"}
                    </td>
                    <td className={pe.control?.passed ? "text-signal-red" : ""}>
                      {pe.control ? (pe.control.passed ? "PASSED (untrusted)" : "failed, as required") : "not run"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ))}
    </div>
  );
}

export default function NqSweepPanel({ initialized }) {
  const [nList, setNList] = useState("4, 8");
  const [qList, setQList] = useState("257, 1153, 4001");
  const [J, setJ] = useState(4);
  const [repeats, setRepeats] = useState(2);
  const [records, setRecords] = useState(40);
  const [timeout, setTimeoutS] = useState(3600);
  const [jobId, setJobId] = useState(null);
  const [snap, setSnap] = useState(null);
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState(null);
  const [jobs, setJobs] = useState([]);
  const pollRef = useRef(null);

  useEffect(() => {
    api.nqSweepJobs().then((r) => setJobs(r.result || [])).catch(() => {});
  }, []);

  useEffect(() => {
    if (!jobId) return undefined;
    const tick = async () => {
      try {
        const r = await api.nqSweepStatus(jobId);
        setSnap(r.result);
        if (r.result.status !== "running") {
          clearInterval(pollRef.current);
          api.nqSweepJobs().then((j) => setJobs(j.result || [])).catch(() => {});
        }
      } catch (e) {
        setError(String(e.message || e));
        clearInterval(pollRef.current);
      }
    };
    tick();
    pollRef.current = setInterval(tick, 4000);
    return () => clearInterval(pollRef.current);
  }, [jobId]);

  const start = async () => {
    setError(null);
    setSelected(null);
    try {
      const r = await api.nqSweepStart({
        n_values: parseList(nList), q_values: parseList(qList), J: Number(J), repeats: Number(repeats),
        records_per_period: Number(records), cell_timeout_s: Number(timeout),
      });
      setSnap(null);
      setJobId(r.result.job_id);
    } catch (e) {
      setError(String(e.message || e));
    }
  };

  const cfg = snap?.config;
  const ns = cfg?.n_values ?? parseList(nList);
  const qs = cfg?.q_values ?? parseList(qList);
  const cellAt = (n, q) => snap?.cells?.find((c) => c.n === n && c.q === q);
  const selectedCell = selected && cellAt(selected.n, selected.q);

  return (
    <div className="space-y-5">
      <Card title="n × q grid" subtitle="Correctness-gated, public-key-only attack vs stolen-key attack, per (n, q). m = 2n·⌈log2 q⌉ is derived per cell, not an axis.">
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs">
          <label className="block"><div className="text-ink-400 mb-1">n values (powers of 2 only)</div>
            <input value={nList} onChange={(e) => setNList(e.target.value)} className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-full" /></label>
          <label className="block"><div className="text-ink-400 mb-1">q values (primes; q ≡ 1 mod 4 for n=4, 8)</div>
            <input value={qList} onChange={(e) => setQList(e.target.value)} className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-full" /></label>
          <label className="block"><div className="text-ink-400 mb-1">J (chain length)</div>
            <input type="number" min={2} max={8} value={J} onChange={(e) => setJ(e.target.value)} className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-full" /></label>
          <label className="block"><div className="text-ink-400 mb-1">repeats / cell</div>
            <input type="number" min={1} max={10} value={repeats} onChange={(e) => setRepeats(e.target.value)} className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-full" /></label>
          <label className="block"><div className="text-ink-400 mb-1">records / period</div>
            <input type="number" min={2} max={51} value={records} onChange={(e) => setRecords(e.target.value)} className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-full" /></label>
          <label className="block"><div className="text-ink-400 mb-1">per-cell timeout (s)</div>
            <input type="number" min={10} value={timeout} onChange={(e) => setTimeoutS(e.target.value)} className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-full" /></label>
        </div>
        <div className="mt-4 flex items-center gap-3">
          <PrimaryButton onClick={start} disabled={!initialized || snap?.status === "running"}>
            {snap?.status === "running" ? `Running… ${snap.done}/${snap.total} cells` : "Run n × q grid"}
          </PrimaryButton>
          {snap && <span className="text-xs text-ink-500 mono">{snap.job_id} · {snap.status} · {snap.elapsed_s?.toFixed(0)}s</span>}
        </div>
        <ErrorBanner message={error} />
        {jobs.length > 0 && (
          <div className="mt-3 flex gap-2 flex-wrap text-xs">
            <span className="text-ink-500">Past runs:</span>
            {jobs.map((j) => (
              <button key={j.job_id} onClick={() => { setSelected(null); setJobId(j.job_id); }}
                className="mono text-ink-400 hover:text-ink-200 underline">{j.job_id} ({j.done}/{j.total}, {j.status})</button>
            ))}
          </div>
        )}
      </Card>

      {snap && (
        <Card title="Verdict per (n, q)" subtitle="Click a cell for its correctness checks, both attacks and the control">
          <div className="overflow-x-auto">
            <div className="inline-block">
              <div className="flex">
                <div className="w-14 shrink-0" />
                {qs.map((q) => <div key={q} className="w-40 text-center text-[11px] text-ink-500 pb-1">q={q}</div>)}
              </div>
              {ns.map((n) => (
                <div key={n} className="flex items-center">
                  <div className="w-14 shrink-0 text-[11px] text-ink-500 pr-2 text-right">n={n}</div>
                  {qs.map((q) => {
                    const c = cellAt(n, q);
                    const v = c ? VERDICTS[c.verdict] ?? VERDICTS.error : null;
                    return (
                      <button key={q} onClick={() => c && setSelected({ n, q })}
                        style={v?.hatch ? { backgroundImage: HATCH } : undefined}
                        className={`w-40 h-16 m-0.5 rounded border flex flex-col items-center justify-center ${
                          selected?.n === n && selected?.q === q ? "border-signal-blue" : "border-ink-800"
                        } ${v ? v.bg : "bg-ink-900"}`}>
                        <span className={`text-[11px] font-medium ${v ? v.text : "text-ink-600"}`}>{v ? v.short : "pending"}</span>
                        <span className="mono text-[10px] text-ink-400">m={c ? c.m : 2 * n * Math.ceil(Math.log2(q))}</span>
                      </button>
                    );
                  })}
                </div>
              ))}
            </div>
          </div>
          <div className="flex gap-3 mt-3 flex-wrap">
            {Object.entries(VERDICTS).map(([k, v]) => (
              <div key={k} className="flex items-center gap-1.5">
                <div className={`w-3 h-3 rounded border border-ink-700 ${v.bg}`} style={v.hatch ? { backgroundImage: HATCH } : undefined} />
                <span className="text-[10px] text-ink-500">{k}</span>
              </div>
            ))}
          </div>
          {snap.conclusion && <p className="text-sm text-ink-200 leading-relaxed mt-4">{snap.conclusion}</p>}
          <div className="text-xs text-amber-400 bg-amber-500/10 border border-amber-600/30 rounded px-3 py-2.5 mt-3 leading-relaxed">
            ⚠ Demonstration parameters only. A public-key-only break means the public key alone yields a working
            trapdoor at that (n, q), so a stolen-key break there says nothing about forward security.
          </div>
        </Card>
      )}

      {selectedCell && <CellDetail cell={selectedCell} />}
    </div>
  );
}
