import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import NetworkDiagram from "./NetworkDiagram";
import { Card, Badge, Value, PrimaryButton, SecondaryButton, ErrorBanner, inputCls } from "../components/Section";

// Building a session costs a TrapGen plus the noise calibration, so a tab
// switch reattaches to the live one instead of throwing the cloud away.
let cachedSessionId = null;

const ORDER = ["public_key", "stolen_key", "control"];
const TITLES = {
  public_key: "Public key only",
  stolen_key: "Stolen period key",
  control: "Garbage key (control)",
};

function Panel({ title, note, children, tone }) {
  const ring = tone === "attacker" ? "ring-[#7a3138]/60" : "ring-ink-800";
  return (
    <div className={`rounded-xl2 bg-ink-900 ring-1 ring-inset ${ring} flex flex-col min-w-0`}>
      <div className="px-4 py-2.5 border-b border-ink-800 flex items-baseline justify-between gap-3">
        <h3 className="text-2xs font-semibold uppercase tracking-[0.1em] text-ink-300">{title}</h3>
        {note && <span className="text-2xs text-ink-500 mono truncate">{note}</span>}
      </div>
      <div className="p-4 space-y-3 flex-1">{children}</div>
    </div>
  );
}

function Row({ label, children }) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-2xs text-ink-500 w-16 shrink-0">{label}</span>
      {children}
    </div>
  );
}

/* One attack, scored against the truth. The recovered keyword is the thing the
   reader is here to read, so it gets primary ink and a chip -- not small
   coloured text on a dark panel. */
function AttackResult({ res, stale }) {
  const total = res.periods.reduce((a, p) => a + (p.total ?? 0), 0);
  const got = res.periods.reduce((a, p) => a + (p.recovered ?? 0), 0);
  const l3 = res.periods.reduce((a, p) => a + (p.rows ?? []).filter((r) => r.level3).length, 0);
  return (
    <Card
      title={TITLES[res.control ? "control" : res.kind] + (res.kind === "stolen_key" && !res.control ? ` · sk_r|${res.stolen_period}` : "")}
      subtitle={`${res.periods.length} period(s) · ${res.records_at_run} stored record(s)`}
      actions={
        <>
          <Badge tone={got ? "red" : "green"}>{got}/{total} tags recovered</Badge>
          {l3 > 0 && <Badge tone="red">{l3} plaintexts</Badge>}
        </>
      }>
      {stale && (
        <div className="text-2xs text-signal-amber bg-signal-amber/10 ring-1 ring-inset ring-signal-amber/25
                        rounded-lg px-3 py-2 mb-4">
          The cloud changed after this run — these numbers describe the database as it was then.
        </div>
      )}
      <div className="space-y-5">
        {res.periods.map((p) => (
          <div key={p.period}>
            <div className="flex items-center gap-2 flex-wrap mb-2.5">
              <span className="text-[13px] font-semibold text-ink-100">Period {p.period}</span>
              <Badge tone={p.outcome === "recovered" ? "red" : p.outcome === "unmeasured (timeout)" ? "neutral" : "green"}>
                {p.outcome}
              </Badge>
              {p.forward_security_break && <Badge tone="amber">★ stolen key required</Badge>}
              {p.recovery_rate != null && (
                <span className="text-2xs text-ink-400 mono">
                  {(p.recovery_rate * 100).toFixed(0)}% · ‖Trap‖ {p.mean_trap_norm?.toFixed(0)} · margin{" "}
                  {p.mean_margin > 0 ? "+" : ""}{p.mean_margin?.toFixed(0)}
                </span>
              )}
            </div>
            {p.comparison_note && (
              <p className={`text-2xs mb-2.5 ${p.forward_security_break ? "text-signal-amber" : "text-ink-500"}`}>
                {p.comparison_note}
              </p>
            )}
            {p.error && <p className="text-2xs text-[#e55757] mono">{p.error}</p>}
            {p.rows?.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-[13px]">
                  <thead>
                    <tr className="text-left text-2xs uppercase tracking-[0.08em] text-ink-500">
                      <th className="pb-2 pr-4 font-medium">Record</th>
                      <th className="pb-2 pr-4 font-medium">Recovered</th>
                      <th className="pb-2 pr-4 font-medium">Truth</th>
                      <th className="pb-2 font-medium">Plaintext</th>
                    </tr>
                  </thead>
                  <tbody>
                    {p.rows.map((r) => (
                      <tr key={r.record_id} className="border-t border-ink-800/70 align-middle">
                        <td className="py-2 pr-4 mono text-ink-500">#{r.record_id}</td>
                        <td className="py-2 pr-4">
                          {r.recovered?.length
                            ? <Value tone={r.correct ? "break" : "warn"}>{r.recovered.join(", ")}</Value>
                            : <span className="text-ink-600">—</span>}
                        </td>
                        <td className="py-2 pr-4 mono text-ink-300">{r.true_disease}</td>
                        <td className="py-2">
                          {r.level3
                            ? <Value tone="break" className="max-w-[28rem] truncate">{r.plaintext}</Value>
                            : r.correct
                              ? <span className="text-2xs text-ink-500">tag only — plaintext hit the decode bound</span>
                              : <span className="text-ink-600">—</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {p.h2_collisions?.length > 0 && (
              <p className="text-2xs text-signal-amber mt-2">
                {p.h2_collisions.map((c) => c.join(" / ")).join("; ")} share an H2 tag — indistinguishable to any searcher.
              </p>
            )}
          </div>
        ))}
      </div>
      <details className="mt-4 pt-3 border-t border-ink-800">
        <summary className="text-2xs text-ink-500 cursor-pointer hover:text-ink-300">Full conclusion</summary>
        <p className="text-[13px] text-ink-300 leading-relaxed mt-2">{res.conclusion}</p>
      </details>
    </Card>
  );
}

export default function NetworkTab({ onTrace }) {
  const [options, setOptions] = useState(null);
  const [n, setN] = useState(4);
  const [q, setQ] = useState(257);
  const [state, setState] = useState(null);
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);
  const [activeEdge, setActiveEdge] = useState(null);
  const [pulse, setPulse] = useState(0);
  const [lastEvent, setLastEvent] = useState(null);
  const [results, setResults] = useState({});   // keyed by attack, so each run persists
  const [script, setScript] = useState(null);

  const [keyword, setKeyword] = useState("diabetes");
  const [text, setText] = useState("Patient A: insulin started");
  const [query, setQuery] = useState("diabetes");
  const [decryptId, setDecryptId] = useState(0);

  const [attackKind, setAttackKind] = useState("public_key");
  const [stolenPeriod, setStolenPeriod] = useState(null);
  const [periodSel, setPeriodSel] = useState("all");
  const [control, setControl] = useState(false);
  const cancelScript = useRef(false);

  const dict = state?.dictionary ?? [];
  const periods = state?.periods ?? [];
  const cloudRecords = useMemo(() => periods.flatMap((p) => p.records), [periods]);
  const available = state?.available;

  const apply = useCallback(async (nn = n, qq = q) => {
    setBusy("rebuild"); setError(null); setResults({});
    try {
      const r = await api.networkNew({ n: Number(nn), q: Number(qq) });
      cachedSessionId = r.result.state.session_id;
      setState(r.result.state);
      setPeriodSel("all"); setStolenPeriod(null);
      setKeyword(r.result.state.dictionary[0]);
      setQuery(r.result.state.dictionary[0]);
      onTrace?.(r.trace, "Network");
    } catch (e) { setError(String(e.message || e)); } finally { setBusy(null); }
  }, [n, q, onTrace]);

  useEffect(() => { api.networkOptions().then((r) => setOptions(r.result)).catch(() => {}); }, []);
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (cachedSessionId) {
        try {
          const r = await api.networkState(cachedSessionId);
          if (!cancelled) {
            setState(r.result.state);
            setN(r.result.state.n); setQ(r.result.state.q);
            setKeyword(r.result.state.dictionary[0]); setQuery(r.result.state.dictionary[0]);
            return;
          }
        } catch { cachedSessionId = null; }
      }
      if (!cancelled) apply(4, 257); // the paper's parameters on a cold start
    })();
    return () => { cancelled = true; };
  }, []); // eslint-disable-line

  const optionFor = (nn, qq) => options?.options?.find((o) => o.n === Number(nn) && o.q === Number(qq));
  const chosen = optionFor(n, q);

  const act = async (label, edge, fn) => {
    setBusy(label); setError(null);
    setActiveEdge(edge); setPulse((p) => p + 1);
    try {
      const r = await fn();
      setState(r.result.state);
      if (r.result.event) setLastEvent(r.result.event);
      if (r.trace?.length) onTrace?.(r.trace, "Network");
      return r;
    } catch (e) {
      setError(String(e.message || e));
      return null;
    } finally { setBusy(null); }
  };

  const addRecord = () => act("record", "doctor->cloud", () =>
    api.networkRecord({ session_id: state.session_id, keyword, text }));
  const doSearch = () => act("search", "doctor->verifier->doctor", () =>
    api.networkSearch({ session_id: state.session_id, keyword: query }));
  const advance = () => act("advance", "doctor", () =>
    api.networkAdvance({ session_id: state.session_id }));
  const decrypt = () => act("decrypt", "cloud->doctor", () =>
    api.networkDecrypt({ session_id: state.session_id, record_id: Number(decryptId) }));

  const launch = async () => {
    const r = await act("attack", "attack", () => api.networkAttack({
      session_id: state.session_id, kind: attackKind, periods: ticked,
      stolen_period: attackKind === "stolen_key" ? stolenPeriod : null, control,
    }));
    if (r) {
      const stamped = { ...r.result, records_at_run: cloudRecords.length, ran_at: Date.now() };
      setResults((prev) => ({ ...prev, [resultKey(attackKind, control)]: stamped }));
    }
    return r;
  };

  // A stolen key only reaches periods EARLIER than the theft, so those are the
  // only ones the dropdown offers for that attack.
  const eligible = useMemo(() => periods
    .map((p) => p.period)
    .filter((i) => attackKind === "public_key" || (stolenPeriod != null && i < stolenPeriod)),
  [periods, attackKind, stolenPeriod]);
  const ticked = periodSel === "all" ? eligible
    : eligible.includes(Number(periodSel)) ? [Number(periodSel)] : [];
  const resultKey = (kind, ctrl) => (ctrl ? "control" : kind);

  // --- the scripted walkthrough (§4) ------------------------------------
  const runScript = async () => {
    cancelScript.current = false;
    const pause = (ms) => new Promise((res) => setTimeout(res, ms));
    const step = async (label, fn) => {
      if (cancelScript.current) throw new Error("cancelled");
      setScript(label);
      await fn();
      await pause(900);
    };
    try {
      const fresh = await api.networkNew({ n: Number(n), q: Number(q) });
      let s = fresh.result.state;
      setState(s); setResults({}); setPeriodSel("all");
      const sid = s.session_id;
      const add = async (kw, txt) => {
        setActiveEdge("doctor->cloud"); setPulse((p) => p + 1);
        const r = await api.networkRecord({ session_id: sid, keyword: kw, text: txt });
        setState(r.result.state); setLastEvent(r.result.event);
      };
      await step("1/6 — doctor stores three records at period 0", async () => {
        await add("diabetes", "Patient A: insulin started");
        await add("asthma", "Patient B: inhaler prescribed");
        await add("melanoma", "Patient C: biopsy scheduled");
      });
      await step("2/6 — doctor searches 'diabetes', verifier answers, doctor decrypts", async () => {
        setActiveEdge("doctor->verifier->doctor"); setPulse((p) => p + 1);
        const r = await api.networkSearch({ session_id: sid, keyword: "diabetes" });
        setState(r.result.state); setLastEvent(r.result.event);
        const n0 = r.result.event.data.N0;
        if (n0 != null) {
          setActiveEdge("cloud->doctor"); setPulse((p) => p + 1);
          const d = await api.networkDecrypt({ session_id: sid, record_id: n0 });
          setState(d.result.state); setLastEvent(d.result.event);
        }
      });
      await step("3/6 — key evolves to periods 1 and 2, more records stored", async () => {
        let r = await api.networkAdvance({ session_id: sid }); setState(r.result.state);
        await add("hepatitis", "Patient D: labs pending");
        r = await api.networkAdvance({ session_id: sid }); setState(r.result.state);
        await add("epilepsy", "Patient E: EEG normal");
      });
      await step("4/6 — attacker, PUBLIC KEY ONLY, all periods", async () => {
        setAttackKind("public_key"); setPeriodSel("all");
        setActiveEdge("attack"); setPulse((p) => p + 1);
        const r = await api.networkAttack({ session_id: sid, kind: "public_key", periods: [0, 1, 2] });
        setState(r.result.state); onTrace?.(r.trace, "Network");
        setResults((prev) => ({ ...prev, public_key: { ...r.result, records_at_run: 5 } }));
      });
      await step("5/6 — attacker steals the period-2 key, reaches back to 0 and 1", async () => {
        setAttackKind("stolen_key"); setStolenPeriod(2); setPeriodSel("all");
        setActiveEdge("attack"); setPulse((p) => p + 1);
        const r = await api.networkAttack({ session_id: sid, kind: "stolen_key", periods: [0, 1], stolen_period: 2 });
        setState(r.result.state); onTrace?.(r.trace, "Network");
        setResults((prev) => ({ ...prev, stolen_key: { ...r.result, records_at_run: 5 } }));
      });
      await step("6/6 — negative control: a garbage key must recover nothing", async () => {
        setControl(true);
        const r = await api.networkAttack({ session_id: sid, kind: "public_key", periods: [0], control: true });
        setState(r.result.state); onTrace?.(r.trace, "Network");
        setResults((prev) => ({ ...prev, control: { ...r.result, records_at_run: 5 } }));
        setControl(false);
      });
      setScript("done — the whole story, every value measured live");
    } catch (e) {
      if (String(e.message) !== "cancelled") setError(String(e.message || e));
      setScript(null);
    }
  };

  return (
    <div className="space-y-4">
      {/* ---- the architecture, and the one control strip that drives it ---- */}
      <Card
        title="Network"
        subtitle="Everything below the dashed line is public. The attacker lives there because it never has to cross it."
        actions={
          <>
            <select value={n} onChange={(e) => setN(e.target.value)} className={`${inputCls} w-[5.5rem]`}>
              {(options?.n_choices ?? [4, 8, 16]).map((v) => <option key={v} value={v}>n = {v}</option>)}
            </select>
            <select value={q} onChange={(e) => setQ(e.target.value)} className={`${inputCls} w-[7.5rem]`}>
              {(options?.q_choices ?? [257]).map((v) => <option key={v} value={v}>q = {v}</option>)}
            </select>
            <span className="text-2xs text-ink-500 mono hidden sm:inline">m {chosen?.m ?? state?.m ?? "—"}</span>
            <SecondaryButton onClick={() => apply()} disabled={busy != null || chosen?.available === false}>
              {busy === "rebuild" ? "Rebuilding…" : "Rebuild"}
            </SecondaryButton>
            <PrimaryButton onClick={runScript} disabled={busy != null}>Run demo</PrimaryButton>
          </>
        }
        pad={false}>
        <div className="px-3 pt-2 pb-1">
          <NetworkDiagram
            activeEdge={activeEdge} pulse={pulse}
            period={state?.current_period ?? 0}
            blobs={cloudRecords.length}
            attackerHolds={attackKind === "public_key" ? "public key only" : `stolen sk_r|${stolenPeriod ?? "?"}`} />
        </div>
        <div className="px-5 py-3 border-t border-ink-800 flex items-center gap-3 flex-wrap min-h-[2.75rem]">
          {script && <span className="text-2xs text-accent-soft">▶ {script}</span>}
          {!script && lastEvent && (
            <span className="text-2xs text-ink-400 mono">
              {lastEvent.label}
              {lastEvent.data?.plaintext && <span className="text-ink-100"> → “{lastEvent.data.plaintext}”</span>}
            </span>
          )}
          {!script && !lastEvent && <span className="text-2xs text-ink-600">Store a record to begin.</span>}
          {chosen?.available === false && (
            <span className="text-2xs text-signal-amber">n={n}, q={q} unavailable — {chosen.reason}</span>
          )}
          {state && !available && <span className="text-2xs text-signal-amber">⚠ {state.unavailable_reason}</span>}
        </div>
        <ErrorBanner message={error} />
      </Card>

      {state && available && (
        <>
          {/* ---- the three actors, side by side, full width ---- */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            <div className="lg:col-span-3">
              <Panel title="Doctor" note={`period ${state.current_period} · pk ${periods[state.current_period]?.pk_fingerprint}`}>
                <Row label="store">
                  <select value={keyword} onChange={(e) => setKeyword(e.target.value)} className={inputCls}>
                    {dict.map((d) => <option key={d} value={d}>{d}</option>)}
                  </select>
                </Row>
                <input value={text} onChange={(e) => setText(e.target.value)} placeholder="record text"
                  className={inputCls} />
                <SecondaryButton onClick={addRecord} disabled={busy != null}>Encrypt → cloud</SecondaryButton>

                <div className="pt-3 border-t border-ink-800 space-y-3">
                  <Row label="search">
                    <select value={query} onChange={(e) => setQuery(e.target.value)} className={inputCls}>
                      {dict.map((d) => <option key={d} value={d}>{d}</option>)}
                    </select>
                  </Row>
                  <Row label="decrypt">
                    <select value={decryptId} onChange={(e) => setDecryptId(e.target.value)} className={inputCls}>
                      {cloudRecords.map((r) => (
                        <option key={r.record_id} value={r.record_id}>#{r.record_id} · period {r.period}</option>
                      ))}
                    </select>
                  </Row>
                  <div className="flex gap-2 flex-wrap">
                    <SecondaryButton onClick={doSearch} disabled={busy != null}>Search</SecondaryButton>
                    <SecondaryButton onClick={decrypt} disabled={busy != null || !cloudRecords.length}>Decrypt</SecondaryButton>
                    <SecondaryButton onClick={advance} disabled={busy != null}>Next period</SecondaryButton>
                  </div>
                </div>
              </Panel>
            </div>

            <div className="lg:col-span-5">
              <Panel title="Cloud" note={`${cloudRecords.length} blob pair(s) · learns nothing`}>
                {cloudRecords.length === 0 ? (
                  <p className="text-2xs text-ink-600">Empty.</p>
                ) : (
                  <div className="overflow-x-auto max-h-[17rem]">
                    <table className="w-full text-[13px] mono">
                      <thead className="sticky top-0 bg-ink-900">
                        <tr className="text-left text-2xs uppercase tracking-[0.08em] text-ink-500">
                          <th className="pb-2 pr-3 font-medium">j</th><th className="pb-2 pr-3 font-medium">rec</th>
                          <th className="pb-2 pr-3 font-medium">CT</th><th className="pb-2 pr-3 font-medium">CM</th>
                          <th className="pb-2 font-medium">bits</th>
                        </tr>
                      </thead>
                      <tbody>
                        {cloudRecords.map((r) => (
                          <tr key={r.record_id} className="border-t border-ink-800/70 text-ink-300">
                            <td className="py-1.5 pr-3 text-ink-500">{r.period}</td>
                            <td className="py-1.5 pr-3">#{r.record_id}</td>
                            <td className="py-1.5 pr-3 text-ink-500">{r.ct_fingerprint}</td>
                            <td className="py-1.5 pr-3 text-ink-500">{r.cm_fingerprint}</td>
                            <td className="py-1.5">{r.cm_bits}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Panel>
            </div>

            <div className="lg:col-span-4 space-y-4">
              <Panel title="Verifier" note="public — no secret">
                {lastEvent?.edge === "doctor->verifier->doctor" ? (
                  <div className="space-y-2">
                    <div className="mono text-[13px] text-ink-300">
                      {lastEvent.data.keyword} @ period {lastEvent.data.period}
                    </div>
                    {lastEvent.data.N0 != null
                      ? <Value tone="ok">match → record #{lastEvent.data.N0}</Value>
                      : <Value>no match</Value>}
                    <div className="text-2xs text-ink-500">
                      truth {lastEvent.data.true_matches?.length
                        ? lastEvent.data.true_matches.map((x) => `#${x}`).join(", ") : "none"}
                      {" · "}{lastEvent.data.correct ? "correct" : "INCORRECT"}
                    </div>
                  </div>
                ) : <p className="text-2xs text-ink-600">Waiting for a trapdoor.</p>}
              </Panel>

              <Panel title="Attacker" tone="attacker"
                note={attackKind === "public_key" ? "public key only" : `stolen sk_r|${stolenPeriod ?? "?"}`}>
                <div className="flex gap-1.5">
                  {["public_key", "stolen_key"].map((k) => (
                    <button key={k} onClick={() => { setAttackKind(k); setPeriodSel("all"); }}
                      className={`px-2.5 py-1.5 rounded-lg text-2xs ring-1 ring-inset transition-colors ${
                        attackKind === k ? "ring-[#d03b3b]/60 text-[#e55757] bg-signal-red/10"
                                         : "ring-ink-700 text-ink-400 hover:text-ink-200"}`}>
                      {k === "public_key" ? "Public key only" : "Stolen key"}
                    </button>
                  ))}
                </div>
                {attackKind === "stolen_key" && (
                  <Row label="steal">
                    <select value={stolenPeriod ?? ""} className={inputCls}
                      onChange={(e) => { setStolenPeriod(Number(e.target.value)); setPeriodSel("all"); }}>
                      <option value="">choose a period…</option>
                      {periods.map((p) => <option key={p.period} value={p.period}>sk_r|{p.period}</option>)}
                    </select>
                  </Row>
                )}
                <Row label="target">
                  <select value={periodSel} onChange={(e) => setPeriodSel(e.target.value)} className={inputCls}>
                    <option value="all">
                      {eligible.length ? `all reachable (${eligible.join(", ")})` : "none reachable"}
                    </option>
                    {eligible.map((i) => <option key={i} value={i}>period {i}</option>)}
                  </select>
                </Row>
                <label className="flex items-center gap-2 text-2xs text-ink-400">
                  <input type="checkbox" checked={control} onChange={(e) => setControl(e.target.checked)} />
                  garbage key (control — must recover nothing)
                </label>
                <PrimaryButton onClick={launch} disabled={busy != null || !ticked.length}>
                  {busy === "attack" ? "Attacking…" : "Launch attack"}
                </PrimaryButton>
                {attackKind === "stolen_key" && stolenPeriod == null && (
                  <p className="text-2xs text-signal-amber">Choose which period’s key is stolen.</p>
                )}
                {attackKind === "stolen_key" && stolenPeriod != null && (
                  <p className="text-2xs text-ink-600">Backward only — periods before {stolenPeriod}.</p>
                )}
              </Panel>
            </div>
          </div>

          {ORDER.filter((k) => results[k]).map((k) => (
            <AttackResult key={k} res={results[k]} stale={results[k].records_at_run !== cloudRecords.length} />
          ))}
        </>
      )}
    </div>
  );
}
