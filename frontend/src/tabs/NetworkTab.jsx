import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import { Card, Badge, PrimaryButton, SecondaryButton, ErrorBanner } from "../components/Section";

const NODES = {
  doctor: { x: 40, y: 30, w: 150, h: 54, label: "DOCTOR", sub: "holds sk_r|j" },
  cloud: { x: 285, y: 30, w: 150, h: 54, label: "CLOUD", sub: "stores blobs" },
  verifier: { x: 530, y: 30, w: 150, h: 54, label: "VERIFIER", sub: "public Verify" },
  attacker: { x: 285, y: 160, w: 150, h: 54, label: "ATTACKER", sub: "no sk (or one)" },
};
const EDGES = {
  "doctor->cloud": ["doctor", "cloud"],
  "cloud->doctor": ["cloud", "doctor"],
  "doctor->verifier->doctor": ["doctor", "verifier"],
  "cloud->verifier": ["cloud", "verifier"],
  "attacker->cloud": ["attacker", "cloud"],
  attack: ["attacker", "cloud"],
  doctor: ["doctor", "doctor"],
};

function centre(id) {
  const n = NODES[id];
  return { cx: n.x + n.w / 2, cy: n.y + n.h / 2 };
}

function NetworkDiagram({ activeEdge, pulse, periodLabel, cloudCount, attackerHolds }) {
  const [from, to] = EDGES[activeEdge] ?? [];
  const a = from && centre(from);
  const b = to && centre(to);
  const moving = a && b && from !== to;
  return (
    <svg viewBox="0 0 720 240" className="w-full" style={{ maxHeight: 260 }}>
      <defs>
        <marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
          <path d="M0,0 L8,4 L0,8 z" fill="#4b4b55" />
        </marker>
      </defs>
      {[["doctor", "cloud"], ["cloud", "verifier"]].map(([f, t]) => {
        const p = centre(f); const r = centre(t);
        return <line key={`${f}${t}`} x1={p.cx + 75} y1={p.cy} x2={r.cx - 78} y2={r.cy}
          stroke="#2a2a30" strokeWidth="2" markerEnd="url(#arrow)" />;
      })}
      <line x1={centre("attacker").cx} y1={centre("attacker").cy - 27}
        x2={centre("cloud").cx} y2={centre("cloud").cy + 27}
        stroke="#3a2a2a" strokeWidth="2" strokeDasharray="5 4" />
      <line x1={centre("attacker").cx + 75} y1={centre("attacker").cy}
        x2={centre("verifier").cx} y2={centre("verifier").cy + 27}
        stroke="#3a2a2a" strokeWidth="2" strokeDasharray="5 4" />
      <text x={centre("attacker").cx + 90} y={centre("attacker").cy - 34} fill="#6b6b76" fontSize="10">
        taps public data
      </text>

      {Object.entries(NODES).map(([id, n]) => {
        const activeNode = from === id || to === id;
        return (
          <g key={id}>
            <rect x={n.x} y={n.y} width={n.w} height={n.h} rx="7"
              fill={activeNode ? "#1d2430" : "#16161a"}
              stroke={activeNode ? "#5b9dff" : id === "attacker" ? "#6b2426" : "#2a2a30"} strokeWidth="1.5" />
            <text x={n.x + 12} y={n.y + 22} fill="#e5e5ea" fontSize="12" fontWeight="600">{n.label}</text>
            <text x={n.x + 12} y={n.y + 40} fill="#8a8a94" fontSize="10">
              {id === "doctor" ? periodLabel : id === "cloud" ? `${cloudCount} blob${cloudCount === 1 ? "" : "s"}`
                : id === "attacker" ? attackerHolds : n.sub}
            </text>
          </g>
        );
      })}

      {moving && (
        <circle key={pulse} r="5" fill="#5b9dff">
          <animate attributeName="cx" from={a.cx} to={b.cx} dur="0.9s" fill="freeze" />
          <animate attributeName="cy" from={a.cy} to={b.cy} dur="0.9s" fill="freeze" />
          <animate attributeName="opacity" from="1" to="0" dur="0.9s" fill="freeze" />
        </circle>
      )}
    </svg>
  );
}

function Node({ title, tone = "ink", children, footer }) {
  const border = tone === "attacker" ? "border-signal-red/40" : "border-ink-800";
  return (
    <div className={`border ${border} rounded-lg bg-ink-900/40 flex flex-col`}>
      <div className="px-3 py-2 border-b border-ink-800 text-xs font-medium text-ink-100 uppercase tracking-wide">
        {title}
      </div>
      <div className="p-3 text-xs space-y-2 flex-1">{children}</div>
      {footer && <div className="px-3 py-2 border-t border-ink-800 text-[11px] text-ink-500">{footer}</div>}
    </div>
  );
}

const input = "mono text-xs bg-ink-900 border border-ink-700 rounded px-2 py-1.5";

// Building a session costs a TrapGen plus the noise calibration, so a tab
// switch reattaches to the live one instead of throwing the cloud away.
let cachedSessionId = null;

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
  const [attackRes, setAttackRes] = useState(null);
  const [script, setScript] = useState(null);

  const [keyword, setKeyword] = useState("diabetes");
  const [text, setText] = useState("Patient A: insulin started");
  const [query, setQuery] = useState("diabetes");
  const [decryptId, setDecryptId] = useState(0);

  const [attackKind, setAttackKind] = useState("public_key");
  const [stolenPeriod, setStolenPeriod] = useState(null);
  const [ticked, setTicked] = useState([]);
  const [control, setControl] = useState(false);
  const cancelScript = useRef(false);

  const dict = state?.dictionary ?? [];
  const periods = state?.periods ?? [];
  const cloudRecords = useMemo(() => periods.flatMap((p) => p.records), [periods]);
  const available = state?.available;

  const apply = useCallback(async (nn = n, qq = q) => {
    setBusy("rebuild"); setError(null); setAttackRes(null);
    try {
      const r = await api.networkNew({ n: Number(nn), q: Number(qq) });
      cachedSessionId = r.result.state.session_id;
      setState(r.result.state);
      setTicked([]); setStolenPeriod(null);
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
    if (r) setAttackRes(r.result);
    return r;
  };

  const tickable = (p) => attackKind === "public_key" || (stolenPeriod != null && p < stolenPeriod);
  const toggleTick = (p) => setTicked((t) => (t.includes(p) ? t.filter((x) => x !== p) : [...t, p]));

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
      setState(s); setAttackRes(null); setTicked([]);
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
        setAttackKind("public_key"); setTicked([0, 1, 2]);
        setActiveEdge("attack"); setPulse((p) => p + 1);
        const r = await api.networkAttack({ session_id: sid, kind: "public_key", periods: [0, 1, 2] });
        setState(r.result.state); setAttackRes(r.result); onTrace?.(r.trace, "Network");
      });
      await step("5/6 — attacker steals the period-2 key, reaches back to 0 and 1", async () => {
        setAttackKind("stolen_key"); setStolenPeriod(2); setTicked([0, 1]);
        setActiveEdge("attack"); setPulse((p) => p + 1);
        const r = await api.networkAttack({ session_id: sid, kind: "stolen_key", periods: [0, 1], stolen_period: 2 });
        setState(r.result.state); setAttackRes(r.result); onTrace?.(r.trace, "Network");
      });
      await step("6/6 — negative control: a garbage key must recover nothing", async () => {
        setControl(true);
        const r = await api.networkAttack({ session_id: sid, kind: "public_key", periods: [0], control: true });
        setState(r.result.state); setAttackRes(r.result); onTrace?.(r.trace, "Network");
        setControl(false);
      });
      setScript("done — the whole story, every value measured live");
    } catch (e) {
      if (String(e.message) !== "cancelled") setError(String(e.message || e));
      setScript(null);
    }
  };

  return (
    <div className="space-y-5 max-w-6xl">
      <Card title="Network" subtitle="Doctor, cloud, verifier and attacker as live nodes — drive the scheme and attack it">
        <div className="flex flex-wrap items-end gap-3 text-xs">
          <label className="block"><div className="text-ink-400 mb-1">n</div>
            <select value={n} onChange={(e) => setN(e.target.value)} className={input}>
              {(options?.n_choices ?? [4, 8, 16]).map((v) => <option key={v} value={v}>{v}</option>)}
            </select></label>
          <label className="block"><div className="text-ink-400 mb-1">q</div>
            <select value={q} onChange={(e) => setQ(e.target.value)} className={input}>
              {(options?.q_choices ?? [257]).map((v) => <option key={v} value={v}>{v}</option>)}
            </select></label>
          <div><div className="text-ink-400 mb-1">m (derived)</div>
            <div className="mono text-ink-200 px-2 py-1.5">{chosen?.m ?? state?.m ?? "—"}</div></div>
          <PrimaryButton onClick={() => apply()} disabled={busy != null || chosen?.available === false}>
            {busy === "rebuild" ? "Rebuilding…" : "Apply / rebuild"}
          </PrimaryButton>
          <SecondaryButton onClick={runScript} disabled={busy != null}>Run demo script</SecondaryButton>
          {state?.n === 4 && state?.q === 257 && <Badge tone="blue">paper's demo parameters</Badge>}
        </div>
        {chosen?.available === false && (
          <div className="text-xs text-amber-400 mt-2">
            Not available at n={n}, q={q}: {chosen.reason}
          </div>
        )}
        <p className="text-[11px] text-ink-500 mt-2 leading-relaxed">{options?.note}</p>
        <ErrorBanner message={error} />
        {state && !available && (
          <div className="text-xs text-amber-400 bg-amber-500/10 border border-amber-600/30 rounded px-3 py-2 mt-2">
            ⚠ {state.unavailable_reason}
          </div>
        )}
        {script && <div className="text-xs text-signal-blue mt-2">▶ {script}</div>}
      </Card>

      {state && available && (
        <>
          <Card title="Live network">
            <NetworkDiagram activeEdge={activeEdge} pulse={pulse}
              periodLabel={`period ${state.current_period} · pk ${periods[state.current_period]?.pk_fingerprint}`}
              cloudCount={cloudRecords.length}
              attackerHolds={attackKind === "public_key" ? "public key only" : `stolen sk_r|${stolenPeriod ?? "?"}`} />
            {lastEvent && (
              <div className="text-xs text-ink-300 mono border-t border-ink-800 pt-2 mt-1">
                {lastEvent.label}
                {lastEvent.data?.plaintext && <span className="text-signal-green"> → “{lastEvent.data.plaintext}”</span>}
                {lastEvent.data?.forward_security_note && (
                  <div className="text-[11px] text-amber-400 mt-1">{lastEvent.data.forward_security_note}</div>
                )}
              </div>
            )}
          </Card>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <Node title="Doctor"
              footer={`n=${state.n} · q=${state.q} · m=${state.m} · period ${state.current_period} · pk ${periods[state.current_period]?.pk_fingerprint}`}>
              <div className="space-y-1">
                <div className="text-ink-400">Add a record</div>
                <div className="flex gap-1.5">
                  <select value={keyword} onChange={(e) => setKeyword(e.target.value)} className={`${input} flex-1`}>
                    {dict.map((d) => <option key={d} value={d}>{d}</option>)}
                  </select>
                </div>
                <input value={text} onChange={(e) => setText(e.target.value)}
                  className={`${input} w-full`} placeholder="record text" />
                <SecondaryButton onClick={addRecord} disabled={busy != null}>Encrypt → cloud</SecondaryButton>
              </div>
              <div className="space-y-1 pt-2 border-t border-ink-800">
                <div className="text-ink-400">Search</div>
                <div className="flex gap-1.5">
                  <select value={query} onChange={(e) => setQuery(e.target.value)} className={`${input} flex-1`}>
                    {dict.map((d) => <option key={d} value={d}>{d}</option>)}
                  </select>
                  <SecondaryButton onClick={doSearch} disabled={busy != null}>Trapdoor →</SecondaryButton>
                </div>
              </div>
              <div className="space-y-1 pt-2 border-t border-ink-800">
                <div className="text-ink-400">Decrypt a stored record</div>
                <div className="flex gap-1.5">
                  <select value={decryptId} onChange={(e) => setDecryptId(e.target.value)} className={`${input} flex-1`}>
                    {cloudRecords.map((r) => <option key={r.record_id} value={r.record_id}>#{r.record_id} (period {r.period})</option>)}
                  </select>
                  <SecondaryButton onClick={decrypt} disabled={busy != null || !cloudRecords.length}>Decrypt</SecondaryButton>
                </div>
              </div>
              <div className="pt-2 border-t border-ink-800">
                <SecondaryButton onClick={advance} disabled={busy != null}>Advance period (KeyExt)</SecondaryButton>
              </div>
            </Node>

            <Node title="Cloud" footer="Dumb storage: it holds blobs and returns them. It learns nothing.">
              {cloudRecords.length === 0 && <div className="text-ink-500">empty — the doctor has stored nothing yet</div>}
              {cloudRecords.length > 0 && (
                <table className="w-full mono text-[11px]">
                  <thead><tr className="text-left text-ink-500">
                    <th className="pb-1 pr-2">j</th><th className="pb-1 pr-2">rec</th>
                    <th className="pb-1 pr-2">CT</th><th className="pb-1 pr-2">CM</th><th className="pb-1">bits</th>
                  </tr></thead>
                  <tbody>
                    {cloudRecords.map((r) => (
                      <tr key={r.record_id} className="border-t border-ink-800 text-ink-300">
                        <td className="py-1 pr-2">{r.period}</td>
                        <td className="py-1 pr-2">#{r.record_id}</td>
                        <td className="py-1 pr-2 text-ink-500">{r.ct_fingerprint}</td>
                        <td className="py-1 pr-2 text-ink-500">{r.cm_fingerprint}</td>
                        <td className="py-1">{r.cm_bits}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Node>

            <Node title="Verifier (blockchain)"
              footer="Verify uses NO secret — anyone can run it. That is what makes both attacks possible.">
              {lastEvent?.data?.N0 !== undefined && lastEvent.edge === "doctor->verifier->doctor" ? (
                <div className="space-y-1">
                  <div className="text-ink-400">last trapdoor</div>
                  <div className="mono text-ink-200">{lastEvent.data.keyword} @ period {lastEvent.data.period}</div>
                  <div className="mono">
                    {lastEvent.data.N0 != null
                      ? <span className="text-signal-green">match → record #{lastEvent.data.N0}</span>
                      : <span className="text-ink-400">no match</span>}
                  </div>
                  <div className="text-[11px] text-ink-500">
                    true matches: {lastEvent.data.true_matches?.length ? lastEvent.data.true_matches.map((x) => `#${x}`).join(", ") : "none"} ·{" "}
                    {lastEvent.data.correct ? "correct" : "INCORRECT"}
                  </div>
                </div>
              ) : <div className="text-ink-500">waiting for a trapdoor</div>}
            </Node>
          </div>

          <Card title="Attacker" className="border-signal-red/30">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-3 text-xs">
                <div className="flex gap-2 items-center">
                  {["public_key", "stolen_key"].map((k) => (
                    <button key={k} onClick={() => { setAttackKind(k); setTicked([]); }}
                      className={`px-2.5 py-1.5 rounded border text-xs ${attackKind === k
                        ? "border-signal-red text-signal-red bg-signal-red/10" : "border-ink-700 text-ink-400"}`}>
                      {k === "public_key" ? "Public-key only" : "Stolen key"}
                    </button>
                  ))}
                  {attackKind === "stolen_key" && (
                    <select value={stolenPeriod ?? ""} onChange={(e) => { setStolenPeriod(Number(e.target.value)); setTicked([]); }}
                      className={input}>
                      <option value="">steal which period?</option>
                      {periods.map((p) => <option key={p.period} value={p.period}>steal sk_r|{p.period}</option>)}
                    </select>
                  )}
                </div>
                <div>
                  <div className="text-ink-400 mb-1">attack which periods?</div>
                  <div className="flex gap-3 flex-wrap">
                    {periods.map((p) => {
                      const ok = tickable(p.period);
                      return (
                        <label key={p.period}
                          title={ok ? "" : "can't reach forward — a stolen key only reaches earlier periods"}
                          className={`flex items-center gap-1.5 ${ok ? "text-ink-300" : "text-ink-600 cursor-not-allowed"}`}>
                          <input type="checkbox" disabled={!ok} checked={ticked.includes(p.period)}
                            onChange={() => toggleTick(p.period)} />
                          period {p.period}
                        </label>
                      );
                    })}
                  </div>
                </div>
                <label className="flex items-center gap-2 text-ink-300">
                  <input type="checkbox" checked={control} onChange={(e) => setControl(e.target.checked)} />
                  use a garbage key (negative control — must recover nothing)
                </label>
                <PrimaryButton onClick={launch} disabled={busy != null || !ticked.length}>
                  {busy === "attack" ? "Attacking…" : "Launch attack"}
                </PrimaryButton>
              </div>
              <div className="text-xs">
                <div className="text-ink-500 uppercase text-[10px] mb-2">what the attacker holds</div>
                <div className="text-signal-green mb-1">✓ the cloud's stored ciphertexts (public)</div>
                <div className="text-signal-green mb-1">✓ pk_r|i and the R matrices (public)</div>
                <div className="text-signal-green mb-1">✓ mu (public parameter)</div>
                <div className="text-signal-green mb-1">✓ the disease dictionary (public knowledge)</div>
                {attackKind === "stolen_key" && stolenPeriod != null && (
                  <div className="text-amber-400 mb-1">⚠ sk_r|{stolenPeriod} — the one stolen secret</div>
                )}
                <div className="text-ink-500 line-through mb-1">🔒 every other period's secret key</div>
                <div className="text-ink-500 line-through mb-1">🔒 record plaintexts and keyword tags</div>
                <div className="text-[11px] text-ink-500 mt-2 leading-relaxed">
                  The attack is handed a period view whose records tuple is empty, so no keyword,
                  plaintext or secret key can reach it through the data.
                </div>
              </div>
            </div>
          </Card>

          {attackRes && (
            <Card title={`Attack result — ${attackRes.control ? "negative control (garbage key)"
              : attackRes.kind === "public_key" ? "public key only" : `stolen sk_r|${attackRes.stolen_period}`}`}>
              {attackRes.periods.map((p) => (
                <div key={p.period} className="mb-4 last:mb-0">
                  <div className="flex items-center gap-2 flex-wrap mb-2">
                    <Badge tone={p.outcome === "recovered" ? "red" : p.outcome === "unmeasured (timeout)" ? "neutral" : "green"}>
                      period {p.period}: {p.outcome} {p.recovered != null && `${p.recovered}/${p.total}`}
                    </Badge>
                    {p.forward_security_break && <Badge tone="amber">★ genuine forward-security break</Badge>}
                    {p.basis_gs != null && (
                      <span className="text-[11px] text-ink-500 mono">
                        attack basis GS {p.basis_gs.toFixed(2)} vs honest {p.honest_gs?.toFixed(2)}
                      </span>
                    )}
                  </div>
                  {p.comparison_note && (
                    <div className={`text-[11px] mb-2 ${p.forward_security_break ? "text-amber-400" : "text-ink-400"}`}>
                      {p.forward_security_break ? "★ " : "↳ "}{p.comparison_note}
                    </div>
                  )}
                  {p.error && <div className="text-[11px] text-signal-red mono">{p.error}</div>}
                  {p.rows?.length > 0 && (
                    <table className="w-full mono text-[11px]">
                      <thead><tr className="text-left text-ink-500">
                        <th className="pb-1 pr-3">record</th><th className="pb-1 pr-3">recovered disease</th>
                        <th className="pb-1 pr-3">true disease</th><th className="pb-1 pr-3">ciphertext</th>
                        <th className="pb-1">plaintext</th>
                      </tr></thead>
                      <tbody>
                        {p.rows.map((r) => (
                          <tr key={r.record_id} className="border-t border-ink-800">
                            <td className="py-1 pr-3 text-ink-400">#{r.record_id}</td>
                            <td className={`py-1 pr-3 ${r.correct ? "text-signal-red" : "text-ink-500"}`}>
                              {r.recovered?.length ? r.recovered.join(", ") : "—"}
                            </td>
                            <td className="py-1 pr-3 text-ink-300">{r.true_disease}</td>
                            <td className="py-1 pr-3 text-ink-500">{r.ciphertext_fetched}</td>
                            <td className="py-1">
                              {r.level3 ? <span className="text-signal-red">“{r.plaintext}”</span>
                                : r.correct ? <span className="text-ink-500">keyword ✓ / plaintext ✗ (decode bound)</span>
                                  : <span className="text-ink-600">—</span>}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                  {p.h2_collisions?.length > 0 && (
                    <div className="text-[11px] text-amber-400 mt-1">
                      Dictionary words sharing an H2 tag ({p.h2_collisions.map((c) => c.join("/")).join("; ")}) cannot be
                      told apart by any searcher, honest or not.
                    </div>
                  )}
                </div>
              ))}
              <div className="text-sm text-ink-200 leading-relaxed border-t border-ink-800 pt-3">
                {attackRes.conclusion}
              </div>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
