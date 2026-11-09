import { useEffect, useState } from "react";
import { api } from "../../api";
import {
  Card, Badge, Stat, PrimaryButton, SecondaryButton, ErrorBanner, Field, inputCls,
} from "../../components/Section";
import { useOp, TraceCard } from "../../components/medvault/shared";

const EVIL_MODES = [
  ["honest", "honest", "serves exactly what was committed"],
  ["stale", "stale", "serves an older version"],
  ["modified", "modified", "flips one byte of the ciphertext"],
  ["withheld", "withheld", "serves nothing"],
];

export default function PatientTab({ session }) {
  const [recordId, setRecordId] = useState("rec-lab");
  const [text, setText] = useState("hba1c 7.4 percent");
  const [keywords, setKeywords] = useState("diabetes, blood");
  const [tag, setTag] = useState("lab");

  const [doctor, setDoctor] = useState("doctor_a");
  const [scopeKind, setScopeKind] = useState("record_tag");
  const [scopeTag, setScopeTag] = useState("lab");
  const [scopeRecords, setScopeRecords] = useState("rec-lab");
  const [expiry, setExpiry] = useState(86400);
  const [breakGlass, setBreakGlass] = useState("");

  const [state, setState] = useState(null);
  const [evil, setEvil] = useState("honest");
  const upload = useOp();
  const grant = useOp();
  const revoke = useOp();

  const refresh = async () => {
    try { setState((await api.mvState()).result); } catch { /* surfaced by the ops */ }
  };
  useEffect(() => { refresh(); }, [session?.seed]);

  const doUpload = async () => {
    const r = await upload.run(() => api.mvUpload({
      record_id: recordId, text,
      keywords: keywords.split(",").map((k) => k.trim()).filter(Boolean),
      tag: tag || null,
    }));
    if (r) refresh();
  };

  const doGrant = async () => {
    const r = await grant.run(() => api.mvGrant({
      doctor_id: doctor,
      scope: scopeKind === "record_tag"
        ? { kind: "record_tag", tag: scopeTag }
        : { kind: "record_set", record_ids: scopeRecords.split(",").map((x) => x.trim()).filter(Boolean) },
      expiry_seconds: Number(expiry),
      break_glass_justification: breakGlass || null,
    }));
    if (r) refresh();
  };

  const doRevoke = async () => {
    const r = await revoke.run(() => api.mvRevoke({ doctor_id: doctor }));
    if (r) refresh();
  };

  const doEvil = async (mode) => {
    await api.mvEvilMode({ mode });
    setEvil(mode);
    refresh();
  };

  return (
    <div className="space-y-4">
      <Card
        title="Patient — its records, its keys, its consent"
        subtitle="MedVault-PQ: a record set committed as one Merkle root, per-doctor per-epoch index keys, and capabilities sealed to each doctor's ML-KEM key."
        actions={
          <>
            <Badge tone="blue">{state?.proof_mode ?? "proof mode…"}</Badge>
            <Badge tone="neutral">{state?.ledger_backend ?? "ledger"}</Badge>
          </>
        }
      >
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <Stat label="Records" value={state?.records?.length ?? "—"} />
          <Stat label="Epoch" value={state?.epoch ?? "—"} hint="bumped by every revocation" />
          <Stat label="Merkle version" value={state?.version ?? "—"} hint="on-chain commit counter" />
          <Stat label="Consent root" value={(state?.consent_root ?? "").slice(0, 8) || "—"} hint="Poseidon root" />
        </div>

        <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-5">
          <div className="space-y-3">
            <div className="text-2xs uppercase tracking-[0.08em] text-ink-500">Upload a record</div>
            <Field label="Record id"><input className={inputCls} value={recordId} onChange={(e) => setRecordId(e.target.value)} /></Field>
            <Field label="Text"><input className={inputCls} value={text} onChange={(e) => setText(e.target.value)} /></Field>
            <Field label="Keywords" hint="comma separated"><input className={inputCls} value={keywords} onChange={(e) => setKeywords(e.target.value)} /></Field>
            <Field label="Tag" hint="what record_tag scopes resolve against"><input className={inputCls} value={tag} onChange={(e) => setTag(e.target.value)} /></Field>
            <PrimaryButton onClick={doUpload} disabled={upload.busy}>
              {upload.busy ? "Encrypting…" : "Encrypt and commit"}
            </PrimaryButton>
            <ErrorBanner message={upload.error} />
          </div>

          <div className="space-y-3">
            <div className="text-2xs uppercase tracking-[0.08em] text-ink-500">Grant a scope</div>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Doctor">
                <select className={inputCls} value={doctor} onChange={(e) => setDoctor(e.target.value)}>
                  <option value="doctor_a">doctor_a</option>
                  <option value="doctor_b">doctor_b</option>
                  <option value="doctor_c">doctor_c</option>
                </select>
              </Field>
              <Field label="Scope kind">
                <select className={inputCls} value={scopeKind} onChange={(e) => setScopeKind(e.target.value)}>
                  <option value="record_tag">record_tag</option>
                  <option value="record_set">record_set</option>
                </select>
              </Field>
            </div>
            {scopeKind === "record_tag"
              ? <Field label="Tag"><input className={inputCls} value={scopeTag} onChange={(e) => setScopeTag(e.target.value)} /></Field>
              : <Field label="Record ids" hint="comma separated"><input className={inputCls} value={scopeRecords} onChange={(e) => setScopeRecords(e.target.value)} /></Field>}
            <div className="grid grid-cols-2 gap-3">
              <Field label="Expiry (seconds)" hint="60 … 31 536 000">
                <input type="number" className={inputCls} value={expiry} onChange={(e) => setExpiry(e.target.value)} />
              </Field>
              <Field label="Break-glass justification" hint="optional, max 1 h">
                <input className={inputCls} value={breakGlass} onChange={(e) => setBreakGlass(e.target.value)} />
              </Field>
            </div>
            <div className="flex gap-2">
              <PrimaryButton onClick={doGrant} disabled={grant.busy}>
                {grant.busy ? "Sealing…" : "Grant and seal capability"}
              </PrimaryButton>
              <SecondaryButton onClick={doRevoke} disabled={revoke.busy}>
                {revoke.busy ? "Revoking…" : "Revoke"}
              </SecondaryButton>
            </div>
            <ErrorBanner message={grant.error || revoke.error} />
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card title="Grants" subtitle="History, not only current state: a revoked grant must still be visible.">
          {state?.grants?.length ? (
            <div className="overflow-x-auto max-h-72">
              <table className="w-full text-[13px]">
                <thead>
                  <tr className="text-left text-2xs uppercase tracking-[0.08em] text-ink-500">
                    <th className="pb-2 pr-3 font-medium">Doctor</th>
                    <th className="pb-2 pr-3 font-medium">Scope</th>
                    <th className="pb-2 pr-3 font-medium">Epoch</th>
                    <th className="pb-2 pr-3 font-medium">Expires</th>
                    <th className="pb-2 font-medium">State</th>
                  </tr>
                </thead>
                <tbody>
                  {state.grants.map((g, i) => (
                    <tr key={`${g.doctor_id}-${i}`} className="border-t border-ink-800/70">
                      <td className="py-1.5 pr-3 mono text-ink-200">{g.doctor_id}</td>
                      <td className="py-1.5 pr-3 text-2xs text-ink-400">{g.scope ?? g.scope_hash?.slice(0, 10)}</td>
                      <td className="py-1.5 pr-3 mono text-ink-400">{g.epoch}</td>
                      <td className="py-1.5 pr-3 mono text-2xs text-ink-500">{g.expiry_seconds}s</td>
                      <td className="py-1.5">
                        <Badge tone={g.revoked ? "red" : g.is_break_glass ? "amber" : "green"}>
                          {g.revoked ? "revoked" : g.is_break_glass ? "break-glass" : "active"}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <p className="text-2xs text-ink-500">No grants yet.</p>}
        </Card>

        <Card title="What the cloud may do to a record" subtitle="Evil-cloud switch: the next retrieval has to survive this, or fail closed.">
          <div className="flex flex-wrap gap-2">
            {EVIL_MODES.map(([value, label, hint]) => (
              <button key={value} type="button" onClick={() => doEvil(value)}
                className={`text-left rounded-lg px-3 py-2 ring-1 ring-inset transition-colors ${
                  evil === value ? "bg-accent/15 ring-accent/40 text-ink-100" : "bg-white/[0.03] ring-ink-800 text-ink-300 hover:bg-white/[0.06]"}`}>
                <div className="text-[13px] font-medium">{label}</div>
                <div className="text-2xs text-ink-500">{hint}</div>
              </button>
            ))}
          </div>
          <p className="text-2xs text-ink-500 mt-3 leading-relaxed">
            Tamper, roll back or withhold a blob, then retrieve it from the Doctor view: the
            version, content hash and Merkle proof are checked before any key is used, so the
            answer is a reason and no plaintext.
          </p>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <TraceCard op={upload} title="Upload trace" />
        <TraceCard op={grant.result ? grant : revoke} title="Grant / revoke trace" />
      </div>
    </div>
  );
}
