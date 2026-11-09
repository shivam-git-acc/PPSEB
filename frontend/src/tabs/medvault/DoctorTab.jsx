import { useEffect, useState } from "react";
import { api } from "../../api";
import {
  Card, Badge, Stat, PrimaryButton, ErrorBanner, Field, inputCls,
} from "../../components/Section";
import { useOp, TraceCard, Verdict, KeyValues } from "../../components/medvault/shared";

export default function DoctorTab() {
  const [doctor, setDoctor] = useState("doctor_a");
  const [keyword, setKeyword] = useState("diabetes");
  const [state, setState] = useState(null);
  const [hits, setHits] = useState([]);
  const [recordId, setRecordId] = useState("");
  const search = useOp();
  const retrieval = useOp();

  const refresh = async () => {
    try { setState((await api.mvState()).result); } catch { /* ops surface errors */ }
  };
  useEffect(() => { refresh(); }, []);

  const doSearch = async () => {
    const r = await search.run(() => api.mvSearch({ doctor_id: doctor, keyword }));
    refresh();
    if (r) {
      setHits(r.record_ids ?? []);
      setRecordId((r.record_ids ?? [])[0] ?? "");
    }
  };

  const doRetrieve = async () => {
    if (!recordId) return;
    await retrieval.run(() => api.mvRetrieve({ doctor_id: doctor, record_id: recordId }));
    refresh();
  };

  const agent = state?.doctors?.find((d) => d.doctor_id === doctor);
  const result = search.result;
  const got = retrieval.result;

  return (
    <div className="space-y-4">
      <Card
        title="Doctor — ask for a keyword, get only what consent covers"
        subtitle="Mode B gates every request: signature, epoch, nonce, scope, then the zero-knowledge authorisation proof."
        actions={<Badge tone={result?.ok ? "green" : result ? "red" : "neutral"}>
          {result ? (result.ok ? "accepted" : result.reason) : "idle"}
        </Badge>}
      >
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          <div className="space-y-3">
            <Field label="Doctor">
              <select className={inputCls} value={doctor} onChange={(e) => setDoctor(e.target.value)}>
                <option value="doctor_a">doctor_a</option>
                <option value="doctor_b">doctor_b</option>
                <option value="doctor_c">doctor_c</option>
              </select>
            </Field>
            <Field label="Keyword"><input className={inputCls} value={keyword} onChange={(e) => setKeyword(e.target.value)} /></Field>
            <PrimaryButton onClick={doSearch} disabled={search.busy}>
              {search.busy ? "Searching…" : "Search"}
            </PrimaryButton>
            <ErrorBanner message={search.error} />
            {agent && (
              <div className="text-2xs text-ink-500 leading-relaxed border-t border-ink-800 pt-3">
                capability epoch <span className="mono text-ink-300">{agent.capability_epoch ?? "—"}</span> ·
                envelope epoch <span className="mono text-ink-300">{agent.envelope_epoch ?? "—"}</span> ·
                nonces used <span className="mono text-ink-300">{agent.nonce_counter}</span>
              </div>
            )}
          </div>

          <div className="lg:col-span-2">
            <div className="flex items-center gap-2 flex-wrap mb-3">
              <span className="text-2xs uppercase tracking-[0.08em] text-ink-500">Matched</span>
              {hits.length === 0 && <span className="text-2xs text-ink-600">nothing yet</span>}
              {hits.map((id) => (
                <button key={id} type="button" onClick={() => setRecordId(id)}
                  className={`mono text-2xs px-2 py-1 rounded-md ring-1 ring-inset ${
                    recordId === id ? "bg-accent/15 ring-accent/40 text-ink-100"
                      : "bg-white/[0.04] ring-ink-700 text-ink-300"}`}>
                  {id}
                </button>
              ))}
            </div>
            <div className="flex items-end gap-3">
              <div className="flex-1">
                <Field label="Record id to retrieve">
                  <input className={inputCls} value={recordId} onChange={(e) => setRecordId(e.target.value)} />
                </Field>
              </div>
              <PrimaryButton onClick={doRetrieve} disabled={retrieval.busy || !recordId}>
                {retrieval.busy ? "Verifying…" : "Retrieve"}
              </PrimaryButton>
            </div>
            <ErrorBanner message={retrieval.error} />

            {got && (
              <div className="mt-4 rounded-lg bg-white/[0.03] ring-1 ring-inset ring-ink-800 p-4">
                <Verdict ok={got.ok}>
                  {got.ok ? `decrypted after integrity checks (${got.version})` : `refused: ${got.reason}`}
                </Verdict>
                {got.plaintext && (
                  <div className="mt-2 mono text-[13px] text-ink-100 bg-ink-950/60 rounded-md px-3 py-2">
                    {got.plaintext}
                  </div>
                )}
                {got.pir && (
                  <div className="mt-3">
                    <div className="text-2xs uppercase tracking-[0.08em] text-ink-500 mb-1">
                      Private retrieval (LWE PIR)
                    </div>
                    <KeyValues entries={{
                      query_bytes: got.pir.query_bytes,
                      answer_bytes: got.pir.answer_bytes,
                      hint_bytes: got.pir.hint_bytes,
                      db_rows: got.pir.db_rows,
                    }} />
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <TraceCard op={search} title="Search trace" subtitle="Every gate is its own step: the rejection reason is the demo." />
        <TraceCard op={retrieval} title="Retrieval trace" subtitle="Version → content hash → Merkle proof → root → decrypt." />
      </div>

      {result && !result.ok && (
        <Card title="Why this was refused">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <Stat label="Reason" value={result.reason} tone="break" />
            <Stat label="Epoch asked" value={result.epoch} />
            <Stat label="Nonce" value={result.nonce} />
            <Stat label="Mode" value={result.mode} />
          </div>
        </Card>
      )}
    </div>
  );
}
