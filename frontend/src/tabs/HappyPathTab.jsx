import { useEffect, useState } from "react";
import { api } from "../api";
import { Card, Badge, PrimaryButton, ErrorBanner } from "../components/Section";

const STAGES = ["Patient", "Cloud", "Blockchain", "Doctor"];

export default function HappyPathTab({ onTrace, initialized, maxPeriod }) {
  const [record, setRecord] = useState("Dx: Type 2 diabetes. Metformin 500mg BID.");
  const [keyword, setKeyword] = useState("diabetes");
  const [query, setQuery] = useState("diabetes");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [stage, setStage] = useState(-1);

  useEffect(() => {
    if (!loading) return;
    setStage(0);
    const t1 = setTimeout(() => setStage(1), 350);
    const t2 = setTimeout(() => setStage(2), 700);
    const t3 = setTimeout(() => setStage(3), 1050);
    return () => { clearTimeout(t1); clearTimeout(t2); clearTimeout(t3); };
  }, [loading]);

  const run = async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await api.encryptSearch({
        record, keyword, query_keyword: query, period: maxPeriod,
      });
      setResult(res.result);
      onTrace(res.trace);
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      setTimeout(() => setLoading(false), 1100);
    }
  };

  return (
    <div className="space-y-5 max-w-4xl">
      <Card title="Happy Path" subtitle="Encrypt → PEKS → Trapdoor → Verify → retrieve → Decrypt">
        <div className="grid md:grid-cols-2 gap-4">
          <label className="block">
            <div className="text-xs text-ink-400 mb-1">Medical record</div>
            <textarea value={record} onChange={(e) => setRecord(e.target.value)} rows={3}
              className="mono text-sm w-full bg-ink-900 border border-ink-700 rounded px-3 py-2" />
          </label>
          <div className="space-y-3">
            <label className="block">
              <div className="text-xs text-ink-400 mb-1">Keyword to encrypt with the record</div>
              <input value={keyword} onChange={(e) => setKeyword(e.target.value)}
                className="mono text-sm w-full bg-ink-900 border border-ink-700 rounded px-3 py-2" />
            </label>
            <label className="block">
              <div className="text-xs text-ink-400 mb-1">Query keyword (doctor's search)</div>
              <input value={query} onChange={(e) => setQuery(e.target.value)}
                className="mono text-sm w-full bg-ink-900 border border-ink-700 rounded px-3 py-2" />
            </label>
          </div>
        </div>
        <div className="mt-4 flex items-center gap-3">
          <PrimaryButton onClick={run} disabled={!initialized || loading}>
            {loading ? "Running…" : "Run happy path"}
          </PrimaryButton>
          {!initialized && <span className="text-xs text-ink-500">Initialize params in the left rail first.</span>}
        </div>
        <ErrorBanner message={error} />
      </Card>

      <Card title="Data flow">
        <div className="flex items-center justify-between">
          {STAGES.map((s, i) => (
            <div key={s} className="flex items-center flex-1">
              <div className={`flex-1 text-center py-2 rounded border transition-colors ${
                stage >= i ? "border-signal-blue/60 bg-signal-blue/10 text-ink-100" : "border-ink-800 text-ink-500"
              }`}>
                <div className="text-xs">{s}</div>
              </div>
              {i < STAGES.length - 1 && (
                <div className={`w-6 h-px mx-1 ${stage > i ? "bg-signal-blue" : "bg-ink-800"}`} />
              )}
            </div>
          ))}
        </div>
      </Card>

      {result && (
        <Card title="Result">
          <div className="flex items-center gap-2 mb-3">
            <Badge tone={result.match ? "green" : "neutral"}>
              {result.match ? "MATCH" : "NO MATCH"}
            </Badge>
            <span className="text-sm text-ink-400">
              encrypted keyword "{result.encrypted_keyword}" vs query "{result.query_keyword}" at period {result.period}
            </span>
          </div>
          {result.match ? (
            <div className="mono text-sm bg-ink-950 border border-signal-green/30 rounded p-3">
              <div className="text-ink-500 text-xs mb-1">decrypted record</div>
              {result.decrypted_record}
            </div>
          ) : (
            <div className="text-sm text-ink-400">Verify correctly rejected — no record retrieved.</div>
          )}
        </Card>
      )}
    </div>
  );
}
