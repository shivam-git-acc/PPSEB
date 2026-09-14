import { useState } from "react";
import { api } from "../api";
import { Card, Badge, PrimaryButton, SecondaryButton, ErrorBanner } from "../components/Section";

const LINE_6 = "R = H1(pk_rj, j)";
const LINE_7 = "sk_rj = NewBasisDel(pk_rj, R, sk_rj, sigma)";

export default function SpecDefectTab({ onTrace, initialized }) {
  const [periods, setPeriods] = useState(3);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [showPaper, setShowPaper] = useState(false);
  const [showCorrected, setShowCorrected] = useState(false);

  const ensureResult = async () => {
    if (result) return result;
    setLoading(true);
    setError(null);
    try {
      const res = await api.attackSpec({ periods });
      setResult(res.result);
      onTrace(res.trace);
      return res.result;
    } catch (e) {
      setError(String(e.message || e));
      return null;
    } finally {
      setLoading(false);
    }
  };

  const runPaper = async () => {
    const r = await ensureResult();
    if (r) setShowPaper(true);
  };
  const runCorrected = async () => {
    const r = await ensureResult();
    if (r) setShowCorrected(true);
  };

  const reset = () => {
    setResult(null);
    setShowPaper(false);
    setShowCorrected(false);
  };

  return (
    <div className="space-y-5 max-w-4xl">
      <Card title="Algorithm 2 (KeyExt), as printed" subtitle="Two lines reference variables that do not exist yet.">
        <div className="mono text-xs bg-ink-950 border border-ink-800 rounded p-3 space-y-1">
          <div><span className="text-ink-600">line 6:  </span><span className="text-amber-400">{LINE_6}</span></div>
          <div><span className="text-ink-600">line 7:  </span><span className="text-amber-400">{LINE_7}</span></div>
        </div>
      </Card>

      <Card title="Three-way justification for the fix">
        <ul className="text-sm text-ink-300 space-y-2 list-disc pl-5">
          <li><b className="text-ink-100">Input list:</b> Algorithm 2's own stated inputs are (j, pk_r{"{j-1}"}, sk_r{"{j-1}"}, params) — pk_rj and sk_rj aren't among them.</li>
          <li><b className="text-ink-100">Lemma 5 signature:</b> NewBasisDel(A, R, T_A, sigma) takes a SOURCE basis of an EXISTING lattice — it delegates FROM a basis you already have, never consumes its own output.</li>
          <li><b className="text-ink-100">Algorithm 4 analogy:</b> the paper's own Trapdoor algorithm calls NewBasisDel(pk_rj, beta, sk_rj, sigma) using the CURRENT, already-established pk_rj/sk_rj — confirming Algorithm 2's self-reference is a transcription error.</li>
        </ul>
      </Card>

      <Card title="Run the comparison" subtitle="Periods to chain for the corrected version">
        <div className="flex items-center gap-3 flex-wrap">
          <input
            type="number" min={1} max={10} value={periods}
            onChange={(e) => { setPeriods(Number(e.target.value)); reset(); }}
            className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-20"
          />
          <PrimaryButton onClick={runPaper} disabled={!initialized || loading}>
            {loading ? "Running…" : "Run paper version"}
          </PrimaryButton>
          <SecondaryButton onClick={runCorrected} disabled={!initialized || loading}>
            {loading ? "Running…" : "Run corrected version"}
          </SecondaryButton>
        </div>
        {!initialized && <div className="text-xs text-ink-500 mt-2">Initialize params in the left rail first.</div>}
        <ErrorBanner message={error} />
      </Card>

      <div className="grid md:grid-cols-2 gap-4">
        <Card title="Paper version" subtitle="executed literally, in order">
          {!showPaper ? (
            <div className="text-xs text-ink-500">Press "Run paper version" above.</div>
          ) : (
            <div className="space-y-2">
              <Badge tone="red">NOT EXECUTABLE</Badge>
              {Object.entries(result.paper.failures).map(([line, err]) => (
                <div key={line} className="mono text-xs bg-ink-950 border border-signal-red/30 rounded p-2">
                  <div className="text-ink-500">{line.replace("_", " ")}</div>
                  <div className="text-signal-red">{err.type}: {err.message}</div>
                </div>
              ))}
            </div>
          )}
        </Card>
        <Card title="Corrected version" subtitle="single-step, non-circular">
          {!showCorrected ? (
            <div className="text-xs text-ink-500">Press "Run corrected version" above.</div>
          ) : (
            <div className="space-y-2">
              <Badge tone={result.corrected.success ? "green" : "red"}>
                {result.corrected.success ? "VALID KEY CHAIN" : "INVALID"}
              </Badge>
              <div className="mono text-[11px] space-y-1">
                {result.corrected.chain.map((c) => (
                  <div key={c.period} className="flex justify-between border-b border-ink-800/60 pb-1">
                    <span className="text-ink-400">period {c.period}</span>
                    <span className={c.valid ? "text-signal-green" : "text-signal-red"}>
                      A·T≡0: {String(c.valid)} · ‖T̃‖={c.sk_gram_schmidt_norm.toFixed(2)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
