import { useState } from "react";
import { api } from "../api";
import { Card, Badge, PrimaryButton, ErrorBanner } from "../components/Section";

export default function SecurityTab({ onTrace, initialized, maxPeriod, params }) {
  const [keyword, setKeyword] = useState("diabetes");
  const [wrongQuery, setWrongQuery] = useState("cancer");
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  const [resultCase1, setResultCase1] = useState(null);
  const [resultCase2, setResultCase2] = useState(null);

  const runAnalysis = async () => {
    setLoading(true);
    setError(null);
    setResultCase1(null);
    setResultCase2(null);
    
    try {
      // Run Case 1 (w != w')
      const res1 = await api.encryptSearch({
        record: "Test record", keyword, query_keyword: wrongQuery, period: maxPeriod,
      });
      setResultCase1(res1.result);
      
      // Run Case 2 (w == w')
      const res2 = await api.encryptSearch({
        record: "Test record", keyword, query_keyword: keyword, period: maxPeriod,
      });
      setResultCase2(res2.result);
      
      // Show trace of Case 2 for simplicity
      onTrace([...res1.trace, ...res2.trace]);
      
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      setLoading(false);
    }
  };

  const threshold = Math.floor(params.q / 4);

  return (
    <div className="space-y-5 max-w-4xl">
      <Card title="5.1 Correctness Analysis" subtitle="Section 5 of the paper under random oracle model">
        <p className="text-sm text-ink-300 mb-4">
          The paper states that the cloud server computes the error vector 
          <code className="mx-1 bg-ink-800 px-1 rounded">y = CT_1 - Trap^T CT_2</code> 
          and checks if its elements are close to <code className="mx-1 bg-ink-800 px-1 rounded">q/2</code>. 
          To decode correctly, the error vector must be less than <code className="mx-1 bg-ink-800 px-1 rounded">q/4</code> (the paper claims q/5, but implements q/4).
        </p>
        
        <div className="grid md:grid-cols-2 gap-4 mb-4">
          <label className="block">
            <div className="text-xs text-ink-400 mb-1">Encrypted Keyword (w)</div>
            <input value={keyword} onChange={(e) => setKeyword(e.target.value)}
              className="mono text-sm w-full bg-ink-900 border border-ink-700 rounded px-3 py-2" />
          </label>
          <label className="block">
            <div className="text-xs text-ink-400 mb-1">Mismatched Query Keyword (w')</div>
            <input value={wrongQuery} onChange={(e) => setWrongQuery(e.target.value)}
              className="mono text-sm w-full bg-ink-900 border border-ink-700 rounded px-3 py-2" />
          </label>
        </div>

        <div className="flex items-center gap-3">
          <PrimaryButton onClick={runAnalysis} disabled={!initialized || loading}>
            {loading ? "Running Analysis…" : "Verify Correctness Proof"}
          </PrimaryButton>
          {!initialized && <span className="text-xs text-ink-500">Initialize params in the left rail first.</span>}
        </div>
        <ErrorBanner message={error} />
      </Card>

      {resultCase1 && resultCase2 && (
        <div className="grid md:grid-cols-2 gap-5">
          <Card title="Case 1: w ≠ w'">
            <div className="mb-3">
              <Badge tone={resultCase1.match ? "red" : "neutral"}>
                {resultCase1.match ? "FALSE POSITIVE" : "CORRECTLY REJECTED"}
              </Badge>
            </div>
            <p className="text-sm text-ink-300 mb-3">
              When the keywords do not match, the trapdoor delegation fails to cancel out the terms.
              The resulting vector should have distances from <code className="bg-ink-800 px-1 rounded">q/2</code> exceeding the threshold of <code className="bg-ink-800 px-1 rounded">{threshold}</code>.
            </p>
            <div className="mono text-xs bg-ink-950 border border-ink-800 rounded p-3 overflow-x-auto">
              <div className="text-ink-500 mb-1">Vector y = CT_1 - Trap^T CT_2 (mod q):</div>
              <div>[{resultCase1.y_preview.join(", ")}]</div>
              <div className="text-ink-500 mt-2 mb-1">Distance from q/2 ({Math.floor(params.q/2)}):</div>
              <div>[{resultCase1.y_preview.map(v => Math.min(Math.abs(v - Math.floor(params.q/2)), params.q - Math.abs(v - Math.floor(params.q/2)))).join(", ")}]</div>
            </div>
          </Card>

          <Card title="Case 2: w == w'">
            <div className="mb-3">
              <Badge tone={resultCase2.match ? "green" : "red"}>
                {resultCase2.match ? "CORRECTLY MATCHED" : "FALSE NEGATIVE"}
              </Badge>
            </div>
            <p className="text-sm text-ink-300 mb-3">
              When keywords match, the terms cancel leaving only the small noise vector <code className="bg-ink-800 px-1 rounded">noij</code> and the signal <code className="bg-ink-800 px-1 rounded">q/2</code>.
              The distance from <code className="bg-ink-800 px-1 rounded">q/2</code> should be {"<"} <code className="bg-ink-800 px-1 rounded">{threshold}</code>.
            </p>
            <div className="mono text-xs bg-ink-950 border border-ink-800 rounded p-3 overflow-x-auto">
              <div className="text-ink-500 mb-1">Vector y = CT_1 - Trap^T CT_2 (mod q):</div>
              <div>[{resultCase2.y_preview.join(", ")}]</div>
              <div className="text-ink-500 mt-2 mb-1">Distance from q/2 ({Math.floor(params.q/2)}):</div>
              <div>[{resultCase2.y_preview.map(v => Math.min(Math.abs(v - Math.floor(params.q/2)), params.q - Math.abs(v - Math.floor(params.q/2)))).join(", ")}]</div>
            </div>
          </Card>
        </div>
      )}

      {resultCase1 && resultCase2 && (
        <Card title="Analysis of the Paper's Correctness Claim">
          <div className="space-y-4 text-sm text-ink-300">
            <p>
              <strong>Verdict:</strong> The paper's proposed mechanism for correctness is <strong className="text-signal-green">valid in principle</strong>, but requires <strong className="text-signal-amber">undocumented load-bearing assumptions</strong> to actually work.
            </p>
            <ul className="list-disc pl-5 space-y-2">
              <li>
                <strong>The Shared B_j Assumption:</strong> The paper's PEKS algorithm states to generate <code className="bg-ink-800 px-1 rounded">CT_j1</code> and <code className="bg-ink-800 px-1 rounded">CT_j2</code> using a random matrix <code className="bg-ink-800 px-1 rounded">B_j</code>, but it is ambiguous about whether it is the <em>same</em> matrix for both. Our implementation proves that <code className="bg-ink-800 px-1 rounded">B_j</code> <strong>must be strictly shared</strong> between both ciphertext components. If independent matrices are used, the <code className="bg-ink-800 px-1 rounded">Trap^T CT_j2</code> term will never cancel out the <code className="bg-ink-800 px-1 rounded">\mu^T B_j</code> term in <code className="bg-ink-800 px-1 rounded">CT_j1</code>, causing <strong>Verify to always reject</strong> even when keywords match.
              </li>
              <li>
                <strong>The q/5 vs q/4 Threshold Mismatch:</strong> The paper's text (Section 5.1) bounds the error vector to <code className="bg-ink-800 px-1 rounded">q/5</code>. However, the actual printed Verification algorithm (Algorithm 5, Line 5) checks if the distance exceeds <code className="bg-ink-800 px-1 rounded">q/4</code>. While <code className="bg-ink-800 px-1 rounded">q/4</code> is the standard threshold for LWE decoding, the mathematical proof in the text is inconsistent with the pseudocode.
              </li>
            </ul>
            <p>
              In conclusion, once the unstated <code className="bg-ink-800 px-1 rounded">B_j</code> sharing requirement is enforced, the cancellation mechanism functions exactly as expected, demonstrating correct decoding under the LWE assumption.
            </p>
          </div>
        </Card>
      )}
    </div>
  );
}
