import { Card, Badge } from "../components/Section";

function ArchDiagram() {
  return (
    <svg viewBox="0 0 720 200" className="w-full h-auto">
      <defs>
        <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
          <path d="M0,0 L6,3 L0,6 Z" fill="#6b7788" />
        </marker>
      </defs>
      {[
        { x: 20, label: "Patient / Sender", sub: "PEKS.Encrypt(pk, w, j)" },
        { x: 200, label: "Cloud storage", sub: "holds CT1, CT2" },
        { x: 380, label: "Blockchain", sub: "Verify(CT, Trap)" },
        { x: 560, label: "Doctor", sub: "sk_rj, Trapdoor(w')" },
      ].map((box, i) => (
        <g key={i}>
          <rect x={box.x} y="70" width="140" height="60" rx="8" fill="#141924" stroke="#242c38" />
          <text x={box.x + 70} y="95" textAnchor="middle" fontSize="12" fill="#e4e9f0">{box.label}</text>
          <text x={box.x + 70} y="112" textAnchor="middle" fontSize="9" fill="#6b7788" fontFamily="monospace">{box.sub}</text>
        </g>
      ))}
      {[20, 200, 380].map((x, i) => (
        <line key={i} x1={x + 140} y1="100" x2={x + 200 - 6} y2="100" stroke="#4a5568" strokeWidth="1.5" markerEnd="url(#arrow)" />
      ))}
      <line x1="700" y1="130" x2="450" y2="150" stroke="#4a5568" strokeWidth="1.5" strokeDasharray="4 3" markerEnd="url(#arrow)" />
      <text x="630" y="170" fontSize="9" fill="#6b7788">doctor submits Trap as a tx →</text>
    </svg>
  );
}

export default function OverviewTab({ goTo }) {
  return (
    <div className="space-y-5 max-w-4xl">
      <Card title="What PPSEB claims">
        <p className="text-sm text-ink-300 leading-relaxed">
          PPSEB (Xu et al., 2022) is a lattice-based (LWE) searchable-encryption scheme for
          e-healthcare records. It adds a time-evolving key ("forward security") and moves the
          search step onto a blockchain for auditability. It claims: (1) postquantum resistance
          to <em>keyword-guessing attacks</em>, (2) <em>forward security</em> — a stolen current
          key must not reveal past keys, and (3) a well-defined key-evolution algorithm.
        </p>
      </Card>

      <Card title="Architecture">
        <ArchDiagram />
      </Card>

      <Card title="Three findings">
        <div className="space-y-3">
          <button onClick={() => goTo("kga")} className="w-full text-left border border-ink-800 hover:border-signal-red/50 rounded-md p-3 transition-colors">
            <div className="flex items-center gap-2"><Badge tone="red">Finding 1</Badge><span className="text-sm font-medium">Keyword-guessing attack breaks the scheme</span></div>
            <p className="text-xs text-ink-400 mt-1.5">
              PEKS.Encrypt and Verify are both PUBLIC algorithms. Anyone holding one captured
              trapdoor (visible on-chain by design) and a guess dictionary can offline-recover the
              searched keyword. LWE hardness and the blockchain are irrelevant — the vulnerability
              is structural to public-key PEKS with a secret-free tester.
            </p>
          </button>
          <button onClick={() => goTo("forward")} className="w-full text-left border border-ink-800 hover:border-amber-500/50 rounded-md p-3 transition-colors">
            <div className="flex items-center gap-2"><Badge tone="amber">Finding 2</Badge><span className="text-sm font-medium">Forward security reduces to a norm question</span></div>
            <p className="text-xs text-ink-400 mt-1.5">
              Consecutive periods are related by a PUBLIC low-norm invertible R. Anyone can compute
              a candidate earlier-period basis from a stolen current basis; whether that candidate
              is actually usable depends entirely on measured Gram-Schmidt norms, not on hardness.
            </p>
          </button>
          <button onClick={() => goTo("spec")} className="w-full text-left border border-ink-800 hover:border-signal-blue/50 rounded-md p-3 transition-colors">
            <div className="flex items-center gap-2"><Badge tone="blue">Finding 3</Badge><span className="text-sm font-medium">Algorithm 2 (KeyExt) is not executable as printed</span></div>
            <p className="text-xs text-ink-400 mt-1.5">
              Two circular dependencies: line 6 uses the public key this algorithm is supposed to
              produce, and line 7 uses the basis it's supposed to produce as its own input. This is
              the certain finding — reproducible, airtight, and fixed by a single-step correction.
            </p>
          </button>
        </div>
      </Card>

      <Card title="What this lab does">
        <p className="text-sm text-ink-300 leading-relaxed">
          This is an ANALYSIS tool, not a reimplementation for production use. It implements a
          faithful, corrected version of the scheme's lattice core at deliberately tiny parameters
          (so every matrix, every step, is visible on screen) and demonstrates all three findings
          live, with a full step-by-step trace of what the backend actually computed — nothing on
          this page is invented or mocked in the frontend.
        </p>
      </Card>
    </div>
  );
}
