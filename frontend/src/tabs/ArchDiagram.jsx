/* PPSEB as it actually runs.
 *
 * The old drawing was a straight chain Patient -> Cloud -> Blockchain ->
 * Doctor, which is not the protocol: the doctor is not downstream of the
 * chain, it DRIVES it. Two paths meet at the cloud:
 *
 *   write   patient/doctor --PEKS(w), Enc(record)-->  cloud
 *   search  doctor --Trap_w (as a tx)--> chain --reads CT--> cloud
 *           chain --N0--> doctor --fetch CM[N0]--> decrypt with sk
 *
 * Two things are load-bearing for the findings, so they are drawn, not
 * captioned: the trapdoor is PUBLIC once it is a transaction (Finding 1), and
 * Verify consumes no secret (the public-key break).
 */
const BOX = { w: 168, h: 56, r: 10 };

function Box({ x, y, title, sub, tone = "neutral" }) {
  const stroke = { neutral: "#2a3040", key: "#3d4c8f", open: "#2a3040" }[tone];
  const fill = { neutral: "#141721", key: "#151a2b", open: "#141721" }[tone];
  return (
    <g>
      <rect x={x} y={y} width={BOX.w} height={BOX.h} rx={BOX.r} fill={fill} stroke={stroke} />
      <text x={x + 14} y={y + 23} fontSize="12" fontWeight="600" fill="#e8ecf4">{title}</text>
      <text x={x + 14} y={y + 40} fontSize="10.5" fill="#6f7a8d" className="mono">{sub}</text>
    </g>
  );
}

function Flow({ d, label, lx, ly, dashed, tone = "muted", anchor = "middle" }) {
  const stroke = { muted: "#2a3040", accent: "#3d4c8f", warn: "#7a5a1f" }[tone];
  const ink = { muted: "#6f7a8d", accent: "#8ba3ff", warn: "#c79a3a" }[tone];
  return (
    <g>
      <path d={d} fill="none" stroke={stroke} strokeWidth="1.3"
            strokeDasharray={dashed ? "5 4" : undefined} markerEnd="url(#ah)" />
      <text x={lx} y={ly} fontSize="10" fill={ink} textAnchor={anchor} className="mono">{label}</text>
    </g>
  );
}

export default function ArchDiagram() {
  return (
    <svg viewBox="0 0 760 286" className="w-full h-auto" style={{ maxWidth: 760 }}>
      <defs>
        <marker id="ah" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
          <path d="M0,0 L7,3.5 L0,7 z" fill="#3d4c8f" />
        </marker>
      </defs>

      {/* the secret / public split, the same language the Network tab uses */}
      <line x1="16" y1="118" x2="744" y2="118" stroke="#242a36" strokeDasharray="3 6" />
      <text x="16" y="14" fontSize="9.5" fill="#6f7a8d" letterSpacing="0.14em">HOLDS A SECRET KEY</text>
      <text x="16" y="136" fontSize="9.5" fill="#6f7a8d" letterSpacing="0.14em">PUBLIC — NO SECRET REQUIRED</text>

      <Box x={16}  y={30}  title="Patient / sender" sub="PEKS(pk_j, w)" tone="key" />
      <Box x={288} y={30}  title="Doctor" sub="sk_r|j" tone="key" />
      <Box x={288} y={196} title="Cloud" sub="CT_w ‖ CM" />
      <Box x={560} y={196} title="Blockchain" sub="Verify(CT, Trap)" />

      {/* write path */}
      <Flow d="M 100 86 L 100 224 L 282 224" label="CT_w ‖ CM" lx={150} ly={216} />
      {/* search path: trapdoor becomes a public transaction */}
      <Flow d="M 456 86 L 560 86 Q 644 86 644 190" label="Trap_w  (a public tx)" lx={556} ly={78} tone="warn" />
      {/* the chain reads the stored ciphertexts */}
      <Flow d="M 554 224 L 462 224" label="reads CT" lx={508} ly={216} />
      {/* result back to the doctor */}
      <Flow d="M 644 252 Q 644 272 604 272 L 396 272 Q 372 272 372 258 L 372 90" label="N₀" lx={500} ly={284} tone="accent" />
      {/* retrieval */}
      <Flow d="M 340 190 L 340 92" label="CM[N₀] → Decrypt(sk)" lx={348} ly={150} anchor="start" tone="accent" />
    </svg>
  );
}
