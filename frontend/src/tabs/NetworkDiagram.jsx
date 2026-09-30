/* The architecture drawn the way the information actually moves.
 *
 * The organising idea is the horizontal rule: ABOVE it lives the only secret in
 * the system, the doctor's key. BELOW it everything is public -- the stored
 * ciphertexts, the period keys, the R matrices, and Verify itself, which takes
 * no secret at all. The attacker sits in the public band because it never needs
 * to cross the line: it runs the same Verify the chain does.
 *
 * Geometry is written out explicitly rather than derived from box centres. An
 * earlier version computed centres with a helper that spread the box AFTER the
 * computed fields, so every centre silently collapsed back to the box's corner
 * and each edge landed half a box away from where it belonged. Explicit
 * endpoints cannot drift like that, and the corridors below are chosen so no
 * two edges cross.
 */

const N = {
  doctor:   { x: 60,  y: 40,  w: 190, h: 64, label: "DOCTOR",          role: "holds sk_r|j" },
  cloud:    { x: 355, y: 170, w: 175, h: 64, label: "CLOUD",           role: "stores blobs" },
  verifier: { x: 655, y: 170, w: 195, h: 64, label: "VERIFIER · chain", role: "runs Verify" },
  attacker: { x: 355, y: 300, w: 175, h: 64, label: "ATTACKER",        role: "reads the public band" },
};

/* Each edge names what actually travels along it. Corridors: y=64 and y=96 for
   the two top runs, y=202 for the write, y=186 for the chain's read. */
const E = {
  store:    { d: "M 120 104 L 120 202 L 347 202",           lx: 196, ly: 195, label: "CT_w ‖ CM" },
  trapdoor: { d: "M 250 64 L 752 64 L 752 162",             lx: 470, ly: 56,  label: "Trap_w" },
  read:     { d: "M 647 186 L 538 186",                     lx: 592, ly: 178, label: "reads CT", anchor: "middle" },
  result:   { d: "M 850 170 L 850 96 L 258 96",             lx: 470, ly: 88,  label: "N₀" },
  fetch:    { d: "M 400 162 L 400 128 L 190 128 L 190 112", lx: 296, ly: 121, label: "CM[N₀]" },
  tap:      { d: "M 442 234 L 442 292",                     lx: 452, ly: 268, label: "all public", anchor: "start" },
  mirror:   { d: "M 700 234 Q 700 348 538 336",             lx: 706, ly: 300, label: "same Verify, no secret",
              anchor: "start", dashed: true },
};

const TOUCHES = {
  store: ["doctor", "cloud"], trapdoor: ["doctor", "verifier"], read: ["verifier", "cloud"],
  result: ["verifier", "doctor"], fetch: ["cloud", "doctor"], tap: ["cloud", "attacker"],
};
const EDGE_FOR = {
  "doctor->cloud": "store",
  "doctor->verifier->doctor": "trapdoor",
  "cloud->doctor": "fetch",
  attack: "tap",
  doctor: null,
};

function Node({ id, active, accent, sub }) {
  const n = N[id];
  const attacker = id === "attacker";
  return (
    <g>
      {active && (
        <rect x={n.x - 5} y={n.y - 5} width={n.w + 10} height={n.h + 10} rx={14}
              fill="none" stroke="#6e8cff" strokeOpacity="0.3" strokeWidth="1.5" />
      )}
      <rect x={n.x} y={n.y} width={n.w} height={n.h} rx={11}
            fill={active ? "#171d2c" : attacker ? "#181215" : "#141721"}
            stroke={active ? "#6e8cff" : attacker ? "#7a3138" : "#2a3040"} strokeWidth="1.25" />
      <text x={n.x + 15} y={n.y + 26} fill="#e8ecf4" fontSize="12.5" fontWeight="600"
            letterSpacing="0.05em">{n.label}</text>
      <text x={n.x + 15} y={n.y + 45} fill={accent ?? "#6f7a8d"} fontSize="10.5"
            className="mono">{sub ?? n.role}</text>
    </g>
  );
}

export default function NetworkDiagram({ activeEdge, pulse, period, blobs, attackerHolds }) {
  const on = EDGE_FOR[activeEdge] ?? null;
  const lit = TOUCHES[on] ?? [];
  return (
    <svg viewBox="0 0 900 380" className="w-full h-auto mx-auto" style={{ maxWidth: 900 }} key={pulse}>
      <defs>
        <marker id="ndArrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
          <path d="M0,0 L7,3.5 L0,7 z" fill="#2a3040" />
        </marker>
        <marker id="ndArrowOn" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
          <path d="M0,0 L7,3.5 L0,7 z" fill="#6e8cff" />
        </marker>
        <marker id="ndArrowDim" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
          <path d="M0,0 L7,3.5 L0,7 z" fill="#5b3d44" />
        </marker>
      </defs>

      {/* The line the attack never has to cross. */}
      <line x1="30" y1="135" x2="870" y2="135" stroke="#242a36" strokeDasharray="3 6" />
      <text x="30" y="24" fontSize="9.5" fill="#6f7a8d" letterSpacing="0.14em">SECRET</text>
      <text x="30" y="152" fontSize="9.5" fill="#6f7a8d" letterSpacing="0.14em">
        PUBLIC — NO SECRET REQUIRED
      </text>

      {Object.entries(E).map(([id, e]) => {
        const active = on === id;
        return (
          <g key={id}>
            <path d={e.d} fill="none" strokeWidth={active ? 1.9 : 1.3}
                  stroke={active ? "#6e8cff" : e.dashed ? "#5b3d44" : "#2a3040"}
                  strokeDasharray={e.dashed ? "5 4" : undefined}
                  markerEnd={`url(#${active ? "ndArrowOn" : e.dashed ? "ndArrowDim" : "ndArrow"})`} />
            <text x={e.lx} y={e.ly} fontSize="10" className="mono"
                  textAnchor={e.anchor ?? "middle"}
                  fill={active ? "#8ba3ff" : e.dashed ? "#a3616c" : "#6f7a8d"}>{e.label}</text>
            {active && (
              <circle r="3.6" fill="#8ba3ff">
                <animateMotion dur="1.05s" path={e.d} fill="freeze" />
                <animate attributeName="opacity" values="0;1;1;0" dur="1.05s" fill="freeze" />
              </circle>
            )}
          </g>
        );
      })}

      <Node id="doctor" active={lit.includes("doctor")} accent="#8ba3ff" sub={`period ${period}`} />
      <Node id="cloud" active={lit.includes("cloud")} sub={`${blobs} record${blobs === 1 ? "" : "s"}`} />
      <Node id="verifier" active={lit.includes("verifier")} />
      <Node id="attacker" active={lit.includes("attacker")} accent="#d98a94" sub={attackerHolds} />
    </svg>
  );
}
