/* The architecture drawn the way the information actually moves.
 *
 * The organising idea is the horizontal rule: ABOVE it lives the only secret in
 * the system, the doctor's key. BELOW it everything is public -- the stored
 * ciphertexts, the period keys, the R matrices, and Verify itself, which takes
 * no secret at all. The attacker sits in the public band because it never needs
 * to cross the line: it runs the same Verify the chain does. That single fact
 * is the finding, so the diagram is built around it rather than around boxes.
 */

const NODES = {
  doctor:   { x: 40,  y: 34,  w: 176, h: 66, label: "DOCTOR", role: "holds sk_r|j" },
  cloud:    { x: 336, y: 178, w: 176, h: 66, label: "CLOUD", role: "stores blobs" },
  verifier: { x: 632, y: 178, w: 196, h: 66, label: "VERIFIER · chain", role: "runs Verify" },
  attacker: { x: 336, y: 296, w: 176, h: 66, label: "ATTACKER", role: "reads the public band" },
};
const C = (id) => {
  const n = NODES[id];
  return { x: n.x + n.w / 2, y: n.y + n.h / 2, ...n };
};

/* Each edge names what actually travels along it. */
const EDGES = {
  store:    { d: `M 128 100 L 128 150 Q 128 178 156 178 L ${C("cloud").x - 88} 178`, label: "CT_w ‖ CM", dir: "down" },
  trapdoor: { d: `M 216 62 L 560 62 Q 600 62 600 102 L 600 178`, label: "Trap_w", dir: "right" },
  verify:   { d: `M 512 200 L 632 200`, label: "reads CT", dir: "right" },
  result:   { d: `M 730 178 L 730 120 Q 730 96 700 96 L 232 96`, label: "N₀", dir: "left" },
  fetch:    { d: `M ${C("cloud").x - 88} 222 L 156 222 Q 128 222 128 194 L 128 104`, label: "CM[N₀]", dir: "left" },
  tap:      { d: `M 424 244 L 424 296`, label: "all public", dir: "down" },
  mirror:   { d: `M 700 244 Q 700 330 520 330`, label: "same Verify, no secret", dir: "left", dashed: true },
};

const EDGE_FOR = {
  "doctor->cloud": "store",
  "doctor->verifier->doctor": "trapdoor",
  "cloud->doctor": "fetch",
  attack: "tap",
  doctor: null,
};

function Node({ id, active, accent, sub }) {
  const n = NODES[id];
  const isAttacker = id === "attacker";
  const stroke = active ? "#6e8cff" : isAttacker ? "#7a3138" : "#2a3040";
  const fill = active ? "#171d2c" : isAttacker ? "#181215" : "#141721";
  return (
    <g>
      {active && <rect x={n.x - 4} y={n.y - 4} width={n.w + 8} height={n.h + 8} rx={13}
        fill="none" stroke="#6e8cff" strokeOpacity="0.28" strokeWidth="1.5" />}
      <rect x={n.x} y={n.y} width={n.w} height={n.h} rx={10} fill={fill} stroke={stroke} strokeWidth="1.25" />
      <text x={n.x + 16} y={n.y + 26} fill="#e8ecf4" fontSize="12.5" fontWeight="600"
            letterSpacing="0.06em">{n.label}</text>
      <text x={n.x + 16} y={n.y + 45} fill={accent ?? "#6f7a8d"} fontSize="11">{sub ?? n.role}</text>
    </g>
  );
}

function Edge({ id, active }) {
  const e = EDGES[id];
  if (!e) return null;
  const stroke = active ? "#6e8cff" : e.dashed ? "#5b3d44" : "#2a3040";
  return (
    <>
      <path d={e.d} fill="none" stroke={stroke} strokeWidth={active ? 1.8 : 1.25}
            strokeDasharray={e.dashed ? "5 4" : undefined} markerEnd={`url(#${active ? "arrowOn" : "arrow"})`} />
      {active && (
        <circle r="3.6" fill="#8ba3ff">
          <animateMotion dur="1.05s" repeatCount="1" path={e.d} fill="freeze" />
          <animate attributeName="opacity" values="0;1;1;0" dur="1.05s" fill="freeze" />
        </circle>
      )}
    </>
  );
}

export default function NetworkDiagram({ activeEdge, pulse, period, blobs, attackerHolds }) {
  const active = EDGE_FOR[activeEdge] ?? null;
  const touched = { store: ["doctor", "cloud"], trapdoor: ["doctor", "verifier"],
                    verify: ["verifier", "cloud"], result: ["verifier", "doctor"],
                    fetch: ["cloud", "doctor"], tap: ["cloud", "attacker"] }[active] ?? [];
  return (
    <svg viewBox="0 0 900 380" className="w-full" style={{ maxHeight: 400 }} key={pulse}>
      <defs>
        <marker id="arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
          <path d="M0,0 L7,3.5 L0,7 z" fill="#2a3040" />
        </marker>
        <marker id="arrowOn" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
          <path d="M0,0 L7,3.5 L0,7 z" fill="#6e8cff" />
        </marker>
      </defs>

      {/* The line the attack never has to cross. */}
      <line x1="24" y1="140" x2="876" y2="140" stroke="#2a3040" strokeDasharray="3 6" />
      <text x="24" y="26" fill="#6f7a8d" fontSize="10" letterSpacing="0.14em">SECRET</text>
      <text x="24" y="162" fill="#6f7a8d" fontSize="10" letterSpacing="0.14em">PUBLIC — NO SECRET REQUIRED</text>

      {Object.keys(EDGES).map((id) => <Edge key={id} id={id} active={active === id} />)}
      {Object.entries(EDGES).map(([id, e]) => {
        const m = { store: [150, 140], trapdoor: [366, 54], verify: [548, 192], result: [430, 88],
                    fetch: [268, 238], tap: [436, 274], mirror: [548, 338] }[id];
        return (
          <text key={`l-${id}`} x={m[0]} y={m[1]} fontSize="10.5"
                fill={active === id ? "#8ba3ff" : e.dashed ? "#a3616c" : "#6f7a8d"}
                className="mono">{e.label}</text>
        );
      })}

      <Node id="doctor" active={touched.includes("doctor")} accent="#8ba3ff" sub={`period ${period}`} />
      <Node id="cloud" active={touched.includes("cloud")} sub={`${blobs} record${blobs === 1 ? "" : "s"}`} />
      <Node id="verifier" active={touched.includes("verifier")} />
      <Node id="attacker" active={touched.includes("attacker")} accent="#d98a94" sub={attackerHolds} />
    </svg>
  );
}
