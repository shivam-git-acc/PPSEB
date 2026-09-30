import { useEffect, useRef, useState } from "react";
import { derivedM, validateParams } from "../utils";
import ShapeTable from "./ShapeTable";
import { Field, PrimaryButton, inputCls } from "./Section";

/* The parameters live in the header, not a sidebar: always visible on every
   tab (so switching tabs never hides them) while the content below keeps the
   full width. Editing happens in a popover so the bar stays one line. */
export default function ParamsBar({ params, setParams, onApply, applying, initialized,
                                    shapeTable, maxPeriod, error }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  const problems = validateParams(params);
  const m = derivedM(params.n, params.q);

  useEffect(() => {
    if (!open) return undefined;
    const onDoc = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    const onEsc = (e) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onEsc);
    return () => { document.removeEventListener("mousedown", onDoc); document.removeEventListener("keydown", onEsc); };
  }, [open]);

  const chip = (k, v) => (
    <span key={k} className="inline-flex items-baseline gap-1.5">
      <span className="text-ink-500">{k}</span>
      <span className="mono text-ink-100">{v}</span>
    </span>
  );

  return (
    <div className="relative" ref={ref}>
      <div className="flex items-center gap-3">
        <button onClick={() => setOpen((o) => !o)}
          className="flex items-center gap-3 rounded-lg bg-white/[0.04] ring-1 ring-inset ring-ink-800
                     hover:ring-ink-600 px-3 py-1.5 text-2xs transition-colors">
          <span className={`w-1.5 h-1.5 rounded-full ${initialized ? "bg-[#35c235]" : "bg-ink-600"}`} />
          {chip("n", params.n)}{chip("q", params.q)}{chip("m", m)}{chip("σ", params.sigma)}
          <span className="text-ink-600">·</span>
          <span className="text-ink-400">{initialized ? `period ≤ ${maxPeriod}` : "not initialized"}</span>
          <svg width="10" height="10" viewBox="0 0 10 10" className="text-ink-500">
            <path d="M2 4l3 3 3-3" stroke="currentColor" strokeWidth="1.4" fill="none" strokeLinecap="round" />
          </svg>
        </button>
        {problems.length > 0 && <span className="text-2xs text-signal-amber">⚠ {problems[0]}</span>}
      </div>

      {open && (
        <div className="absolute right-0 z-40 mt-2 w-[22rem] max-w-[calc(100vw-2rem)] panel shadow-pop enter p-4 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <Field label="n" hint="lattice dimension">
              <input type="number" className={inputCls} value={params.n}
                onChange={(e) => setParams((p) => ({ ...p, n: Number(e.target.value) }))} />
            </Field>
            <Field label="q" hint="prime modulus">
              <input type="number" className={inputCls} value={params.q}
                onChange={(e) => setParams((p) => ({ ...p, q: Number(e.target.value) }))} />
            </Field>
            <Field label="σ" hint="Gaussian width">
              <input type="number" step="0.1" className={inputCls} value={params.sigma}
                onChange={(e) => setParams((p) => ({ ...p, sigma: Number(e.target.value) }))} />
            </Field>
            <Field label="ℓ" hint="keyword test length">
              <input type="number" className={inputCls} value={params.l}
                onChange={(e) => setParams((p) => ({ ...p, l: Number(e.target.value) }))} />
            </Field>
          </div>

          <div className="text-2xs text-ink-500 mono">m = 2·n·⌈log₂ q⌉ = <span className="text-ink-100">{m}</span></div>

          {problems.length > 0 && (
            <div className="text-2xs text-signal-amber bg-signal-amber/10 ring-1 ring-inset ring-signal-amber/25
                            rounded-lg px-2.5 py-2 space-y-0.5">
              {problems.map((p, i) => <div key={i}>⚠ {p}</div>)}
            </div>
          )}
          {error && (
            <div className="text-2xs text-[#e55757] bg-signal-red/10 ring-1 ring-inset ring-signal-red/30 rounded-lg px-2.5 py-2">
              {error}
            </div>
          )}

          <PrimaryButton onClick={onApply} disabled={applying || problems.length > 0}>
            {applying ? "Generating keys…" : "Apply · regenerate keys"}
          </PrimaryButton>

          {shapeTable && (
            <details className="pt-1">
              <summary className="text-2xs text-ink-500 cursor-pointer hover:text-ink-300">Type discipline</summary>
              <div className="mt-2"><ShapeTable shapeTable={shapeTable} /></div>
            </details>
          )}
        </div>
      )}
    </div>
  );
}
