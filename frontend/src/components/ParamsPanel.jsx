import { useState } from "react";
import { derivedM, validateParams } from "../utils";
import ShapeTable from "./ShapeTable";

function Field({ label, value, onChange, step, hint }) {
  return (
    <label className="block">
      <div className="flex items-baseline justify-between">
        <span className="text-xs text-ink-300">{label}</span>
        {hint && <span className="text-[10px] text-ink-500">{hint}</span>}
      </div>
      <input
        type="number"
        step={step ?? 1}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="mt-1 w-full mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5
                   text-ink-100 focus:outline-none focus:border-signal-blue"
      />
    </label>
  );
}

export default function ParamsPanel({ params, setParams, onApply, applying, initialized, shapeTable, maxPeriod }) {
  const problems = validateParams(params);
  const m = derivedM(params.n, params.q);

  return (
    <div className="flex flex-col h-full">
      <div className="px-4 py-3 border-b border-ink-800">
        <div className="text-sm font-semibold tracking-wide">PPSEB Analysis Lab</div>
        <div className="text-[11px] text-ink-500 mt-0.5">Xu et al. 2022 — corrected & attacked</div>
      </div>

      <div className="px-4 py-4 space-y-3 border-b border-ink-800">
        <div className="text-[11px] uppercase tracking-wide text-ink-500">Parameters</div>
        <Field label="n — lattice dimension" value={params.n} onChange={(v) => setParams((p) => ({ ...p, n: v }))} />
        <Field label="q — modulus (prime)" value={params.q} onChange={(v) => setParams((p) => ({ ...p, q: v }))} />
        <Field label="sigma — Gaussian width" value={params.sigma} step={0.1} onChange={(v) => setParams((p) => ({ ...p, sigma: v }))} />
        <Field label="l — keyword test length" value={params.l} onChange={(v) => setParams((p) => ({ ...p, l: v }))} />
        <div className="text-[11px] text-ink-400 mono">m = 2·n·⌈log2 q⌉ = <span className="text-ink-100">{m}</span></div>

        {problems.length > 0 && (
          <div className="text-[11px] text-signal-red bg-signal-red/10 border border-signal-red/30 rounded px-2 py-1.5 space-y-0.5">
            {problems.map((p, i) => <div key={i}>⚠ {p}</div>)}
          </div>
        )}

        <button
          onClick={onApply}
          disabled={applying || problems.length > 0}
          className="w-full text-sm font-medium rounded px-3 py-2 bg-signal-blue/90 hover:bg-signal-blue
                     text-ink-950 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          {applying ? "Generating keys…" : "Apply / Regenerate keys"}
        </button>
        {initialized && (
          <div className="text-[11px] text-signal-green">✓ initialized · max period {maxPeriod}</div>
        )}
      </div>

      <div className="px-4 py-4 overflow-y-auto flex-1">
        <div className="text-[11px] uppercase tracking-wide text-ink-500 mb-2">Type discipline</div>
        {shapeTable ? <ShapeTable shapeTable={shapeTable} /> : (
          <div className="text-[11px] text-ink-600">Initialize to see the shape table.</div>
        )}
      </div>
    </div>
  );
}
