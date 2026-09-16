import { useEffect, useRef, useState } from "react";
import {
  ResponsiveContainer, LineChart, Line, BarChart, Bar, XAxis, YAxis, Tooltip, Legend,
  CartesianGrid, ErrorBar, ReferenceLine,
} from "recharts";
import { api } from "../api";
import { Card, Badge, PrimaryButton, SecondaryButton, ErrorBanner } from "../components/Section";

const OUTCOME_STYLE = {
  survives: { bg: "bg-signal-green/25", text: "text-signal-green", label: "survives" },
  break: { bg: "bg-signal-red/30", text: "text-signal-red", label: "break" },
  untrusted: { bg: "bg-amber-500/25", text: "text-amber-400", label: "untrusted" },
  error: { bg: "bg-ink-700", text: "text-ink-400", label: "error" },
  skipped: { bg: "bg-ink-800", text: "text-ink-500", label: "skipped" },
};

function parseList(s) {
  return s.split(",").map((x) => parseInt(x.trim(), 10)).filter((x) => Number.isFinite(x) && x > 0);
}

function fmtDuration(seconds) {
  if (!seconds || seconds < 0) return "—";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}

/** Plot A — outcome heatmap. Built from CSS grid rather than a charting
 *  library: a categorical n x J matrix reads far better as labelled cells
 *  than as a scatter with colour-mapped points. */
function Heatmap({ panel }) {
  const { n_values: ns, J_values: Js, cells } = panel;
  const at = (n, J) => cells.find((c) => c.n === n && c.J === J);
  return (
    <div className="overflow-x-auto">
      <div className="inline-block">
        <div className="flex">
          <div className="w-14 shrink-0" />
          {Js.map((J) => (
            <div key={J} className="w-20 text-center text-[11px] text-ink-500 pb-1">J={J}</div>
          ))}
        </div>
        {ns.map((n) => (
          <div key={n} className="flex items-center">
            <div className="w-14 shrink-0 text-[11px] text-ink-500 pr-2 text-right">n={n}</div>
            {Js.map((J) => {
              const c = at(n, J);
              const style = OUTCOME_STYLE[c?.outcome] ?? OUTCOME_STYLE.skipped;
              const rate = c?.break_rate;
              return (
                <div
                  key={J}
                  title={
                    c
                      ? `n=${n} J=${J}: ${c.outcome}` +
                        (rate != null ? ` (break_rate ${rate.toFixed(2)}, ${c.broken_trusted_repeats}/${c.trusted_repeats} repeats)` : "") +
                        (c.broken_periods_l2?.length ? `, periods ${JSON.stringify(c.broken_periods_l2)}` : "") +
                        (c.errors?.length ? `\n${c.errors[0]}` : "")
                      : ""
                  }
                  className={`w-20 h-14 m-0.5 rounded flex flex-col items-center justify-center border border-ink-800 ${style.bg}`}
                >
                  <span className={`text-[10px] font-medium ${style.text}`}>{style.label}</span>
                  {rate != null && (
                    <span className="mono text-[10px] text-ink-300">{rate.toFixed(2)}</span>
                  )}
                  {c && (
                    <span className="text-[9px] text-ink-500">
                      {c.trusted_repeats}/{c.repeats_expected} ok
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        ))}
      </div>
      <div className="flex gap-3 mt-2 flex-wrap">
        {Object.entries(OUTCOME_STYLE).map(([k, v]) => (
          <div key={k} className="flex items-center gap-1.5">
            <div className={`w-3 h-3 rounded ${v.bg} border border-ink-700`} />
            <span className="text-[10px] text-ink-500">{v.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}


const EXPORT_BG = "#0f0f12";

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function escapeXml(text) {
  return String(text).replace(/[<>&"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;" }[c]));
}

/** Wrap a chart's inner SVG with a title, a caption carrying the config, and a
 *  solid background, so an exported figure stands on its own in a writeup. */
function framedSvg(innerSvg, width, height, title, caption) {
  const top = 34;
  const bottom = 34;
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height + top + bottom}" ` +
    `viewBox="0 0 ${width} ${height + top + bottom}" font-family="ui-sans-serif, system-ui, sans-serif">` +
    `<rect width="100%" height="100%" fill="${EXPORT_BG}"/>` +
    `<text x="12" y="22" fill="#e5e5ea" font-size="14" font-weight="600">${escapeXml(title)}</text>` +
    `<g transform="translate(0, ${top})">${innerSvg}</g>` +
    `<text x="12" y="${height + top + 22}" fill="#8a8a94" font-size="11">${escapeXml(caption)}</text>` +
    `</svg>`
  );
}

function svgToPng(svgString, width, height, filename) {
  const img = new Image();
  const url = URL.createObjectURL(new Blob([svgString], { type: "image/svg+xml;charset=utf-8" }));
  img.onload = () => {
    const scale = 2;
    const canvas = document.createElement("canvas");
    canvas.width = width * scale;
    canvas.height = height * scale;
    const ctx = canvas.getContext("2d");
    ctx.scale(scale, scale);
    ctx.drawImage(img, 0, 0, width, height);
    URL.revokeObjectURL(url);
    canvas.toBlob((blob) => blob && downloadBlob(blob, filename), "image/png");
  };
  img.src = url;
}

/** Plot A as a real SVG (the on-screen heatmap is HTML, which cannot be
 *  exported as a figure directly). Same data, same colour semantics. */
function heatmapSvg(panel) {
  const fills = { survives: "#1f5a37", break: "#6b2426", untrusted: "#6b4a12", error: "#3a3a42", skipped: "#26262c" };
  const { n_values: ns, J_values: Js, cells } = panel;
  const cw = 78, ch = 48, left = 56, top = 22;
  const width = left + Js.length * cw + 16;
  const height = top + ns.length * ch + 30;
  let body = "";
  Js.forEach((J, j) => {
    body += `<text x="${left + j * cw + cw / 2}" y="15" fill="#8a8a94" font-size="11" text-anchor="middle">J=${J}</text>`;
  });
  ns.forEach((n, i) => {
    body += `<text x="${left - 8}" y="${top + i * ch + ch / 2 + 4}" fill="#8a8a94" font-size="11" text-anchor="end">n=${n}</text>`;
    Js.forEach((J, j) => {
      const c = cells.find((x) => x.n === n && x.J === J);
      const outcome = c?.outcome ?? "skipped";
      const x = left + j * cw, y = top + i * ch;
      body += `<rect x="${x + 2}" y="${y + 2}" width="${cw - 4}" height="${ch - 4}" rx="4" fill="${fills[outcome]}"/>`;
      body += `<text x="${x + cw / 2}" y="${y + 20}" fill="#e5e5ea" font-size="10" text-anchor="middle">${outcome}</text>`;
      if (c?.break_rate != null) {
        body += `<text x="${x + cw / 2}" y="${y + 34}" fill="#c8c8d0" font-size="10" text-anchor="middle">${c.break_rate.toFixed(2)} (${c.trusted_repeats}/${c.repeats_expected})</text>`;
      }
    });
  });
  const legendY = top + ns.length * ch + 18;
  Object.entries(fills).forEach(([k, f], idx) => {
    const lx = left + idx * 84;
    body += `<rect x="${lx}" y="${legendY - 9}" width="10" height="10" fill="${f}"/>`;
    body += `<text x="${lx + 14}" y="${legendY}" fill="#8a8a94" font-size="10">${k}</text>`;
  });
  return { svg: body, width, height };
}

function ExportButtons({ getSvg, filename }) {
  const exportAs = (fmt) => {
    const out = getSvg();
    if (!out) return;
    if (fmt === "svg") {
      downloadBlob(new Blob([out.svg], { type: "image/svg+xml;charset=utf-8" }), `${filename}.svg`);
    } else {
      svgToPng(out.svg, out.width, out.height, `${filename}.png`);
    }
  };
  return (
    <div className="flex gap-2 mt-2">
      <button onClick={() => exportAs("svg")} className="text-[11px] px-2 py-1 rounded border border-ink-700 text-ink-400 hover:text-ink-200">Download SVG</button>
      <button onClick={() => exportAs("png")} className="text-[11px] px-2 py-1 rounded border border-ink-700 text-ink-400 hover:text-ink-200">Download PNG</button>
    </div>
  );
}

/** Recharts renders an <svg class="recharts-surface">; export that inside a
 *  titled, captioned frame. */
function RechartsExport({ containerRef, title, caption, filename }) {
  const getSvg = () => {
    const el = containerRef.current?.querySelector("svg.recharts-surface");
    if (!el) return null;
    const width = el.clientWidth || Number(el.getAttribute("width")) || 800;
    const height = el.clientHeight || Number(el.getAttribute("height")) || 260;
    const inner = new XMLSerializer().serializeToString(el);
    const framed = framedSvg(inner, width, height, title, caption);
    return { svg: framed, width, height: height + 68 };
  };
  return <ExportButtons getSvg={getSvg} filename={filename} />;
}

export default function BatchSweepTab({ initialized }) {
  const [view, setView] = useState("configure");

  const [nList, setNList] = useState("4, 8");
  const [jList, setJList] = useState("3, 4, 5, 6, 8");
  const [variants, setVariants] = useState(["low_norm"]);
  const [reducers, setReducers] = useState(["bkz"]);
  const [recordsPerPeriod, setRecordsPerPeriod] = useState(40);
  const [repeats, setRepeats] = useState(3);
  const [seedBase, setSeedBase] = useState(1000);
  const [maxHours, setMaxHours] = useState(12);

  const [preflight, setPreflight] = useState(null);
  const [error, setError] = useState(null);
  const [starting, setStarting] = useState(false);

  const [jobId, setJobId] = useState(null);
  const [status, setStatus] = useState(null);
  const [results, setResults] = useState(null);
  const [jobs, setJobs] = useState([]);
  const [gate, setGate] = useState("strict");
  const pollRef = useRef(null);
  const plotBRefs = useRef({});
  const plotCRef = useRef(null);
  const plotDRef = useRef(null);

  const config = {
    n_values: parseList(nList),
    J_values: parseList(jList),
    h1_variants: variants,
    reducers,
    records_per_period: Number(recordsPerPeriod),
    repeats: Number(repeats),
    seed_base: Number(seedBase),
    max_hours: Number(maxHours),
  };

  const refreshJobs = async () => {
    try {
      const res = await api.sweepJobs();
      setJobs(res.result || []);
    } catch (e) {
      /* the jobs list is a convenience; never block the tab on it */
    }
  };

  useEffect(() => {
    refreshJobs();
  }, []);

  // Pre-flight whenever the grid changes, so the cost (and any impossible
  // cells) are visible BEFORE committing a night to the run.
  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      try {
        const res = await api.sweepPreflight(config);
        if (!cancelled) setPreflight(res.result);
      } catch (e) {
        if (!cancelled) setPreflight(null);
      }
    };
    run();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nList, jList, variants.join(), reducers.join(), recordsPerPeriod, repeats, seedBase, maxHours]);

  // Poll a running job. Safe to leave and come back -- the job is
  // server-side, and re-attaching by job_id resumes polling.
  useEffect(() => {
    if (!jobId) return undefined;
    const tick = async () => {
      try {
        const res = await api.sweepStatus(jobId);
        setStatus(res.result);
        if (["done", "stopped", "failed"].includes(res.result.status)) {
          clearInterval(pollRef.current);
          loadResults(jobId);
          refreshJobs();
        }
      } catch (e) {
        setError(String(e.message || e));
        clearInterval(pollRef.current);
      }
    };
    tick();
    pollRef.current = setInterval(tick, 4000);
    return () => clearInterval(pollRef.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobId]);

  const loadResults = async (id, g = gate) => {
    try {
      const res = await api.sweepResults(id, g);
      setResults(res.result);
    } catch (e) {
      setError(String(e.message || e));
    }
  };

  const start = async () => {
    setStarting(true);
    setError(null);
    setResults(null);
    try {
      const res = await api.sweepStart(config);
      setJobId(res.result.job_id);
      setView("run");
      refreshJobs();
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      setStarting(false);
    }
  };

  const stop = async () => {
    if (!jobId) return;
    try {
      await api.sweepStop(jobId);
    } catch (e) {
      setError(String(e.message || e));
    }
  };

  const openJob = async (id) => {
    setJobId(id);
    setResults(null);
    setView("results");
    loadResults(id);
  };

  const toggle = (arr, setter, value) => {
    setter(arr.includes(value) ? arr.filter((x) => x !== value) : [...arr, value]);
  };

  const dropInvalidN = () => {
    if (preflight?.valid_n?.length) setNList(preflight.valid_n.join(", "));
  };

  return (
    <div className="space-y-5 max-w-5xl">
      <Card
        title="Batch Sweep"
        subtitle="Run the end-to-end attack across a grid of configurations unattended, checkpointed to disk, then read the heatmap and conclusion in the morning"
      >
        <p className="text-sm text-ink-300 leading-relaxed">
          Every cell is one full end-to-end run (frozen DBs, real search and decrypt) and is
          repeated with different seeds so a single lucky or unlucky match never decides a cell.
          A repeat counts toward a verdict <b>only</b> if its negative controls failed (garbage and
          wrong-period keys did not pass Level 2). In the <b>strict</b> view a break also needs the
          attacker's word basis to be within 3× the honest doctor's; breaks that aren't are listed
          with their ratio, not hidden. Untrusted, errored and skipped cells are reported openly and
          excluded from the conclusion — never counted as "survives".
        </p>
        <div className="flex gap-2 mt-4">
          {["configure", "run", "results"].map((v) => (
            <button
              key={v}
              onClick={() => {
                setView(v);
                if (v === "results" && jobId && !results) loadResults(jobId);
              }}
              className={`px-3 py-1.5 text-sm rounded border transition-colors ${
                view === v ? "border-signal-blue text-ink-100" : "border-ink-700 text-ink-400 hover:text-ink-200"
              }`}
            >
              {v === "configure" ? "Configure" : v === "run" ? "Run / progress" : "Results"}
            </button>
          ))}
        </div>
      </Card>

      <ErrorBanner message={error} />

      {view === "configure" && (
        <Card title="Configure the grid">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <label className="block">
              <div className="text-xs text-ink-400 mb-1">n values (comma-separated; powers of 2 only at q=257)</div>
              <input value={nList} onChange={(e) => setNList(e.target.value)}
                className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-full" />
            </label>
            <label className="block">
              <div className="text-xs text-ink-400 mb-1">J values (comma-separated)</div>
              <input value={jList} onChange={(e) => setJList(e.target.value)}
                className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-full" />
            </label>
            <div>
              <div className="text-xs text-ink-400 mb-1">H1 variants</div>
              <div className="flex gap-2">
                {["low_norm", "naive_uniform"].map((v) => (
                  <button key={v} onClick={() => toggle(variants, setVariants, v)}
                    className={`px-2 py-1 text-xs rounded border ${
                      variants.includes(v) ? "border-signal-blue text-ink-100" : "border-ink-700 text-ink-500"
                    }`}>{v}</button>
                ))}
              </div>
            </div>
            <div>
              <div className="text-xs text-ink-400 mb-1">Attacker reducers</div>
              <div className="flex gap-2">
                {["bkz", "lll"].map((v) => (
                  <button key={v} onClick={() => toggle(reducers, setReducers, v)}
                    className={`px-2 py-1 text-xs rounded border ${
                      reducers.includes(v) ? "border-signal-blue text-ink-100" : "border-ink-700 text-ink-500"
                    }`}>{v}</button>
                ))}
              </div>
            </div>
            <label className="block">
              <div className="text-xs text-ink-400 mb-1">records / period</div>
              <input type="number" min={1} max={51} value={recordsPerPeriod}
                onChange={(e) => setRecordsPerPeriod(e.target.value)}
                className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-full" />
            </label>
            <label className="block">
              <div className="text-xs text-ink-400 mb-1">repeats / cell</div>
              <input type="number" min={1} max={20} value={repeats}
                onChange={(e) => setRepeats(e.target.value)}
                className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-full" />
            </label>
            <label className="block">
              <div className="text-xs text-ink-400 mb-1">seed base (reproducibility)</div>
              <input type="number" value={seedBase} onChange={(e) => setSeedBase(e.target.value)}
                className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-full" />
            </label>
            <label className="block">
              <div className="text-xs text-ink-400 mb-1">max hours (safety stop, checkpoints cleanly)</div>
              <input type="number" min={0.1} step={0.5} value={maxHours}
                onChange={(e) => setMaxHours(e.target.value)}
                className="mono text-sm bg-ink-900 border border-ink-700 rounded px-2 py-1.5 w-full" />
            </label>
          </div>

          {preflight && (
            <div className="mt-4 space-y-3">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                <div className="border border-ink-800 rounded p-2">
                  <div className="text-ink-500 uppercase text-[10px] mb-1">cells</div>
                  <div className="mono text-ink-200">{preflight.total_cells}</div>
                </div>
                <div className="border border-ink-800 rounded p-2">
                  <div className="text-ink-500 uppercase text-[10px] mb-1">runs (cells × repeats)</div>
                  <div className="mono text-ink-200">{preflight.total_units}</div>
                </div>
                <div className="border border-ink-800 rounded p-2">
                  <div className="text-ink-500 uppercase text-[10px] mb-1">runnable</div>
                  <div className="mono text-ink-200">{preflight.runnable_units}</div>
                </div>
                <div className="border border-ink-800 rounded p-2">
                  <div className="text-ink-500 uppercase text-[10px] mb-1">rough ETA</div>
                  <div className="mono text-ink-200">{fmtDuration(preflight.eta_seconds)}</div>
                </div>
              </div>

              {preflight.warnings?.map((w, i) => (
                <div key={i} className="text-xs text-amber-400 bg-amber-500/10 border border-amber-600/30 rounded px-3 py-2.5 leading-relaxed">
                  ⚠ {w}
                  {preflight.valid_n?.length > 0 && (
                    <button onClick={dropInvalidN}
                      className="ml-2 underline text-amber-300 hover:text-amber-200">
                      use n={preflight.valid_n.join(", ")}
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}

          <div className="mt-4 flex items-center gap-3">
            <PrimaryButton onClick={start} disabled={!initialized || starting || !preflight?.runnable_units}>
              {starting ? "Starting…" : "Start batch (runs in the background)"}
            </PrimaryButton>
            {!initialized && <span className="text-xs text-ink-500">Initialize params in the left rail first.</span>}
          </div>
        </Card>
      )}

      {view === "run" && (
        <Card title="Progress">
          {!status && <p className="text-sm text-ink-500">No job running. Start one from Configure.</p>}
          {status && (
            <div className="space-y-4">
              <div className="flex items-center gap-3 flex-wrap">
                <Badge tone={status.status === "done" ? "green" : status.status === "running" ? "blue" : "amber"}>
                  {status.status}
                </Badge>
                <span className="mono text-xs text-ink-400">{status.job_id}</span>
                {status.stop_reason && <span className="text-xs text-amber-400">{status.stop_reason}</span>}
              </div>

              <div>
                <div className="h-2 bg-ink-800 rounded overflow-hidden">
                  <div className="h-full bg-signal-blue transition-all"
                    style={{ width: `${status.total ? (status.done / status.total) * 100 : 0}%` }} />
                </div>
                <div className="flex justify-between text-xs text-ink-500 mt-1">
                  <span>{status.done} / {status.total} runs</span>
                  <span>elapsed {fmtDuration(status.elapsed_s)} · ETA {fmtDuration(status.eta_s)}</span>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3 text-xs">
                <div className="border border-ink-800 rounded p-2">
                  <div className="text-ink-500 uppercase text-[10px] mb-1">trusted</div>
                  <div className="mono text-signal-green">{status.trusted_units}</div>
                </div>
                <div className="border border-ink-800 rounded p-2">
                  <div className="text-ink-500 uppercase text-[10px] mb-1">untrusted</div>
                  <div className="mono text-amber-400">{status.untrusted_units}</div>
                </div>
                <div className="border border-ink-800 rounded p-2">
                  <div className="text-ink-500 uppercase text-[10px] mb-1">errored</div>
                  <div className="mono text-ink-400">{status.error_units}</div>
                </div>
              </div>

              <div className="flex gap-2">
                <SecondaryButton onClick={stop} disabled={status.status !== "running"}>
                  Stop (checkpoints cleanly)
                </SecondaryButton>
                <SecondaryButton onClick={() => { setView("results"); loadResults(jobId); }}>
                  View results so far
                </SecondaryButton>
              </div>
              <p className="text-xs text-ink-500">
                Safe to close this tab — the job runs server-side and checkpoints every run to disk.
                Reopen it from the past-jobs list below.
              </p>
            </div>
          )}

          {jobs.length > 0 && (
            <div className="mt-5 border-t border-ink-800 pt-4">
              <div className="text-xs text-ink-500 uppercase mb-2">Past jobs</div>
              <div className="space-y-1">
                {jobs.map((j) => (
                  <button key={j.job_id} onClick={() => openJob(j.job_id)}
                    className="flex items-center gap-3 w-full text-left px-2 py-1.5 rounded hover:bg-ink-800/60">
                    <span className="mono text-xs text-ink-300">{j.job_id}</span>
                    <Badge tone={j.status === "done" ? "green" : j.status === "running" ? "blue" : "neutral"}>{j.status}</Badge>
                    <span className="text-xs text-ink-500">{j.done}/{j.total} runs</span>
                    <span className="text-xs text-ink-600">
                      n={j.config?.n_values?.join(",")} · J={j.config?.J_values?.join(",")}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </Card>
      )}

      {view === "results" && (
        <>
          {!results && <Card title="Results"><p className="text-sm text-ink-500">No results loaded. Pick a job from Run / progress.</p></Card>}
          {results && (() => {
            const cfg = results.config;
            const caption = `n∈{${cfg.n_values.join(",")}} · J∈{${cfg.J_values.join(",")}} · H1=${cfg.h1_variants.join("/")} · attacker=${cfg.reducers.join("/")} · repeats=${cfg.repeats} · records/period=${cfg.records_per_period} · trust gate=${results.gate}`;
            return (
            <>
              <Card title="Trust gate">
                <div className="flex gap-2 flex-wrap">
                  {[
                    ["strict", "strict (headline)"],
                    ["controls_only", "negative controls only"],
                  ].map(([g, label]) => (
                    <button key={g}
                      onClick={() => { setGate(g); loadResults(results.job_id, g); }}
                      className={`px-3 py-1.5 text-xs rounded border ${
                        gate === g ? "border-signal-blue text-ink-100" : "border-ink-700 text-ink-400 hover:text-ink-200"
                      }`}>
                      {label}
                    </button>
                  ))}
                </div>
                <p className="text-xs text-ink-400 mt-3 leading-relaxed">
                  Both views come from the same saved runs — nothing is re-run. <b>strict</b> counts a break only if the
                  negative controls failed <i>and</i> the attacker's word basis is within the stated factor of the honest
                  doctor's at that period; <b>controls only</b> drops the word check.
                </p>
                {results.gate_diagnostics && (() => {
                  const d = results.gate_diagnostics;
                  const excluded = d.breaks_excluded_by_word_check || [];
                  const rate = d.word_decision_stability;
                  return (
                    <div className="mt-3 space-y-2">
                      <div className={`text-xs rounded px-3 py-2.5 border leading-relaxed ${
                        d.word_check_unstable ? "border-signal-red/50 bg-signal-red/10 text-signal-red" : "border-ink-700 text-ink-400"
                      }`}>
                        <b>Word-check stability:</b> two independent draws of the attacker's word basis made the same approve/exclude
                        decision in <span className="mono">{d.word_decision_stable}/{d.word_decision_periods}</span> periods
                        {rate != null && <> (<span className="mono">{(rate * 100).toFixed(0)}%</span>)</>}.{" "}
                        {d.word_check_unstable
                          ? "Well below 100%: sampling noise, not the basis, is deciding exclusions — they are not reliable."
                          : "This only rules out sampling noise. It does not show the word check agrees with real search: in testing, breaks it excluded passed a 50-decoy false-accept test."}
                      </div>
                      <div className="text-xs rounded px-3 py-2.5 border border-ink-700 text-ink-400 leading-relaxed">
                        <b>{excluded.length}</b> measured break(s) had every negative control holding but were excluded by the word check
                        (attacker word basis more than {d.word_factor}× the honest doctor's). They are neither trusted breaks nor survivals.
                        {excluded.length > 0 && (
                          <div className="overflow-x-auto mt-2">
                            <table className="text-[11px] mono">
                              <thead>
                                <tr className="text-ink-500 text-left">
                                  <th className="pr-3">n</th><th className="pr-3">J</th><th className="pr-3">repeat</th>
                                  <th className="pr-3">period</th><th className="pr-3">attacker/honest</th>
                                  <th className="pr-3">attacker word_gs</th><th>honest word_gs</th>
                                </tr>
                              </thead>
                              <tbody>
                                {excluded.map((e) => (
                                  <tr key={`${e.key}|${e.period}`} className="text-ink-300">
                                    <td className="pr-3">{e.n}</td><td className="pr-3">{e.J}</td><td className="pr-3">{e.repeat}</td>
                                    <td className="pr-3">{e.period}</td>
                                    <td className="pr-3 text-amber-400">{e.word_ratio != null ? e.word_ratio.toFixed(2) : "n/a"}</td>
                                    <td className="pr-3">{e.word_gs != null ? e.word_gs.toFixed(1) : "—"}</td>
                                    <td>{e.honest_word_gs != null ? e.honest_word_gs.toFixed(1) : "—"}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })()}
              </Card>

              <Card title={`Conclusion (trusted cells only, gate: ${results.gate})`}>
                <p className="text-sm text-ink-200 leading-relaxed">{results.conclusion}</p>
                <div className="flex gap-3 mt-4 flex-wrap text-xs">
                  {Object.entries(results.counts).map(([k, v]) => (
                    <div key={k} className="border border-ink-800 rounded px-2 py-1">
                      <span className="text-ink-500">{k}: </span>
                      <span className="mono text-ink-200">{v}</span>
                    </div>
                  ))}
                </div>
                <div className="flex gap-2 mt-4">
                  <a href={api.sweepExportUrl(results.job_id, "csv")} download
                    className="text-sm px-3 py-1.5 rounded border border-ink-700 text-ink-300 hover:text-ink-100">
                    Download CSV
                  </a>
                  <a href={api.sweepExportUrl(results.job_id, "jsonl")} download
                    className="text-sm px-3 py-1.5 rounded border border-ink-700 text-ink-300 hover:text-ink-100">
                    Download raw JSONL
                  </a>
                </div>
              </Card>

              <Card title="Plot A — outcome heatmap"
                subtitle={`break_rate per cell; ${results.config.repeats} repeats/cell, records/period=${results.config.records_per_period}`}>
                <div className="space-y-5">
                  {results.plots.plot_a.panels.map((panel) => (
                    <div key={`${panel.variant}|${panel.reducer}`}>
                      <div className="text-xs text-ink-400 mb-2">
                        H1 = <span className="mono">{panel.variant}</span> · attacker reducer = <span className="mono">{panel.reducer}</span>
                      </div>
                      <Heatmap panel={panel} />
                      <ExportButtons
                        filename={`plotA_heatmap_${panel.variant}_${panel.reducer}`}
                        getSvg={() => {
                          const h = heatmapSvg(panel);
                          const title = `Plot A — outcome heatmap (H1=${panel.variant}, attacker=${panel.reducer})`;
                          return { svg: framedSvg(h.svg, h.width, h.height, title, caption), width: h.width, height: h.height + 68 };
                        }}
                      />
                    </div>
                  ))}
                </div>
              </Card>

              <Card title="Plot B — word-basis norm vs usability threshold"
                subtitle="Mean ± sd over trusted repeats. The word basis is what SamplePre actually consumes — this is WHY cells survive or break.">
                {Object.entries(results.plots.plot_b).map(([key, series]) => (
                  <div key={key} className="mb-4">
                    <div className="text-xs text-ink-400 mb-2 mono">{key}</div>
                    {series.length === 0 ? (
                      <p className="text-xs text-ink-500">No trusted repeats to plot.</p>
                    ) : (
                      <>
                      <div ref={(el) => { plotBRefs.current[key] = el; }}>
                        <ResponsiveContainer width="100%" height={260}>
                          <LineChart margin={{ top: 8, right: 16, bottom: 24, left: 8 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#2a2a30" />
                            <XAxis type="number" dataKey="periods_back" allowDecimals={false}
                              domain={["dataMin", "dataMax"]}
                              stroke="#8a8a94" fontSize={11}
                              label={{ value: "periods back from compromise", position: "insideBottom", offset: -12, fill: "#8a8a94", fontSize: 11 }} />
                            <YAxis stroke="#8a8a94" fontSize={11}
                              label={{ value: "word_gs", angle: -90, position: "insideLeft", fill: "#8a8a94", fontSize: 11 }} />
                            <Tooltip contentStyle={{ background: "#16161a", border: "1px solid #2a2a30", fontSize: 12 }} />
                            <Legend wrapperStyle={{ fontSize: 11 }} />
                            {series.map((s, i) => {
                              const colour = ["#5b9dff", "#4ade80", "#f472b6", "#fbbf24"][i % 4];
                              return [
                                <Line key={`w${s.n}`} data={s.points} dataKey="word_gs_mean" name={`word_gs n=${s.n}`}
                                  stroke={colour} strokeWidth={2} dot={{ r: 3 }} isAnimationActive={false}>
                                  <ErrorBar dataKey="word_gs_sd" width={4} strokeWidth={1} stroke="#8a8a94" />
                                </Line>,
                                // The usability threshold depends on n (sigma scales with
                                // dimension), so each n is compared against its OWN line.
                                <Line key={`t${s.n}`} data={s.points} dataKey="threshold" name={`threshold n=${s.n}`}
                                  stroke={colour} strokeDasharray="5 4" strokeWidth={1.5} dot={false} isAnimationActive={false} />,
                              ];
                            })}
                          </LineChart>
                        </ResponsiveContainer>
                      </div>
                      <RechartsExport
                        containerRef={{ get current() { return plotBRefs.current[key]; } }}
                        title={`Plot B — attacker word_gs vs usability threshold (${key})`}
                        caption={caption}
                        filename={`plotB_wordgs_${key.replace("|", "_")}`}
                      />
                      </>
                    )}
                  </div>
                ))}
              </Card>

              {results.config.reducers.length > 1 && (
                <Card title="Plot C — tooling sensitivity (LLL vs BKZ attacker)"
                  subtitle="Mean break_rate across cells at each n, per attacker reducer">
                  <div ref={plotCRef}>
                  <ResponsiveContainer width="100%" height={260}>
                    <BarChart data={results.plots.plot_c} margin={{ top: 8, right: 16, bottom: 24, left: 8 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#2a2a30" />
                      <XAxis dataKey="n" stroke="#8a8a94" fontSize={11}
                        label={{ value: "lattice dimension n", position: "insideBottom", offset: -12, fill: "#8a8a94", fontSize: 11 }} />
                      <YAxis domain={[0, 1]} stroke="#8a8a94" fontSize={11}
                        label={{ value: "mean break_rate", angle: -90, position: "insideLeft", fill: "#8a8a94", fontSize: 11 }} />
                      <Tooltip contentStyle={{ background: "#16161a", border: "1px solid #2a2a30", fontSize: 12 }} />
                      <Legend wrapperStyle={{ fontSize: 11 }} />
                      {results.config.reducers.map((r, i) => (
                        <Bar key={r} dataKey={r} name={`attacker: ${r}`} fill={["#5b9dff", "#f472b6"][i % 2]} isAnimationActive={false} />
                      ))}
                    </BarChart>
                  </ResponsiveContainer>
                  </div>
                  <RechartsExport containerRef={plotCRef} title="Plot C — tooling sensitivity: mean break_rate vs n, LLL vs BKZ attacker"
                    caption={caption} filename="plotC_tooling" />
                </Card>
              )}

              <Card title="Plot D — dimension trend"
                subtitle="How many cells broke / survived / were untrusted at each n">
                <div ref={plotDRef}>
                <ResponsiveContainer width="100%" height={260}>
                  <BarChart data={results.plots.plot_d} margin={{ top: 8, right: 16, bottom: 24, left: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#2a2a30" />
                    <XAxis dataKey="n" stroke="#8a8a94" fontSize={11}
                      label={{ value: "lattice dimension n", position: "insideBottom", offset: -12, fill: "#8a8a94", fontSize: 11 }} />
                    <YAxis allowDecimals={false} stroke="#8a8a94" fontSize={11}
                      label={{ value: "cells", angle: -90, position: "insideLeft", fill: "#8a8a94", fontSize: 11 }} />
                    <Tooltip contentStyle={{ background: "#16161a", border: "1px solid #2a2a30", fontSize: 12 }} />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                    <Bar isAnimationActive={false} dataKey="broke" stackId="a" name="break" fill="#ef4444" />
                    <Bar isAnimationActive={false} dataKey="survives" stackId="a" name="survives" fill="#4ade80" />
                    <Bar isAnimationActive={false} dataKey="untrusted" stackId="a" name="untrusted" fill="#f59e0b" />
                    <Bar dataKey="error" stackId="a" name="error/skipped" fill="#4b4b55" isAnimationActive={false} />
                  </BarChart>
                </ResponsiveContainer>
                </div>
                <RechartsExport containerRef={plotDRef} title="Plot D — dimension trend: cells per outcome vs n"
                  caption={caption} filename="plotD_dimension" />
              </Card>

              <Card title="Per-cell detail">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm mono">
                    <thead>
                      <tr className="text-left text-ink-500 text-xs uppercase">
                        <th className="pb-2 pr-3">n</th>
                        <th className="pb-2 pr-3">J</th>
                        <th className="pb-2 pr-3">variant</th>
                        <th className="pb-2 pr-3">reducer</th>
                        <th className="pb-2 pr-3">outcome</th>
                        <th className="pb-2 pr-3">break_rate</th>
                        <th className="pb-2 pr-3">trusted</th>
                        <th className="pb-2">broken periods / error</th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.cells.map((c) => (
                        <tr key={`${c.n}|${c.J}|${c.variant}|${c.reducer}`} className="border-t border-ink-800">
                          <td className="py-1.5 pr-3">{c.n}</td>
                          <td className="py-1.5 pr-3">{c.J}</td>
                          <td className="py-1.5 pr-3 text-ink-400">{c.variant}</td>
                          <td className="py-1.5 pr-3 text-ink-400">{c.reducer}</td>
                          <td className={`py-1.5 pr-3 ${OUTCOME_STYLE[c.outcome]?.text}`}>{c.outcome}</td>
                          <td className="py-1.5 pr-3">{c.break_rate != null ? c.break_rate.toFixed(2) : "—"}</td>
                          <td className="py-1.5 pr-3 text-ink-400">{c.trusted_repeats}/{c.repeats_expected}</td>
                          <td className="py-1.5 text-ink-400 text-xs">
                            {c.broken_periods_l2?.length ? JSON.stringify(c.broken_periods_l2) : ""}
                            {c.errors?.length ? c.errors[0].slice(0, 90) : ""}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Card>
            </>
            );
          })()}
        </>
      )}
    </div>
  );
}
