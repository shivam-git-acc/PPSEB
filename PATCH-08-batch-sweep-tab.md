# PATCH 08 — "Batch Sweep" tab: overnight multi-config run, saved results, final plots

> Apply after PATCH-07. Purpose: a NEW top-level tab that runs the end-to-end
> forward-security attack across a large grid of configurations UNATTENDED (overnight),
> checkpoints progress to disk, and produces publication-quality plots + a written
> conclusion the user reads in the morning. Long runtime is EXPECTED and fine.
>
> This reuses PATCH-06 `run_end_to_end` and PATCH-07 per-cell trust gates. It adds:
> persistence (results survive a crash/restart), a background job, and a results
> viewer with static plots + exportable data.
>
> GUARDRAILS (inherited, enforced per cell, non-negotiable): frozen DBs; attacker
> reads only stolen sk + public; Level-2 = same N0; word-basis cross-check must AGREE;
> negative control must fail; untrusted cells EXCLUDED from the conclusion; skipped/
> errored cells never counted as "survives". The overnight conclusion must rest ONLY
> on trusted cells — no human is watching, so the gates must be strict.

---

## 1. New tab: "Batch Sweep"

Top-level tab alongside Overview / Happy Path / KGA / Forward Security / Spec Defect.
Two sub-views: **Configure & Run** and **Results**.

---

## 2. Configure & Run

Inputs (with sensible defaults for an overnight run):
- `n_values`: default `[4, 6, 8, 10]`   (10 is slow; that's fine overnight)
- `J_values`: default `[3, 4, 5, 6, 8]`
- `h1_variants`: default `["low_norm"]` (optionally add `"naive_uniform"` to show the
  correctness-collapse contrast in the same batch)
- `reducers`: default `["bkz"]` (optionally add `"lll"` to show tooling sensitivity —
  the LLL-vs-BKZ story from PATCH-04, now swept)
- `records_per_period`: default = the value that fixed the period-3 artifact (e.g. 40)
- `repeats`: default `3` — repeat each cell with different RNG seeds and AGGREGATE, so
  a single lucky/unlucky match doesn't decide a cell (see §5). Overnight budget allows this.
- `seed_base`: for reproducibility.
- No hard time budget by default (overnight), but a "max hours" safety stop that
  checkpoints and halts cleanly.

The full grid = n × J × h1_variant × reducer × repeats. Show the total cell count and a
rough ETA (use PATCH-03 per-period timings: ~3s@n4, ~12s@n6, ~38s@n8, scale up for n10)
so the user knows it's an overnight job before starting.

"Start batch" launches a BACKGROUND job (don't block the request). Return a job_id.

---

## 3. Persistence & checkpointing (so an overnight crash doesn't lose everything)

- Write results to disk incrementally: `backend/results/sweep_<job_id>.jsonl`, ONE line
  per completed (cell, repeat). Append as each finishes — never hold the whole grid in
  memory only.
- Also write `sweep_<job_id>.meta.json`: config, start time, total cells, cells done,
  status (running/done/failed/stopped).
- On restart, if a job was `running`, RESUME: skip cells already in the .jsonl, continue
  the rest. Idempotent — re-running never double-counts (key each record by
  (n,J,variant,reducer,repeat,seed)).
- A per-cell try/except: if one cell throws, record it as `status:"error"` with the
  traceback and CONTINUE — one bad cell must not kill the overnight job.

---

## 4. Job status endpoint + UI polling

```
POST /api/sweep/start   {config}         -> {job_id, total_cells, eta_s}
GET  /api/sweep/status  {job_id}         -> {done, total, status, elapsed_s, eta_s}
GET  /api/sweep/results {job_id}         -> aggregated grid + plot data (see §6)
POST /api/sweep/stop    {job_id}         -> checkpoints and halts
```
- Configure & Run view shows a progress bar (done/total), elapsed, ETA, and a live
  count of trusted / untrusted / error / skipped cells so far.
- Safe to close the tab; the job runs server-side. Reopen and re-poll by job_id.
- Keep a list of past jobs (from the meta files) so morning-you can open last night's.

---

## 5. Repeats & aggregation (robustness)

Each cell runs `repeats` times with different seeds (different frozen DBs / RNG). A
cell's outcome is decided by the aggregate, not one draw:
- `break_rate` = fraction of trusted repeats with a non-empty L2_broken_periods.
- A cell is:
  - **survives** if all trusted repeats survive (break_rate == 0),
  - **break** if break_rate > 0 (report the rate, e.g. "2/3 repeats broke period 3"),
  - **untrusted** if < half the repeats were trusted (guardrails disagreed too often),
  - **error/skipped** otherwise.
- Report break_rate per cell — a break that appears in 1/3 repeats at n=4 is weaker
  evidence than 3/3, and the plot should show that.

This is important: with the earlier period-3 artifact in mind, repeats guard against a
single spurious same-N0 match deciding a cell.

---

## 6. Results view — publication plots + data

Generate STATIC plots (this is the "final plot" deliverable). Use the chart tooling
already in the app (recharts) OR render server-side PNG/SVG for export. Provide:

- **Plot A — outcome heatmap:** x = J, y = n, one panel per (h1_variant, reducer). Cell
  colour = break_rate (0 = green/survives … 1 = red/breaks), untrusted = amber hatch,
  error = grey. This is THE summary figure.
- **Plot B — norm-vs-threshold:** for a chosen (variant, reducer), plot attacker
  `word_gs` (mean over repeats, with error bars) vs the usability threshold, as a
  function of periods_back, for each n. Shows WHY cells survive/break (the word basis
  sits above/below threshold). This is the mechanistic explanation figure.
- **Plot C — tooling sensitivity (if lll+bkz both run):** break_rate vs n for LLL vs
  BKZ attacker. Shows the PATCH-04 tooling-sensitivity story across the grid.
- **Plot D — dimension trend:** number of trusted cells that broke vs n. Does the break
  shrink/grow/vanish with dimension?

Each plot: titled, axis-labelled, legended, with the config (records/period, reducer,
repeats) printed in a caption. Downloadable as PNG/SVG. Also a "Download raw data (CSV
+ JSONL)" button — the underlying numbers for the writeup.

---

## 7. Auto-generated conclusion (trusted cells only)

From the aggregated TRUSTED cells, generate a paragraph filled with measured numbers:

> "Batch sweep over n∈{...}, J∈{...}, {variant(s)}, {reducer(s)}, {repeats} repeats/cell,
> records/period={r}. Of {T} trusted cells, {a} survive (attack recovered no past
> period's search capability) and {b} show a break (break_rate>0), specifically at
> {list cells + rates}. {If b==0:} No trusted configuration yielded a functional
> forward-security break — a consistent negative result across the tested grid under
> fair BKZ tooling. {If b>0:} Breaks are confined to {pattern, e.g. n≤4 / periods within
> k of compromise} and do not appear for n≥{x}. {u} cells were untrusted (guardrail
> disagreement) and {e} errored/were skipped; these are excluded from the conclusion.
> Demonstration parameters throughout; cryptographic-parameter behaviour requires
> large-n BKZ estimates not performed here."

Never claim beyond trusted cells. Never say "all parameters" — say "all tested". Show
the untrusted/error counts openly.

---

## 8. Tests

- `test_checkpoint_resume`: kill mid-run, restart, assert no cell double-counted and the
  rest complete.
- `test_error_cell_continues`: inject a throwing cell; job finishes, cell marked error.
- `test_conclusion_trusted_only`: untrusted/error/skipped cells excluded from counts.
- `test_break_rate_from_repeats`: break_rate = broken_trusted_repeats / trusted_repeats.
- `test_results_persist`: results readable from .jsonl after job object is gone.
- `test_skipped_never_survives`: safety-stopped cells not counted as survives.
- `test_plot_data_shape`: plot payloads (A–D) well-formed for the aggregated grid.

---

## 9. Order
1. Persistence layer (.jsonl + .meta.json, resume logic, per-cell try/except).
2. Background job + status/stop endpoints.
3. Repeats & aggregation with per-cell trust gates (reuse PATCH-06/07).
4. Configure & Run UI (grid inputs, ETA, progress, past-jobs list).
5. Results UI: Plots A–D + auto-conclusion + CSV/JSONL export.
6. Launch defaults (n∈{4,6,8,10}, J∈{3,4,5,6,8}, low_norm, bkz, 3 repeats) as an
   overnight job.
In the morning: open Batch Sweep → Results → read the heatmap + conclusion, export the
figures. Report the heatmap image, the conclusion paragraph, and any untrusted/error cells.
