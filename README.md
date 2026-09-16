# PPSEB Analysis Lab

An interactive lab for analyzing the PPSEB paper (Xu et al., 2022) — a
lattice-based searchable-encryption scheme on blockchain — and demonstrating
three concrete findings against it:

1. **Keyword-guessing attack (KGA)** — recovers a searched keyword using only
   public data (pk, one captured trapdoor, a guess dictionary). LWE hardness
   and the blockchain don't prevent it: the vulnerability is structural to
   public-key PEKS with a secret-free tester.
2. **Forward-security norm experiment** — shows that "stealing today's key
   reveals yesterday's key" reduces entirely to a measured Gram-Schmidt norm
   against a usability threshold, not to any hardness assumption.
3. **Specification defect** — Algorithm 2 (KeyExt) is not executable as
   printed (two circular variable references); a single-step, non-circular
   correction is derived from the paper's own Lemma 5 and Algorithm 4.

The full build specification — architecture, the exact corrected crypto, the
trace format, and the UI — lives in [`CLAUDE.md`](CLAUDE.md).

## Project layout

```
backend/    Python (FastAPI) — the lattice crypto + the three attacks
frontend/   React (Vite) + Tailwind — the lab UI
```

## Running

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn api:app --reload --port 8000
```

The API is now at `http://127.0.0.1:8000` (docs at `/docs`, health check at
`/api/health`).

`requirements.txt` also lists `fpylll`/`cysignals` as optional (Linux-only):
they give the Forward Security tab's dimension-scaling sweep real BKZ
reduction for the legitimate key chain. If they fail to install (no network,
or missing build tools), the sweep automatically falls back to the lab's own
LLL at a stronger reduction factor — nothing else in the app depends on them.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open the printed Vite URL (default `http://localhost:5173`). The dev server
proxies `/api/*` to `http://127.0.0.1:8000`, so start the backend first.

### Using the lab

1. **Left rail** — set `n`, `q`, `sigma`, `l` (or keep the tiny demo defaults:
   n=4, q=257, sigma=4.0, l=10) and click **Apply / Regenerate keys**.
2. Work through the tabs: **Overview → Happy Path → KGA Attack →
   Forward Security → Spec Defect**. Every button press produces a trace,
   rendered live in the right-hand panel — nothing is mocked in the frontend.

## Tests

```bash
cd backend
source .venv/bin/activate
PYTHONPATH=. pytest tests/ -q
```

Covers: mod-q linear algebra and LLL reduction, TrapGen, H1/H2 hash
constructions, the trapdoor samplers, the seven scheme algorithms (matching
keyword verifies, non-matching rejects, record encrypt/decrypt round-trips,
a noise-sweep correctness check), and all three findings (KGA recovery,
forward-security norm table, paper-vs-corrected KeyExt), plus a FastAPI
smoke test of the full happy path through every endpoint.

## Notes on the crypto

Every deviation from the paper (unspecified hash constructions, the
must-be-shared B_j, the q/4-vs-q/5 decode threshold, the KeyExt circularity
fix, the low-norm requirement on H2's FRD encoding) is implemented as a
documented correction and logged as a `correction`/`note` event in the trace
— visible in the UI, not hidden in the code. See `CLAUDE.md §3` for the full
list and rationale, and `backend/ppseb/` / `backend/attacks/` for the
implementation.

Parameters are deliberately tiny (n=4, q=257 by default) so every matrix and
every step fits on screen and every operation completes in a couple of
seconds — this is an analysis instrument, not a production implementation.

## Batch Sweep (overnight runs)

The **Batch Sweep** tab runs the end-to-end forward-security attack over a grid
(n × J × H1 variant × attacker reducer × repeats) as a server-side background
job. Every completed run is appended to `backend/results/sweep_<job_id>.jsonl`
(with `sweep_<job_id>.meta.json` for status), so you can close the browser. If
the server dies mid-run it resumes the job on its next start and skips
anything already on disk. `backend/results/` is git-ignored.

Things to know before launching a long run:

- **Only powers of 2 work for n at q=257.** H2's construction needs every prime
  factor of n to divide q-1 = 256. The pre-flight panel lists the cells that
  are guaranteed to error (PATCH 08's suggested n=6 and n=10 included) and
  leaves them out of the ETA.
- **Trust gate, chosen when you read results (nothing is re-run).** *strict*
  (the headline) counts a break only if the negative controls failed and the
  attacker's word basis is within 3× the honest doctor's at that period.
  *controls only* drops that word check. The word check is stable under
  sampling noise (the Results view shows this), but it is a norm proxy, not a
  test of search: in testing, breaks it excluded at ratios 6.8 and 8.0 still
  passed a 50-decoy false-accept test. The Results view lists every excluded
  break with its ratio, and the conclusion won't call a run a negative result
  while any exist.
- Plots A–D export as SVG/PNG, and the raw data as CSV/JSONL.
