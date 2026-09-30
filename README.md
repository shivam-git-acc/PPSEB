# PPSEB Analysis Lab

https://chatgpt.com/share/6ab67073-41cc-83ee-8451-94f2fefe725b


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

### n × q grid (Batch Sweep → "n × q grid")

For each (n, q), with m = 2n·⌈log2 q⌉ derived per cell, the grid checks that the
honest doctor's chain is correct: A·T ≡ 0, matching and non-matching keywords
verify correctly, search returns the right record, decryption round-trips, and
the period basis is under the usability threshold. Only then does it run two
attacks: one using the **public key only**, and the **stolen-key** backward
attack. A public-key-only break outranks a stolen-key break, because it means
no secret was needed. The negative control is a genuine short trapdoor for an
unrelated lattice, which must not find the doctor's record.

- The default q list is 257, 1153, 4001. The original 4099 can't work for
  n=4 or 8: `x^n − c` is never irreducible when 4 | n and q ≡ 3 (mod 4).
- Cells take minutes, not seconds. At n=4, cells took 96–285s; n=8 is much
  slower. The per-cell timeout defaults to 1 hour, and a timed-out cell is
  "untested", never "secure".
- The honest word-basis-vs-threshold number is shown but not used as a gate
  (it's the check PATCH 09 found to be wrong).

### Public-Key Break tab

Shows the consequence of the parameter finding concretely: holding only the
public key, the public ciphertext database and a list of diseases, the attacker
labels each encrypted record with its disease. Measured at the paper's
parameters (n=4, q=257) it recovers every record's tag — and, with that same
basis, the full record plaintexts — at LLL-level effort (BKZ block size 2),
while a basis from an unrelated lattice recovers nothing. The attack receives no
secret key: `PeriodDB` carries none, and a test runs it with the honest key
replaced by an object that raises if touched. Keyword recovery and plaintext
recovery are reported as separate claims, the latter only when Decrypt actually
round-trips.

### Security Boundary tab

Runs **both** attacks on each (n, q) of a wide grid — n ∈ {4, 8, 16},
q ∈ {257, 1153, 4001, 12289, 40961} — against the *same* frozen earlier-period
database, and plots the measured outcome against an estimated bit-security
axis. Attack 1 holds only the public key. Attack 2 steals the current period's
secret key sk_r|J (J = 3 by default) and transforms it backward by the public
R-product. Each attack climbs its own BKZ block-size ladder under its own
budget.

The verdict per cell is **relative**, and that is the point:

| both attacks | verdict |
|---|---|
| control passed | `untrusted` (excluded from every count) |
| public key broke it | `BROKEN (public-key only)` — the theft was redundant |
| public key failed, stolen key broke it | `forward-security break (stolen key REQUIRED)` |
| either ran out of budget | `unmeasured (timeout)` — never "secure" |
| both ran to completion, neither broke | `attack failed (secure vs both, this budget)` |

Only the third row demonstrates forward security failing. The tab counts those
cells explicitly, and says so plainly when there are none.

- Each cell runs in its own subprocess so the hard timeout can kill a running
  BKZ. Small fast cells (n ≤ 8, q ≤ 1153) run 2 repeats, the rest 1; a break in
  any repeat is a break, and a timeout can never overwrite one or be read as a
  survival.
- Results append to `backend/results/secbound_<job_id>.jsonl` per cell, with
  `secbound_<job_id>.meta.json` for status. "Resume" re-runs nothing that
  already finished. There is also an overall wall-clock cap (default 9 h): when
  it is hit the job checkpoints and stops, and the cells it never reached are
  simply absent — not reported as secure.
- q = 4099 (asked for in the patch) is impossible here: H2's twisted binomial
  needs q ≡ 1 (mod 4) when 4 | n, and 4099 ≡ 3 (mod 4), so every n in the grid
  would be n/a. q = 4001 is substituted, and the substitution is carried in the
  job config, the conclusion text and the UI.
- The bit axis is an *estimate* (root-Hermite fit; the lattice-estimator
  backend needs SageMath and is reported as unavailable rather than faked); the
  break/no-break outcome is *measured*. They are never merged.

### Network tab

The whole scheme staged as four live nodes — doctor, cloud, verifier, attacker
— driven by hand. The doctor stores records (PEKS keyword + encrypted record)
under the current period key, searches (trapdoor → verifier → matching record
number), advances the period (KeyExt) and decrypts any stored record. The
cloud is dumb storage. The verifier runs the **public** Verify, which is
exactly what makes both attacks possible.

The attacker picks an attack and ticks which periods to hit:

- **Public-key only** — a basis built from `pk_r|i` and reduced. No secret.
- **Stolen key** — one period's secret key is stolen and transformed backward
  by the public R-product. Reaching *forward* is rejected; only periods
  earlier than the theft are tickable.

Every stolen-key period also reports whether the public key alone would have
recovered it, so the demo can never imply the theft was necessary when it was
not. A period is flagged as a genuine forward-security break only when the
stolen key recovered it **and** the public key alone did not.

Honesty rules, enforced in the data:

- The attack is handed a period view whose records tuple is **empty** — no
  keyword, no plaintext, and (as `PeriodDB` has no such field) no secret key
  can reach it. Scoring against the truth happens outside the attack.
- Attacker plaintext is shown only when Decrypt with the attack-derived basis
  round-trips; otherwise the row reads "keyword ✓ / plaintext ✗ (decode
  bound)". The doctor's decrypt is always real.
- Stored blobs are hashed when written and re-checked after every attack, so
  an attack that regenerated a ciphertext would be caught.
- A period whose attack exceeds its budget reads "unmeasured (timeout)", never
  "secure". The budget is checked between dictionary words, so one long
  reduction can overrun it; the measured runtime is always reported.
- The "use a garbage key" toggle runs the same flow from an unrelated
  lattice's basis. It must recover nothing.
- Decrypting a record from an *earlier* period uses a key that forward
  security assumes was deleted. The simulator keeps it so the true plaintext
  can sit beside the attacker's attempt, and says so on screen rather than
  implying the scheme allows it.

`n` and `q` are selectable from the same grid as the Security Boundary tab,
with `m = 2n⌈log2 q⌉` derived live. A pair H2 cannot support, or one where the
honest scheme fails its correctness gate, comes back "not available" with the
reason instead of a broken demo. **"Run demo script"** walks the whole story
hands-free: store records → honest search and decrypt → evolve the key →
public-key attack → stolen-key attack with the comparison strip → garbage
control.

Note on reuse: PATCH 18 describes the stolen-key backward attack as new. It
already existed here (`attacks/end_to_end.py`, and on the boundary axis in
`attacks/boundary.py`), so this tab calls that tested code rather than keeping
a second copy of the R-product transform.
