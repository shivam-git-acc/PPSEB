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

A system layer built on top of this lab, **MedVault-PQ**, is included: a
patient-controlled, searchable share of medical records whose five defensive
mechanisms each close one of the findings above. It is the first tab group in
the UI (Demo / Patient / Doctor / Auditor / Evidence) and lives in
`backend/medvault/`. Its tracker, claims policy and measured numbers are in
[`../task.md`](../task.md) and
[`backend/results/summary.md`](backend/results/summary.md).

## Project layout

```
backend/    Python (FastAPI) — the lattice crypto + the three attacks
            medvault/ — the system layer (M1-M8) and its tests in tests/medvault/
frontend/   React (Vite) + Tailwind — the lab UI
circuits/   M6 — Circom circuit + snarkjs/Groth16 dev setup (generated build/)
contracts/  M4/M6 — ConsentRegistry.sol on a local Hardhat chain (opt-in)
docs/       security-games.md (the games the paper lacks, each tied to a test)
            design-only-fixes.md (Module-LWE, ORAM, forward security, ZK well-formedness)
```

## Running

### Entire MedVault-PQ demo in one command (Windows)

```bat
start.cmd                 :: backend + frontend, in-process ledger
start.cmd --with-chain    :: also a local Hardhat chain, so gas is measured
```

Then open `http://localhost:5173`; the **MedVault** group is the first tab group
and **Demo** runs all nine steps in one call. The same sequence from the command
line:

```bash
cd backend
python -m medvault.demo          # nine steps; writes results/demo_trace.latest.json,
                                 # and replaces the committed demo_trace.json only on a clean 9/9 pass
python -m medvault.repro         # every evaluation table, writes results/repro.json
```

The Demo tab's **Replay saved trace** reads the committed golden trace from the
backend, and falls back to a copy bundled into the UI build when the backend is
down or does not answer within 5 seconds.

### MedVault-PQ: what each fix closes, and what it does not

Numbering follows the mid-sem deck (findings 1–10). The paper's model covers
one game; [`docs/security-games.md`](docs/security-games.md) writes down the
others (G0–G8), each with its measured outcome per mode and the test that runs
it, and [`docs/design-only-fixes.md`](docs/design-only-fixes.md) covers the fixes
that were not built. `tests/medvault/test_docs_references.py` fails if a cited
test is renamed or removed.

| Deck finding | Fix in MedVault-PQ | Closes | Does **not** close |
| --- | --- | --- | --- |
| 3 · Offline KGA | Mode B: keyed HMAC tokens, per doctor and epoch, never on-chain | Outsider and keyless-server guessing: 0 successes in every trial (`repro.json → kga_trials`). An unkeyed-hash control succeeds on every keyword, so the **key** is the fix, not the hashing | An authorised insider: 100 % inside their own scope, by design. Mode B replaces PPSEB's public tester rather than repairing it; the deck's PAEKS fix is S2 |
| 3 · Offline KGA, keeping PPSEB | Mode C, PAEKS-style: PPSEB's unchanged PEKS / Trapdoor / Verify on `HMAC(K_pd, keyword)`, with `K_pd` the per-doctor per-epoch key from the ML-KEM envelope | With the trapdoor **on-chain** and Verify **public**, outsider and keyless chain node 0/20 each (`repro.json → mode_tradeoff`). Revocation works through the key: a revoked doctor's request is accepted but matches nothing | Insider 17/20 (2 trapdoors fail on their own keyword, 1 false-positive Verify match: toy-parameter effects). Mode C authenticates keywords, not requests or ciphertexts: replay and planting still succeed. It is in the spirit of Huang–Li PAEKS (the deck's fix), not that pairing scheme, and has no proof. Same cost as mode A: ≈ 0.7–0.9 s per search, ≈ 5.9 KB per entry, vs mode B's 0.35 ms and 96 B |
| 3 · Offline KGA, baseline | Mode A (PPSEB, toy n = 4, q = 257) | — | Measured as a rate over every dictionary keyword: the attack finds the keyword on every trial where the honest search works. The misses are trapdoors that fail Verify on their own keyword's ciphertext, a toy-parameter correctness failure the doctor suffers as well (deck: "the margin law") |
| 5 · Universal-ciphertext forgery | (a) Mode B: no universal entry can exist, since an HMAC entry matches exactly one token; entry writes must carry the owning patient's signature. (b) Mode A′: PPSEB plus a cheap CT₂ shape check on writes (`medvault/wellformed.py`), the stopgap the deck names | (a) Outsider planting, and any "matches everything" entry in mode B. (b) The paper's canonical `CT₂ = 0` forgery and every forgery with a short CT₂ column; 0 honest ciphertexts refused (`repro.json → shape_check`) | As the deck says, **a signature proves who sent an entry, not that it is well formed**: a registered but malicious patient can still poison their own index. The shape check is necessary, not sufficient: it cannot tell an honest uniform-looking CT₂ from a dishonest one. Closing finding 5 for an open, public ledger needs a ZK well-formedness proof (design only) |
| 6 · Access-pattern leakage | Mode B: the chain stores one commitment per search, never the trapdoor or the matched records; PIR hides retrieval from storage. Measured with the mid-sem Tier 1 / Tier 2 attacks, **unchanged**, on MedVault's own logs (`medvault/leakage.py`, 10 seeds, 20 records, 300 searches) | Chain observer. PPSEB-style mode A chain: Tier 1 groups 100 % pure, Tier 2 labels 0.715 of records vs chance 0.17 (10/10 seeds). Mode B chain: no record ever visible, Tier 2 0.19 vs chance 0.18 (0/10) | **The search node.** It still sees tokens and matches (R11.10): Tier 2 0.755, 10/10. Cover queries (real searches, scheduled to flatten keyword counts) lower that to 0.355 at 2× and 0.335 at 4× extra searches, still above chance in 4–5 of 10 seeds, and leave Tier 1 at 100 %: co-access and group sizes are untouched by frequency smoothing. Hiding co-access needs oblivious search (ORAM), design-only |
| 7 · Replay | Signed, nonce-bound, epoch-checked **search and retrieval** requests; one per-doctor counter covers both; signatures are domain-separated | Re-sending a captured search (`reused_nonce`) and re-sending a captured fetch to pull the record again (`reused_nonce`); a search signature cannot be presented as a fetch signature | Nothing beyond the doctor's own device: a stolen signing key is out of scope |

Neither needs network access. The circuit in `circuits/build/` is generated and
gitignored; rebuild it with `npm --prefix circuits install && npm --prefix
circuits run build` (about a minute) if it is missing — without it the system
falls back to the labelled signed consent mode. Gas needs a chain:
`npm --prefix contracts install && npm --prefix contracts run compile`, then
`npm --prefix contracts run node`.

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

The system layer has its own suite:

```bash
cd backend
python -m pytest tests/medvault -q      # ~4.2 minutes, 175 passed (with a local chain)
```

`tests/medvault` covers properties 1-25: AES-GCM and Merkle fail-closed
behaviour, ML-KEM envelope sealing, keyed search and the five gateway gates,
consent and revocation, PIR round trips and server-view regressions, real
Groth16 proofs (including nullifier reuse), the lattice epoch tree, the attack
harness, traceability per finding, and the nine-step demo. The eight chain tests
skip when no local node is running; everything else runs offline.

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
  *controls only* drops that word check. The Results view lists every excluded
  break with its ratio, and the conclusion won't call a run a negative result
  while any exist.
  - The word check used to exclude breaks at ratios 6.8 and 8.0, which made it
    look too strict — those breaks still passed a 50-decoy false-accept test.
    That was the sublattice bug (below) inflating the attacker's basis, not a
    flaw in the gate: since the repair the measured ratios are ~1.0 and nothing
    is excluded. Results produced before 2026-09-30 carry the inflated ratios.
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

### Sublattice repair in the backward attack (2026-09-30)

The stolen-key backward attack computes `P⁻¹ · sk_J`, where `P⁻¹` is the
public R-product inverse taken **mod q**. Every column of that product lies in
`L⊥_q(pk_i)` — the membership check passes — but the columns do not *generate*
that lattice: as an integer matrix `P⁻¹` has a large determinant, and the
candidate spans a sublattice of index about **q²⁸** at n=4, m=72. Reduction
then works correctly on a far sparser lattice and returns honestly-long
vectors, so the attack measured itself as much weaker than it is.

The repair (`ppseb.linalg.q_ary_basis_from_generators`) adjoins the `q·e_j`
vectors — free to anyone holding the public key — and extracts a genuine basis
from the generating set. `ppseb.linalg.q_ary_index_log` reports the index, and
is the one number that distinguishes "this attack is weak" from "this attack is
reducing the wrong lattice".

Measured effect at n=4, q=257 (honest basis ≈ 2.98):

| | before | after |
|---|---|---|
| reconstructed basis, 1 period back | GS 41.97, index q²⁶ | GS 5.22, index 1 |
| reconstructed basis, 2 periods back | GS 50.29, index q²⁸ | GS 6.26, index 1 |
| attacker/honest word-basis ratio | 3.15 – 7.97 | 0.95 – 1.30 |
| periods broken (8 seeds, J=2) | mixed, many excluded | [0, 1] at every seed |

This strengthens Finding 2: the attacker's reconstructed earlier-period key is
indistinguishable in quality from the honest doctor's, so forward security
fails on its own terms rather than being borderline. **Every stolen-key result
produced before this date understates the attacker**, including the wide
boundary sweep; those runs need repeating before they are quoted.

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

### Recovery Analysis tab

The per-attack displays used to report the attack basis's Gram-Schmidt norm,
and it does not predict recovery: in one measured run a basis at GS 6.24
recovered every time while one at GS 5.29 recovered a quarter of the time. The
GS norm is a *distributional bound* on what SamplePre will produce. Verify
consumes one *realized* trapdoor, and accepts exactly when every coordinate of
`CT₁ − Trapᵀ·CT₂` lands within q/4 of q/2.

So every attempt now records the variables that decide the outcome:

| variable | what it is |
|---|---|
| `trap_norm` | ‖Trap‖ of the realized sampled vector — what Verify actually consumes |
| `decode_margin` | `q/4 − max_i dist(y_i, q/2)`; positive exactly when Verify accepts |
| `basis_gs` | the old proxy, kept to show it does **not** predict recovery |
| `recovered` | unchanged: the search returned the doctor's own N₀ on the frozen DB |

`decode_margin` mirrors `scheme.verify` exactly, wrap-around distance included,
and `margin > 0 ⟺ verify() accepts` is asserted rather than assumed
(`test_margin_agrees_with_verify`). The one way `recovered` can differ from a
positive margin is a decoy matching first — a false accept — which is counted
and reported separately rather than allowed to blur the separation.

Sampling noise is removed rather than argued away: many records per period,
many trapdoor draws per basis, and several independent rebuilds, so a period
reports a recovery **rate** instead of one coin flip. The tab shows four plots
— recovery vs ‖Trap‖, the margin histograms for recovered vs failed, the
falsifier (recovery vs basis GS), and a σ-sweep that holds the basis fixed and
widens only the attacker's sampling width, walking the rate down from 1 to 0.

Measured at n=4, q=257 over 1800 attempts (30 records × 50 samples × 3
repeats): a positive margin and Verify accepting coincide on **all 1800**, with
zero false accepts; recovery correlates with ‖Trap‖ at r=+0.74 and with the
decode margin at r=+0.87, but with the basis GS norm at **r=−0.19** — the old
variable points the wrong way. The σ-sweep falls monotonically from 1.00
(‖Trap‖ 77, margin +49) to 0.07 (‖Trap‖ 773, margin −41). The σ-sweep varies
the *attacker's own* sampling width: it demonstrates that recovery follows the
margin, and is not a claim that the scheme weakens, since a real attacker would
pick the smallest σ that works.

A build where the honest doctor's own search fails leaves no baseline to judge
an attacker against, so it is rebuilt with a fresh seed; if it still fails the
repeat is **skipped and reported**, and the auto-statement quotes the repeats
actually *measured*, never the number configured. (`build_frozen_history`'s own
retry cannot help here — it hangs off an assertion that `honest_checks=True`
suppresses — so the retry is done explicitly.)
The Network tab's per-period rows now lead with recovery rate, mean ‖Trap‖ and
mean margin, with the basis GS norm moved into a details expander labelled as a
bound that does not predict recovery.

### Ledger Attacks tab

Three findings that need no crypto break and no secret. They exploit the
paper's own central design choice — public on-chain search — plus two checks it
never specifies: nothing authenticates who submits a trapdoor or fetches a
record, and nothing checks that a stored ciphertext is well formed. All are
**parameter-independent**: they hold even if the lattice were secure. The
preconditions are asserted by `test_flow_matches_the_paper`, so if
authentication were ever added to this implementation the tests fail loudly
rather than the findings quietly becoming wrong.

**A · Replay** (confidentiality). A trapdoor is a public transaction. Re-submit
it and the same Verify returns the same sequence number, and the cloud hands
over the record, because nothing asks who is asking. Measured: identical result
to the doctor's; a random vector in place of a captured trapdoor matches
nothing. Replay yields the record's **identity and ciphertext, not plaintext** —
decryption still needs a key.

**B · Access-pattern leakage** (confidentiality), in two halves that behave very
differently:

| | needs a prior? | measured |
|---|---|---|
| Tier 1 — recover *which records share a disease* | no | **100% pure groups, every run, down to 10 queries** |
| Tier 2 — name *which disease* | yes (public prevalence) | 0.40–0.95, mean 0.725 vs ~0.18 chance, 6/6 seeds |

Tier 1 groups records by co-access: records answering exactly the same
transactions carry the same keyword. That is exact and needs nothing but the
ledger. Tier 2 then matches those groups against a public prevalence table —
and is brittle, because the match is positional: one adjacent swap near the top
shifts every group after it. At 16 records / 200 queries it can collapse to
exactly 0.000. Off-distribution (the attacker's prior is wrong) it falls to
~0.067. Accuracy is always reported beside a random baseline drawn from the
same label distribution, and the UI shows the measured range so a single run
cannot be read as the headline. `tier2_label` takes only the ledger, the public
prevalence table and the record ids — there is no parameter through which the
ground-truth map could arrive.

**C · Universal-ciphertext plant** (integrity / DoS). `CT₂ = 0` makes
`y = CT₁` for *any* trapdoor, so `CT₁ = ⌊q/2⌋·1` sits exactly on the decision
point and matches everything. Measured: the planted entry matched **200/200**
arbitrary trapdoors and every real search, while a random ciphertext matched
**0/200** — the control is what rules out a merely permissive Verify. It
reveals no keyword, so it is classified integrity, not confidentiality.
Authenticated writes mitigate it only while no patient is compromised;
verifying well-formedness mitigates it even then.

The framing: classical PEKS leaks the access pattern to one private server.
Putting verification on a public chain broadcasts it to everyone — the paper's
contribution is what makes this leakage public.

### Proof Analysis tab

Two attacks on the paper's Section 5 proof itself, rather than on the scheme.

**A · Reduction loss.** Theorem 1 reduces ciphertext indistinguishability to
LWE with an explicit loss — the challenger solves LWE with probability about
p/2m, the 1/m coming from guessing the break-in period. Read as a guarantee
that is `λ_scheme ≥ λ_LWE − log₂(2m)`, so the theorem gives away log₂(2m) bits.
Measured over the lab's own grid:

| n | q | m | LWE bits (est) | loss | guaranteed | verdict |
|---|---|---|---|---|---|---|
| 4 | 257 | 72 | ≤14.6 | 7.2 | **≤7.4** | negligible |
| 8 | 257 | 144 | ≤14.6 | 8.2 | ≤6.4 | negligible |
| 16 | 12289 | 448 | 29.8 | 9.8 | 20.0 | negligible |
| 256 | 12289 | 7168 | — | 13.8 | — | unquantified |

At the paper's own demonstration parameters the theorem guarantees **at most
~7 bits** — roughly 2⁷ operations. Three things are kept distinct and are
stated on the tab:

- This is what the **theorem guarantees**, not what we measured to break. A
  loose proof is not a broken scheme; the measured break is the separate
  Public-Key result. The implication runs one way.
- The figure is **negligible, not vacuous**. It is positive, so calling it
  vacuous would overstate it; it gets its own band instead.
- The LWE number is an **upper bound** wherever the root-Hermite fit is below
  its trustworthy range, which makes the guarantee an upper bound too. Rows the
  fit cannot reach at all report nothing rather than a zero — that is a gap in
  the estimator, not a security claim.

**B · Coverage map.** For each threat: the attack in this tool that
demonstrates it is real, and the point in the paper's §5.2 game where the model
cannot express it. The two columns are labelled **DEMONSTRATED** (measured
here) and **ANALYSIS** (argued from the paper's text, not executed), so nobody
reads the second as a run.

The attack column is pulled from stored results — the Public-Key and Ledger
tabs record what they measured, and the boundary sweep is read off disk. A
threat with no stored run shows "run that tab" and links to it, **never a
fabricated number**; `test_coverage_pulls_live_results` asserts an unpopulated
row contains no digits at all.

Of seven threats the game expresses one: the one it proves. Key recovery,
offline keyword guessing, universal-ciphertext forgery, trapdoor replay and
access-pattern leakage all fall outside it, and forward security appears in the
game's setup but is never proven as its own statement. "No" means the game
cannot express the threat — not that the scheme is unconditionally insecure;
for key recovery specifically it is the game's premise (LWE hard) that fails at
these parameters, not its reasoning.
