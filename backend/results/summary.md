# MedVault-PQ — committed result summary

This file is displayable without running anything (Requirement 8.6). The
authoritative numbers live in [`repro.json`](repro.json), which `./repro.sh`
(or `repro.cmd` on Windows) regenerates in about 200 seconds; `--fast` takes
about 40 seconds with one trial per KGA cell and one leakage seed.

**Seed 42. KEM: `pure-python-ml-kem-768-NON-HARDENED`. Ledger backend: `memory-ledger`.**
**Lattice parameters: n = 4, q = 257, σ = 4.0, l = 10 (the key tree: n = 2, q = 257) —
toy values, labelled as such.**
**Proof system: Groth16 over BN254, 3 202 constraints, depth-4 consent tree —
classical, single-party dev setup, not suitable for real use.**
**Finding numbers are the mid-sem deck's 1–10;** [`../../docs/security-games.md`](../../docs/security-games.md)
maps the other numberings and states each attack as a game.

## Index modes

| Mode | What it is |
| --- | --- |
| A | PPSEB as published: public tester, trapdoor and matched records on-chain |
| A′ | A plus a cheap CT₂ shape check on entry writes |
| B | keyed HMAC index per doctor and epoch, signed one-time search **and retrieval** requests, commitments only on-chain |
| C | PPSEB's unchanged PEKS / Trapdoor / Verify on `HMAC(K_pd, keyword)` — PAEKS-style, Verify and trapdoor stay public |

## Attacks, before and after

KGA cells are successes over trials: every dictionary keyword as the secret,
two seeds, 20 trials each.

| Attack | A | A′ | B | C |
| --- | --- | --- | --- | --- |
| KGA — outsider (deck 3) | **17/20** | 17/20 | **0/20** | **0/20** |
| KGA — keyless server / chain node | 17/20 | 17/20 | 0/20 | 0/20 |
| KGA — insider holding the key | 17/20 | 17/20 | 20/20 | 17/20 |
| Replay a captured search (deck 7) | accepted | accepted | `reused_nonce` | accepted |
| Replay a captured retrieval (deck 7) | ciphertext handed over again | same | `reused_nonce` | same |
| Plant `CT₁ = ⌊q/2⌋`, `CT₂ = 0` (deck 5) | matches every search | `malformed_ciphertext` | `unsigned_entry` | matches every search |
| Trapdoor / token on-chain | yes | yes | no (`SHA256(token‖nonce‖epoch)` only) | yes |
| Matched record ids on-chain (deck 6) | yes | yes | no | yes |

How to read the KGA row:

* **Mode A's 17/20 is not a weak attack.** In 3 of 20 trials the honest trapdoor
  failed to match its own keyword's ciphertext (a toy-parameter correctness
  failure), so the doctor's own search missed too. Over the trials where search
  works, the attack succeeds 100 %, with 0 wrong-keyword matches.
* **Mode C** keeps PPSEB's public Verify and on-chain trapdoor, and keyless
  guessing still finds nothing. Its insider's 17/20 is 2 own-keyword failures
  and 1 false-positive match on another keyword.
* **The insider row is the one to say out loud:** an authorised doctor can always
  guess keywords inside their own scope.
* **Control:** a "fix" that hashes the keyword with no key (SHA-256) is guessed
  10/10, so the key is the fix, not the hashing.

The A′ shape check refused **0 of 1 000** honest ciphertexts (lowest honest column
RMS 57.5 against a threshold of 32.1). It stops the canonical forgery and any short
`CT₂` column; it is necessary, not sufficient, and a registered patient can
still poison their own index (deck 5 is fully closed only by a ZK
well-formedness proof, design-only).

## Access-pattern leakage (deck 6)

The mid-sem Tier 1 / Tier 2 attacks (`attacks/ledger.py`, unchanged) run on
MedVault's own logs: 10 seeds, 20 records, 300 searches each.

| Observer | Tier 1 group purity | Tier 2 labelling | Chance | Beats chance |
| --- | --- | --- | --- | --- |
| Mode A, chain (PPSEB) | 1.00 | **0.715** | 0.17 | 10/10 |
| Mode B, chain | nothing visible | 0.19 | 0.18 | 0/10 |
| Mode B, search node | 1.00 | **0.755** | 0.18 | 10/10 |
| … with 2 cover searches per real one | 1.00 | 0.355 | 0.18 | 5/10 |
| … with 4 cover searches per real one | 1.00 | 0.335 | 0.18 | 4/10 |

Mode B removes the leak from the chain, not from the search node, which sees
tokens and matches by design (R11.10). Cover queries lower Tier 2 but never
Tier 1. Hiding co-access needs oblivious search (ORAM), design-only.

## Cost

| Quantity | Value |
| --- | --- |
| Record ciphertext overhead | 28 bytes (12-byte nonce + 16-byte GCM tag) |
| Envelope | 1 427 bytes (1 088 ML-KEM-768 ciphertext + 339 sealed payload) |
| Index entry, mode B | 96 bytes (32-byte HMAC token + 64-byte Ed25519 signature) |
| Index entry, modes A / C | ≈ 5.9 KB (a full PEKS ciphertext) |
| Keyed search latency (B) | ≈ 0.31–0.38 ms/query at 25–100 records, 1–3 doctors |
| PPSEB search latency (A) | ≈ 530 ms/query at **10** records — `verify` runs per entry |
| Mode trade-off table, 10 records | search ≈ 0.3 ms (B) vs ≈ 580 ms (A) and ≈ 630 ms (C) in this run; see `mode_tradeoff` |
| Revocation (20 records, 3 doctors) | 18 ms, 1 transaction, 2 re-key, 2 re-wrap, 80 re-index, 40 entries erased |
| Groth16 prove + one search | ≈ 1.6 s (includes one `node` process start) |
| Groth16 verify | ≈ 233 ms |
| Proof / proving key | 741 B (varies by a few bytes per proof) / 1.4 MB (`auth_final.zkey`) |
| PIR query / answer | 64 B / 2 048 B at 16 rows; 4 096 B / 2 048 B at 1 024 rows |
| PIR hint | 2 097 160 B (≈ 2 MiB) regardless of row count; n = 1024, q = 2³² |
| PIR server time | 0.02 ms (16 rows) to 1.4 ms (1 024 rows) |
| Gas — register doctor / commit record root | 90 905 / 68 283 |
| Gas — grant / revoke | 75 244 / 53 265 |
| Gas — search with proof | ≈ 302 000 (varies slightly with the proof bytes) |
| Gas — deploy `ConsentRegistry` | 1 223 297 |
| Demo path (9 graded steps) | ≈ 18 s from the command line (Groth16) |

Latencies are one run on the development laptop. They vary with the machine;
the ratios do not. Gas is from a local Hardhat chain (id 31337) — a dev chain,
not a mainnet cost estimate. Groth16 proofs are randomised, so proof size and
search-with-proof gas differ by a few units between runs; they are excluded from
the determinism check, which compares every other headline value.

## Privacy layer and research arm

| Result | Value |
| --- | --- |
| Key tree (depth 4, n = 2, q = 257) | 31 nodes, **all** satisfy `A·T = 0 mod q` |
| Norms | max ‖T̃‖ ≈ 2.6–4.2 per level, all under the 10.57 toy usability threshold |
| PEKS match matrix | 16/16 within an epoch, **0/16** across epochs |
| Future epochs reachable | every future leaf has a retained ancestor; past epochs raise `erased_key` |
| ZK nullifier reuse | second submission rejected (`bad_proof`), proof verified on-chain too |

Nothing here supports a forward-security claim: at these parameters the public
key alone already breaks the scheme, so a stolen key adds nothing (deck 9:
vacuous, not broken). The tree demonstrates structure, correctness and measured
cost, and Python erasure cannot erase a key someone already copied.

## Archived sweeps

These stay runnable but are deliberately outside the reproduction path
(Requirement 8.5), because each takes hours:

| Module | What it does |
| --- | --- |
| `sweep.py` | parameter sweep over (n, q, σ) |
| `attacks/boundary*.py` | security-boundary estimation, public-key-only and stolen-key |
| `attacks/nq_sweep.py` | (n, q) scaling sweep |
| `attacks/end_to_end.py` | end-to-end forward-security attack across n |
| `attacks/forward_sec.py` | forward-security norm experiment |
| `attacks/recovery.py` | what actually decides break versus no-break |

## Not measured, on purpose

* **Gas on a public network.** The figures above are a local Hardhat dev chain.
* **Anything design-only** — Module-LWE, ORAM, a forward-security claim, ZK
  well-formedness: see [`../../docs/design-only-fixes.md`](../../docs/design-only-fixes.md).
* **Recorded video.** Requirement 13.11's fallback is covered by
  [`demo_trace.json`](demo_trace.json) (replayable traces, also bundled into the
  UI) and [`screenshots/`](screenshots/).

The ML-KEM fallback is labelled `NON-HARDENED` because it is pure Python and has
no constant-time guarantees; `liboqs` is used instead when it is installed.
