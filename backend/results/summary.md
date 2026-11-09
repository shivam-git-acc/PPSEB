# MedVault-PQ — committed result summary

This file is displayable without running anything (Requirement 8.6). The
authoritative numbers live in [`repro.json`](repro.json), which `./repro.sh`
(or `repro.cmd` on Windows) regenerates in about 40 seconds.

**Seed 42. KEM: `pure-python-ml-kem-768-NON-HARDENED`. Ledger backend: `memory-ledger`.**
**Lattice parameters: n = 4, q = 257, σ = 4.0, l = 10 — toy values, labelled as such.**
**Proof system: Groth16 over BN254, 3 202 constraints, depth-4 consent tree —
classical, single-party dev setup, not suitable for real use.**

## Attacks, before and after

| Attack | Original PPSEB (mode A) | Hardened (mode B) |
| --- | --- | --- |
| KGA — outsider with a dictionary | **100 %** recovered | **0 %** (cannot form a token) |
| KGA — keyless server observing tokens | **100 %** | **0 %** |
| KGA — authorised insider holding the key | **100 %** | **100 %** (reported openly; expected) |
| Replay of one captured token | **accepted** | rejected: `reused_nonce` |
| Plant one universal ciphertext (`CT1 = ⌊q/2⌋`, `CT2 = 0`) | **matches every search** | rejected: `unsigned_entry` |
| Token visible in the on-chain log | **yes** | no (only `SHA256(token‖nonce‖epoch)`) |

The insider row is the one to say out loud: an authorised doctor can always guess
keywords inside their own scope. The fix removes the *offline, keyless* attack,
not the insider's knowledge.

## Cost

| Quantity | Value |
| --- | --- |
| Record ciphertext overhead | 28 bytes (12-byte nonce + 16-byte GCM tag) |
| Envelope | 1 427 bytes (1 088 ML-KEM-768 ciphertext + 339 sealed payload) |
| Index entry | 96 bytes (32-byte HMAC token + 64-byte Ed25519 signature) |
| PPSEB mode-A index entry | a full PEKS ciphertext instead of 96 bytes |
| Keyed search latency | ≈ 0.33–0.38 ms/query at 25–100 records, 1–3 doctors |
| PPSEB mode-A search latency | ≈ 880 ms/query at **10** records — `verify` runs per entry |
| Plaintext index (floor, no crypto) | ≈ 0.0003 ms/query |
| Revocation (20 records, 3 doctors) | 19 ms, 1 transaction, 2 re-key, 2 re-wrap, 80 re-index, 40 entries erased |
| Groth16 prove + one search | ≈ 4.0 s (includes one `node` process start) |
| Groth16 verify | ≈ 293 ms |
| Proving key | 1.4 MB (`auth_final.zkey`) |
| PIR query / answer | 64 B / 2 048 B at 16 rows; 4 096 B / 2 048 B at 1 024 rows |
| PIR hint | 2 097 160 B (≈ 2 MiB) regardless of row count; n = 1024, q = 2³² |
| Gas — grant | 75 244 |
| Gas — revoke | 53 265 |
| Gas — search with proof | 302 010 |
| Gas — register doctor | 90 905 |
| Gas — commit record root | 68 283 |
| Gas — deploy `ConsentRegistry` | 1 223 297 |
| Demo path (9 graded steps) | ≈ 20 s (Groth16) |

Latencies are one run on the development laptop. They vary with the machine;
the ratios do not. Gas is from a local Hardhat chain (id 31337) — a dev chain,
not a mainnet cost estimate.

## Privacy layer and research arm

| Result | Value |
| --- | --- |
| Key tree (depth 4) | 31 nodes, **all** satisfy `A·T = 0 mod q` |
| Norms | max ‖T̃‖ ≈ 2.8–4.2 per level, all under the toy usability threshold |
| PEKS match matrix | 16/16 within an epoch, **0/16** across epochs |
| Future epochs reachable | every future leaf has a retained ancestor; past epochs raise `erased_key` |
| ZK nullifier reuse | second submission rejected (`bad_proof`), proof verified on-chain too |

Nothing here supports a forward-security claim: the tree demonstrates structure,
correctness and measured cost on toy parameters, and Python erasure cannot
erase a key someone already copied.

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

## Not measured yet

Nothing in the evaluation plan is unmeasured: every key in `repro.json` carries a
number. Two things remain outside the measurement path on purpose:

* **Gas on a public network.** The figures above are a local Hardhat dev chain.
* **Recorded video.** Requirement 13.11's fallback is covered by
  [`demo_trace.json`](demo_trace.json) (replayable traces) and
  [`screenshots/`](screenshots/), not by a video recording.

The ML-KEM fallback is labelled `NON-HARDENED` because it is pure Python and has
no constant-time guarantees; `liboqs` is used instead when it is installed.
