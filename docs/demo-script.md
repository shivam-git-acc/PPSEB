# Demo recording script (≈ 10 minutes)

For S5-T5 / R13.11: record this once, after the final code is in place. It
follows PRD §11 steps 1–9, then the Phase 6 evidence. Every number on screen
comes from the running system or from `backend/results/repro.json`; nothing here
should be read out unless the screen shows it.

## Before recording

1. Close other heavy programs (the demo runs ≈ 18 s from the CLI, ≈ 40 s through the UI when warm).
2. Start everything: `start.cmd --with-chain` (or `start.cmd` without gas figures).
3. Open `http://localhost:5173`, MedVault group, **Demo** tab.
4. Warm up once: press **Run the demo** and wait for 9/9, so the recorded run is not a cold start.
5. Screen recorder: full browser window, 1080p, microphone on. OBS or the Windows Game Bar (`Win + Alt + R`) both work offline.

**If anything fails live:** press **Replay saved trace**. It shows the committed
9/9 run and works even with the backend stopped. Say that it is a replay; the
banner says so too.

## Script

| Time | Screen | Say (in your words) |
| --- | --- | --- |
| 0:00 | Deck slide 1, then 20 | PPSEB claims post-quantum keyword-guessing resistance, forward security and efficiency. We tested all three and found ten problems; MedVault-PQ is the system that fixes the ones a protocol can fix, and measures the rest. |
| 0:45 | Demo tab, **Run the demo** | One call runs nine steps: baseline attacks, upload, grants, search and retrieve, hardened attacks, revocation, a second doctor, a tampered record, and the key tree. |
| 1:30 | Step 1 open | On the original PPSEB, keyword guessing recovers the keyword, a planted ciphertext matches every search, a replayed trapdoor is accepted. |
| 2:15 | Steps 2–3 | Records are AES-GCM encrypted under a Merkle root on-chain; three doctors get ML-KEM-wrapped capabilities with different scopes. |
| 3:00 | Step 4 trace | Doctor A signs a search and a separate retrieval request; the Groth16 proof is checked; retrieval goes through PIR; integrity is checked before any decryption. |
| 3:45 | Step 5 | The same three attacks on the hardened path are all rejected, each with a named reason. |
| 4:15 | Steps 6–7 | Revoke doctor A: old token, nonce, envelope and proof all fail. Doctor B still works. Revocation cannot recall what A already downloaded. |
| 4:45 | Steps 8–9 | A flipped byte fails closed. The key tree is correct at every node; this is structure and cost, not a forward-security claim. |
| 5:15 | **Auditor** tab, **Run every attack** | Five attacks, mode A against mode B, including replaying a captured fetch. |
| 6:00 | **Evidence** tab, **Mode trade-off** | Mode C keeps PPSEB's public Verify and trapdoor, yet keyless guessing finds nothing. Mode B is about 2 000× faster but gives up public verification. No mode is both. |
| 7:00 | **Evidence** tab, **Access-pattern leakage** | The mid-sem leakage attack, unchanged: PPSEB's chain labels 72 % of records, mode B's chain is at chance, but the search node still labels 76 %. Cover queries help partly and never hide grouping. |
| 8:00 | Deck slides 46–49 | What is closed, partial and open, and what each fix costs. |
| 9:00 | `docs/security-games.md` (optional) | Every threat is written as a game and tied to a test that fails if it breaks. Closed means measured, not proven. |
| 9:30 | Deck slide 49 | Close on the trade-off. |

## Do not say (R16)

"post-quantum system", "PPSEB is Module-LWE", "forward security proven",
"revocation recalls data", "LWE is broken", "production-ready", "mode C is a
proven PAEKS", "mode B leaks nothing".

## After recording

Save the file outside the repository or under `backend/results/` (it is
gitignored there except for the listed files), and note its name in `task.md`
under D-T3 / S5-T5.
