# Project-Specific Interview Question Bank — PPSEB Analysis Lab

Questions below are based on the repository's code and documented behavior. “Strong answer” outlines the concepts an interviewer should hear; it is not a script to memorize verbatim.

## Explanation

### Q1: Walk me through the architecture and a single Happy Path request.

**Why interviewers ask:** Checks whether you can connect UI, network, backend and crypto code rather than naming frameworks in isolation.

**Expected concepts (rubric):**
- React tab and shared API client
- Vite `/api` proxy to FastAPI
- In-memory period keys/parameters
- PEKS, trapdoor, Verify and match-gated decrypt
- Response envelope includes trace

**Strong answer:** The React tab calls the shared client in `frontend/src/api.js`; Vite proxies `/api` to the local FastAPI server. `POST /api/encrypt-search` reads the initialized period keys and shared parameters from the process-wide session. It creates the keyword ciphertext and query trapdoor, runs Verify, encrypts the record, and decrypts it only when the query matches. The handler returns the match, an optional plaintext, a preview of the verifier output, trace events and params. No database write occurs in that handler.

**Weak answers:** Claiming a database stores the record; skipping the Vite proxy; saying the browser performs the cryptography; omitting why a no-match has no plaintext.

**Follow-up:** If you wanted multiple browser users, which session-state boundary would you change first?

### Q2: Why does the PEKS implementation use one shared matrix `B`?

**Why interviewers ask:** Tests understanding of the cancellation that makes a correct keyword test possible.

**Expected concepts (rubric):**
- Both ciphertext components depend on the same randomness
- Trapdoor/public-key relation cancels the shared term
- Independent matrices would leave uncancelled terms
- The assumption is marked as a correction in trace

**Strong answer:** Both `CT1` and `CT2` carry terms derived from the same random matrix. During Verify, the trapdoor relation makes the keyword-dependent public-key term line up with `mu`, so the shared `B` terms cancel and only noise remains around the decode target. If the two components used independent matrices, that algebraic cancellation would not occur, so matching keywords would not reliably pass. The code explicitly samples `B` once and records the correction in the trace.

**Weak answers:** Describing `B` as an encryption key; saying it is only a speed optimization; ignoring the equality of the two random matrices.

**Follow-up:** Which test would you write to catch accidental reintroduction of separate matrices?

### Q3: Explain the KeyExt defect and the corrected single-step version.

**Why interviewers ask:** Tests whether you can reason from algorithm inputs and data dependencies.

**Expected concepts (rubric):**
- Printed line 6 uses `pk_rj` while defining it
- Printed line 7 passes `sk_rj` as its own input
- Corrected call uses previous period's public/secret values
- Verify each resulting pair modulo `q`

**Strong answer:** The printed algorithm refers to the key it is supposed to create, so line 6 has a forward reference, and line 7 calls basis delegation with its own output as the source basis. The corrected version computes `R` from `pk_{j-1}`, derives `pk_j` from the inverse transform, and delegates using `sk_{j-1}`. The implementation validates `pk_j * sk_j == 0 mod q` for every produced period. The correction is backed by the stated inputs and the source-basis role of NewBasisDel.

**Weak answers:** Calling it a typo without identifying both cycles; changing the algorithm without checking lattice membership; claiming the paper's printed code executes.

**Follow-up:** Why is a source basis needed by NewBasisDel?

## Failure scenarios

### Q4: What happens when a caller submits invalid parameters?

**Why interviewers ask:** Evaluates request validation and whether the UI can distinguish invalid inputs from a crypto mismatch.

**Expected concepts (rubric):**
- `Params.validate()` checks primality, dimension and positive widths
- `/api/init` returns 422 with problem details
- Frontend API wrapper throws on non-2xx
- UI state records initialization errors

**Strong answer:** `/api/init` constructs `Params`, calls `validate()`, and raises HTTP 422 with the collected problems if any constraint fails. The API client treats any non-OK response as an error and throws a message based on the response detail. `App` catches that failure, stores it as `initError`, and marks the session uninitialized, so invalid parameters do not look like a successful setup.

**Weak answers:** Saying the frontend alone validates; treating all errors as no-match; assuming the server silently defaults invalid values.

**Follow-up:** Which parameter constraints are checked before a root key is generated?

### Q5: What happens if `/api/encrypt-search` is called before initialization or with a missing period?

**Why interviewers ask:** Checks session lifecycle and endpoint preconditions.

**Expected concepts (rubric):**
- Initialization is required
- Requested/default period selected
- `require_period` produces explicit 400 on absent period
- UI surfaces the returned error

**Strong answer:** The handler first ensures the session has keys. It uses the requested period or the latest period, then checks that the period exists before it indexes the key dictionaries. A missing initialization or period raises HTTP 400 rather than accessing nonexistent state. The frontend wrapper rejects the request and lets the tab display the error.

**Weak answers:** Assuming every request creates keys; claiming missing periods return an empty result; overlooking the session reset on init.

**Follow-up:** What behavior would you want if an init request arrives while a long-running job is using the same session?

### Q6: A batch experiment times out. Can you conclude forward security held?

**Why interviewers ask:** Evaluates scientific honesty and interpretation of resource-bounded experiments.

**Expected concepts (rubric):**
- Timeout is unmeasured, not a negative result
- Verdict depends on measured norms/control gates/reducer
- Demo dimension does not establish cryptographic-scale security
- Job/status/result artifacts preserve experiment state

**Strong answer:** No. A timeout means the attack was not measured to completion under that budget; it is neither a break nor evidence of survival. The result should retain an explicit timeout/unmeasured state and report the parameter set, reduction level and controls. Even a completed failure at the demo dimensions applies only to that measured run, not to secure-size parameters.

**Weak answers:** Calling timeout “secure”; treating every no-break as proof; ignoring attack budget and controls.

**Follow-up:** What negative control helps validate a reported break?

## Trade-offs

### Q7: Why use small parameters and implement the lattice primitives directly?

**Why interviewers ask:** Tests whether you understand the project's research/teaching goals and limitations.

**Expected concepts (rubric):**
- Readable matrices and inspectable traces
- Fast, reproducible experiments
- No heavy lattice dependency in the core
- Results are not security certification at real parameters

**Strong answer:** Tiny parameters keep matrix operations and traces visible and allow an evaluator to rerun the workflows quickly. Implementing the primitives locally keeps the experiment auditable and avoids hiding the mechanism behind a lattice library. The cost is that the results do not transfer directly to production dimensions; the project explicitly treats them as analysis measurements, and optional BKZ tooling is only used for selected experiments.

**Weak answers:** Claiming the toy parameters are secure; saying large parameters are unnecessary for every conclusion; dismissing auditability.

**Follow-up:** Which parts of the conclusion remain structural even when the demo dimensions are small?

### Q8: Why is the API's process-global session an acceptable choice here, and what would need to change for deployment?

**Why interviewers ask:** Tests ability to distinguish a demo shortcut from a production design.

**Expected concepts (rubric):**
- Single-user local demo assumption
- Global mutable state is shared and reset by initialization
- Authentication, per-user isolation, persistence and CORS are absent/limited
- Do not expose the demo API as-is

**Strong answer:** The code calls itself a single-user analysis instrument, so one process-global session keeps the demo simple. That means concurrent users can overwrite or share period keys, and reinitialization resets the same state. A deployed version would require authenticated per-user sessions, controlled persistence/lifecycle, strict CORS, and production-safe exception handling; none of those are implied by this demo.

**Weak answers:** Claiming global state is safe because FastAPI is asynchronous; adding a database without discussing identity/isolation; calling permissive CORS a security boundary.

**Follow-up:** Which state should be separated first: parameters, secret bases, job records, or all three?

## Coding tasks

### Q9: Add a focused test proving a non-matching keyword does not return the record.

**Why interviewers ask:** Tests ability to work with the API contract and verify a negative path.

**Expected concepts (rubric):**
- Initialize a deterministic test client/session
- Submit distinct stored/query keywords
- Assert `match` is false
- Assert `decrypted_record` is null/absent
- Avoid brittle assertions on random matrices or full trace contents

**Strong answer:** Use the existing FastAPI test setup and call `/api/init` first. Then post a record with one keyword and a different `query_keyword`. Assert the response is successful as an operation, `result.match` is false, and `result.decrypted_record` is `None`. Keep the assertion focused on the observable contract; random matrix previews and exact sampled vectors should not be hard-coded.

**Weak answers:** Testing only a helper instead of the endpoint contract; checking only status 200; expecting a fixed random ciphertext.

**Follow-up:** How would you make the test deterministic without weakening the production randomization?

**Acceptance criteria:** The test fails if a mismatch is accepted or plaintext is returned; it passes for valid parameters and does not rely on exact random matrix values.

### Q10: Add a trace assertion for the shared-`B` correction.

**Why interviewers ask:** Tests understanding of the trace as part of the product contract.

**Expected concepts (rubric):**
- Invoke PEKS with a trace object
- Assert a correction event names shared `B`
- Check structured data includes the matrix shape
- Keep the test tied to semantics, not formatting

**Strong answer:** Create valid parameters, call the PEKS encryption routine with a `Trace`, then inspect the serialized trace for a correction event describing that the same `B` is used in CT1 and CT2. Assert its structured `B_shape` matches `(n, l)`. This verifies the correction remains visible to the UI as well as implemented in the arithmetic.

**Weak answers:** Looking only for any event string; testing a manually constructed fake event; asserting the full event JSON byte-for-byte.

**Follow-up:** What other correction event is important for period-key correctness?

**Acceptance criteria:** The test fails if the correction event is removed or the recorded shape is wrong, while allowing unrelated trace text to change.

## MedVault-PQ and the Phase 6 fixes

Numbers below are from `backend/results/repro.json` (seed 42). Finding numbers are the mid-sem deck's 1–10; `docs/security-games.md` maps every other numbering to them.

### Q11: Mode B fixes keyword guessing by replacing PEKS with HMAC. Haven't you just removed the scheme you were asked to analyse?

**Why interviewers ask:** Checks whether you can separate "the attack is closed" from "the scheme is repaired".

**Expected concepts (rubric):**
- Mode B is a different design: a keyed index, no public tester
- Mode C keeps PPSEB's own PEKS / Trapdoor / Verify, unchanged
- Mode C runs them on `HMAC(K_pd, keyword)`; `K_pd` arrives in the ML-KEM envelope
- The deck's own proposed fix is PAEKS (Huang–Li, the paper's ref. 4)

**Strong answer:** Yes, mode B sidesteps the public tester, which is why mode C exists. Mode C keeps PPSEB's algorithms and its public Verify, and the trapdoor still goes on-chain. What changes is the keyword it encrypts: an HMAC under a key the patient shares with that doctor for that epoch. Measured over 20 trials, the outsider and a keyless chain node recover 0 keywords, while the key-holding insider recovers 17/20. It is PAEKS-style in spirit, not the pairing-based Huang–Li scheme, and it has no proof.

**Weak answers:** "HMAC is post-quantum so it is fine"; claiming mode C is a proven PAEKS; not mentioning that the insider still succeeds.

**Follow-up:** What does mode C *not* fix? (Replay and planting: it authenticates keywords, not requests or ciphertexts.)

### Q12: Mode A's keyword-guessing rate is 85 %, not 100 %. Is the attack unreliable?

**Why interviewers ask:** Tests whether you read your own numbers or just report them.

**Expected concepts (rubric):**
- Every miss is a trapdoor that fails Verify on its own keyword's honest ciphertext
- The doctor's real search misses in exactly those cases
- Conditional on search working, the attack succeeds 100 %
- Toy parameters (n = 4, q = 257): the deck's "margin law"
- Success now means the *right* keyword, with false positives counted separately

**Strong answer:** The attack is not the weak part. In 3 of 20 trials the honest trapdoor failed to match its own keyword's ciphertext, a correctness failure at these toy parameters, so the doctor's own search would have missed as well. Over the trials where search works, the attack succeeds 100 % with zero wrong-keyword matches. Mode C's insider also had one false-positive match, the same parameter effect from the other side.

**Weak answers:** Blaming randomness without naming the mechanism; quoting 100 % from a single trial.

**Follow-up:** How does your harness tell a weak attack apart from a weak scheme? (`own_ciphertext_failures` and `success_rate_given_working_search_pct`.)

### Q13: Your mode A′ shape check rejects the `CT₂ = 0` forgery. Does that fix planting?

**Why interviewers ask:** A classic place to overclaim.

**Expected concepts (rubric):**
- The check rejects short CT₂ columns; honest columns look uniform mod q
- 0 of 1 000 honest ciphertexts refused; wide margin to the threshold
- Necessary, not sufficient: it cannot tell honest uniform-looking data from dishonest
- A signature proves who wrote an entry, not that it is well formed
- Real closure on an open ledger needs a ZK well-formedness proof (design-only)

**Strong answer:** It stops the paper's canonical forgery and any forgery with a short CT₂ column, and it refused none of 1 000 honest ciphertexts. But it is a necessary condition only, so we do not claim it closes the finding. In mode B a "matches everything" entry cannot exist at all, and writes must be patient-signed, which stops outsiders. A registered but malicious patient can still poison their own index. Closing it for a public ledger needs a zero-knowledge proof that the ciphertext is a genuine small-noise sample, described in `docs/design-only-fixes.md`.

**Weak answers:** "Signed writes fix it"; "the check proves well-formedness".

**Follow-up:** Why is lattice ZK the consistent choice over the Groth16 you already use?

### Q14: Mode B hides the access pattern from the chain. Is mode B private?

**Why interviewers ask:** Tests whether you know who the remaining observer is.

**Expected concepts (rubric):**
- Chain observer: 0 records visible; Tier 2 0.19 against chance 0.18
- The search node computes matches, so it still sees tokens and matched ids (R11.10)
- Measured: Tier 2 0.755 against the search node, 10/10 seeds above chance
- PIR hides retrieval from storage, not the search node's view
- Cover queries lower Tier 2 (0.355 at 2×) but never Tier 1

**Strong answer:** Private from the chain, not from the search node. We measured it with the mid-sem Tier 1 / Tier 2 attacks, unchanged: the search node labels records about as well as PPSEB's public chain does. Cover queries help Tier 2 partly and at real cost, but co-access grouping stays 100 % pure, because which records answer together and how many records each disease has do not change. Hiding that needs oblivious search (ORAM), which is design-only.

**Weak answers:** "PIR fixes access-pattern leakage"; "mode B leaks nothing".

**Follow-up:** Why does Tier 2 stay above chance even at 4× cover traffic? (Group sizes still mirror prevalence.)

### Q15: Why sign retrieval requests separately from searches?

**Why interviewers ask:** Checks protocol-level thinking.

**Expected concepts (rubric):**
- Deck finding 7 is "replay it, pull the record"
- A retrieval carries its own Ed25519 signature, epoch and nonce
- One per-doctor nonce counter covers search and retrieval
- Domain separation: a search signature cannot be used as a retrieval signature
- A rejected request does not consume a nonce

**Strong answer:** Signing only searches would leave the fetch itself replayable. Retrievals are signed over a domain-separated message, so the two signature types cannot be swapped, and they spend nonces from the same counter. A replay is rejected as `reused_nonce`; a forged, tampered or cross-used signature as `bad_signature`, without burning the nonce, so a rejected request cannot lock the doctor out.

**Weak answers:** "The token already authenticates the doctor"; ignoring denial of service via burnt nonces.

**Follow-up:** What does a replay give an attacker in mode A? (Ciphertext and the fact of access, never plaintext.)

### Q16: Is PPSEB forward secure?

**Why interviewers ask:** The paper claims it; the answer must be precise.

**Expected concepts (rubric):**
- The backward attack works, but the public key alone already breaks these parameters
- So forward security is vacuous here, not broken
- The paper never proves forward security as its own statement
- M7 shows structure, correctness at every node and measured norms only

**Strong answer:** At the paper's parameters the question cannot be asked meaningfully: the public key alone yields a working short basis, so stealing today's key adds nothing. That makes the claim vacuous rather than broken. Our tree-based key evolution demonstrates structure, `A·T ≡ 0 (mod q)` at all 31 nodes and flat norms; we claim nothing about forward security.

**Weak answers:** "We proved it is forward secure"; "we broke forward security".

**Follow-up:** What would you need before a forward-security claim made sense?

### Q17: The gateway receives the record id when authorising a retrieval. Doesn't that defeat PIR?

**Why interviewers ask:** Tests whether you know your own trust boundaries.

**Expected concepts (rubric):**
- Design decision D5: gateway and search node are one process
- PIR protects against the storage server, which never sees a record id
- The gateway/search node already knows matched ids (R11.10)
- Splitting the process would not remove that knowledge from the search side

**Strong answer:** PIR's adversary is the storage server, and the test shows it never receives a record id. The gateway shares a process with the search node by design, and the search node already knows which records matched, so authorisation reveals nothing new to it. Separating them would need the authorisation itself to be private, for example by proving scope in zero knowledge.

**Weak answers:** "PIR hides everything"; not knowing where the record id travels.

**Follow-up:** Which leakage does the threat-model table document for the search node?

### Q18: Some pre-existing research-arm tests fail. Why should we trust the suite?

**Why interviewers ask:** Tests honesty and diagnosis.

**Expected concepts (rubric):**
- The research code and its tests are untouched (R8.1)
- Ledger failures: honest trapdoors miss their own records at toy parameters
- Sweep test: a Windows environment quirk; the property holds when re-checked
- Lab full-flow test: intermittent; a global-`random` fallback is the likely cause
- MedVault's suite: 206 passed; the leakage numbers are regenerated by script

**Strong answer:** We did not edit those tests. Each failure is diagnosed in `task.md` (X-T8): two are a toy-parameter correctness failure, one is an environment issue, one is intermittent with a likely cause we state but have not proven. The reproducible replacement for the ledger numbers is `medvault/leakage.py` over 10 seeds, which `repro` regenerates.

**Weak answers:** "The whole suite is green"; "those tests are flaky, ignore them".

**Follow-up:** How would you make the lab's runs reproducible without changing their results?

### Q19: Is MedVault-PQ post-quantum?

**Why interviewers ask:** Checks the claims policy.

**Expected concepts (rubric):**
- Key wrapping (ML-KEM-768) and PIR use lattice assumptions
- ML-KEM here is the pure-Python fallback, labelled non-hardened
- Groth16 over BN254 and the chain's signatures are classical
- The Groth16 setup is a single-party dev ceremony
- PPSEB at toy parameters is broken by the public key alone

**Strong answer:** No, and we do not say so. Key wrapping and PIR rest on lattice assumptions; the ZK proofs and chain signatures are classical, the trusted setup is a development ceremony, and the lattice PEKS runs at parameters that are broken. The accurate claim is that each finding has a fix and a regression test, and cost and leakage are measured.

**Weak answers:** "Yes, it uses ML-KEM"; "PPSEB is now Module-LWE".

**Follow-up:** Which component would you replace first to strengthen the claim?
