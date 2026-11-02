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
