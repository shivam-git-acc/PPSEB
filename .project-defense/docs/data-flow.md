# Data Flow — PPSEB Analysis Lab

> **Project:** PPSEB  
> **Generated:** 2026-10-17  
> **Source:** `.project-defense/project-graph.json` (verified entries only)

## 1. Overview

The main user journey starts when the browser posts a parameter set to initialize a root key pair. The user then supplies a record, its keyword, and a query keyword. The FastAPI handler creates the searchable ciphertext and trapdoor, verifies them, encrypts the record, and decrypts it only if verification matches. Results and trace events return to the UI as JSON. The core endpoint does not persist the record in a database.

The browser's `fetch` calls use `/api`; Vite proxies that prefix to `http://127.0.0.1:8000`. See [data-flow.mmd](../diagrams/data-flow.mmd).

## 2. Step-by-step lifecycle: Happy Path

1. **User action:** the user enters a record, keyword, and query keyword in the Happy Path tab.
2. **Frontend handling:** the tab sends a JSON body through the shared API client.
3. **Network request:** `POST /api/encrypt-search` is proxied by Vite to FastAPI. The request model accepts the strings and an optional period.
4. **API route:** the handler requires initialized session state, selects the requested/current period, and obtains that period's public key, secret basis, `mu`, and PKE anchor.
5. **Scheme operations:** the backend runs PEKS encryption, trapdoor generation, verification, and record encryption. Record decryption runs only after a match.
6. **Response:** the response envelope contains `result`, `trace`, and `params`; the result includes the match, a preview of the verifier output, and a decrypted record only on a match.
7. **Frontend update:** the tab displays match/no-match, decrypted content when available, and trace events.

**Evidence:** `backend/api.py:263-297`; `frontend/src/api.js:1-29`; `frontend/vite.config.js:5-12`.

## 3. Other data paths

### Initialization and period extension

`POST /api/init` validates parameters, builds the root key and shared values, resets the process-wide session, and returns a shape table. `POST /api/keyext` extends the key chain through the requested period and stores each period's public/secret key pair in that same session ([api.py](../../backend/api.py), lines 195–248).

### Keyword-guessing attack

`POST /api/attack/kga` creates a doctor trapdoor using the session secret basis, then passes the public key, `mu`, period, trapdoor, and dictionary to the attack. Each guess is publicly encrypted and tested with the captured trapdoor. The response includes guess outcomes and the combined trace ([api.py](../../backend/api.py), lines 299–336; [kga.py](../../backend/attacks/kga.py), lines 30–82).

### Long-running experiments

Sweep, boundary, and recovery routes start jobs and expose status/results through follow-up requests. Batch sweep output is written to JSONL files under `backend/results/`; it is not a database-backed flow ([README.md](../../README.md), lines 102–145; [api.py](../../backend/api.py), lines 482–629 and 803–830).

## 4. State transitions

| State | Trigger | Next state | Evidence |
|---|---|---|---|
| Uninitialized | Valid `POST /api/init` | Root keys and parameters in `SESSION` | `backend/api.py:195-219` |
| Root period 0 | `POST /api/keyext` requests a later period | Period chain extended through `j` | `backend/api.py:226-248` |
| Initialized | `/api/encrypt-search` has a matching keyword | Search accepted; record decrypted for response | `backend/api.py:263-297` |
| Initialized | `/api/encrypt-search` has a non-matching query | Search rejected; decrypted record omitted | `backend/api.py:263-297` |
| Experiment not running | Job start endpoint | Job ID returned; client polls status | `backend/api.py:482-529` |

The application has no login/token state. The session is process-wide, not isolated by browser or user.

## 5. Async and side-effect flows

| Flow | Trigger and side effect | Failure/observability |
|---|---|---|
| Batch/measurement jobs | User starts a sweep; job data and JSONL records are persisted locally. | Status/results routes report missing jobs with HTTP 404. |
| Network simulation | New simulation session; record/search/advance/decrypt/attack mutate that simulation state. | Invalid transitions and inputs map to HTTP 400; unknown session maps to 404. |
| Core search | One request performs all crypto operations; no persistent record write is shown in the handler. | Parameter/session errors are explicit HTTP errors; match is returned as data, not treated as an exception. |

Evidence: `backend/api.py:482-529`, `backend/api.py:701-789`, and `backend/api.py:263-297`.

## 6. Error propagation

| Error source | Backend behavior | Frontend behavior | Evidence |
|---|---|---|---|
| Invalid parameters | `Params.validate()` problems become HTTP 422 | API client throws an `Error` with response detail | `backend/api.py:195-204`; `frontend/src/api.js:4-14` |
| Request before init / missing period | HTTP 400 with a direct message | Rejected request is surfaced to the tab caller | `backend/api.py:221-224`; `frontend/src/api.js:4-14` |
| Invalid H1 variant | HTTP 422 | API client throws | `backend/api.py:338-343`; `frontend/src/api.js:4-14` |
| Missing job/session | HTTP 404 | API client throws | `backend/api.py:498-503`; `backend/api.py:701-706` |
| Unhandled backend exception | HTTP 500 JSON includes exception and traceback | API client throws the returned error/status | `backend/api.py:897-904`; `frontend/src/api.js:4-14` |

## 7. Interview-ready summary

For the Happy Path, the browser posts record and keyword inputs to one FastAPI route through the Vite proxy. The handler reads the selected period's in-memory keys, runs search encryption and trapdoor verification, encrypts the record, and only decrypts it after a match. It returns both the result and an ordered trace, so the UI can show what happened instead of presenting a mocked outcome.

## 8. Evidence appendix

| Step | File | Lines | Status |
|---|---|---:|---|
| Browser API client | `frontend/src/api.js` | 1–29 | code-verified |
| Development proxy | `frontend/vite.config.js` | 5–12 | code-verified |
| Session and envelope | `backend/api.py` | 78–118 | code-verified |
| Init and key extension | `backend/api.py` | 195–248 | code-verified |
| Encrypt/search/decrypt | `backend/api.py` | 263–297 | code-verified |
| KGA orchestration | `backend/api.py` | 299–336 | code-verified |
| Batch job endpoints | `backend/api.py` | 482–529 | code-verified |
| Network state operations | `backend/api.py` | 701–789 | code-verified |
| Error response handling | `backend/api.py` | 897–904 | code-verified |
