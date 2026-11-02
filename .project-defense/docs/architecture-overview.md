# Architecture Overview — PPSEB Analysis Lab

> **Project:** PPSEB  
> **Generated:** 2026-10-17  
> **Source:** `.project-defense/project-graph.json` (verified entries only)

## 1. Project purpose

PPSEB Analysis Lab is an interactive research instrument for examining Xu et al.'s 2022 searchable-encryption scheme. Its corrected scheme implementation is paired with runnable experiments for offline keyword guessing, forward-security norm behavior, and the circularity in the paper's KeyExt algorithm. The README also describes broader experiments for public-key attacks, ledger leakage, recovery, proof analysis, and parameter sweeps. The application is explicitly a small-parameter analysis demo, not a production cryptosystem. See [README.md](../../README.md#ppseb-analysis-lab).

## 2. Technology stack

| Layer | Technology | Version / notes |
|---|---|---|
| Frontend | React | 18.x in `frontend/package.json` |
| Frontend tooling | Vite | 5.x; dev server proxies `/api` to port 8000 |
| UI styling / charts | Tailwind CSS, Recharts | Manifest dependencies |
| Backend | Python, FastAPI, Pydantic | Python packages declared in `backend/requirements.txt` |
| Crypto / math | NumPy, SymPy | Small-parameter linear algebra and exact modular arithmetic |
| Tests | pytest, httpx | Backend test suite under `backend/tests/` |

## 3. Main components

### 3.1 Frontend

`frontend/src/App.jsx` owns the parameter and initialization state, navigation, and tab selection. `ParamsBar` submits parameters to the API; tab components call the shared client in `frontend/src/api.js`. The UI groups pages into Scheme, Findings, and Measurement sections.

Core views include Overview, Happy Path, KGA, Forward Security, Spec Defect, Security (Correctness), and Network. Additional views cover Batch Sweep, Security Boundary, Public-Key Break, Recovery, Ledger, and Proof. The 35 component definitions and their individual source evidence are indexed in `.project-defense/project-graph.json`.

### 3.2 Backend

`backend/api.py` constructs the FastAPI app, owns a single process-wide `Session`, validates parameter requests, and serializes each operation into a response envelope containing results, trace events, and parameters. The core request lifecycle is implemented by `/api/init`, `/api/keyext`, `/api/encrypt-search`, and the three main `/api/attack/*` endpoints.

The scheme implementation is in `backend/ppseb/` (parameters, linear algebra, hashing, trapdoor sampling, scheme algorithms, trace events, and TrapGen). Attack and measurement modules are in `backend/attacks/`. Longer-running sweeps use job modules and JSONL result files rather than a database. The local analysis API enables CORS for all origins and is documented in code as not internet-facing.

### 3.3 Data and authentication

No ORM/database models were detected. The core API stores keys and parameters in memory; the Happy Path request encrypts and conditionally decrypts the supplied record within the request rather than persisting it. The Network simulation has a separate session model. Batch experiment results are persisted to local files as described in the README.

No authentication or token handling is implemented. This is consistent with the local, single-user demo design, not a claim that the API is safe to expose remotely.

## 4. Component interactions

```text
Browser (React)
  -> frontend/src/api.js
  -> Vite /api proxy (127.0.0.1:8000)
  -> FastAPI handlers (backend/api.py)
  -> ppseb scheme primitives / attacks / job modules
  -> JSON result + trace
  -> React tab renders outcome and evidence
```

There is no database in the core Happy Path. For batch experiments, backend job code writes result records locally. See [architecture.mmd](../diagrams/architecture.mmd).

## 5. Key design decisions

- Parameters are intentionally small and configurable so matrix operations and traces remain inspectable; `Params.validate()` checks primality of `q`, a minimum `m`, positive widths, and H2's divisibility constraint ([params.py](../../backend/ppseb/params.py), lines 13–112).
- The API centralizes generated keys and period state in one in-memory session for this single-user demo ([api.py](../../backend/api.py), lines 78–103).
- Deviations and corrections are recorded in typed trace events rather than being hidden in the implementation ([scheme.py](../../backend/ppseb/scheme.py), lines 1–4 and the algorithm implementations).
- The browser uses a same-origin `/api` path during development, proxied to the local backend ([vite.config.js](../../frontend/vite.config.js), lines 1–13).

## 6. Interview-ready summary

PPSEB Analysis Lab is a React and FastAPI research demo that implements a corrected, small-parameter version of a searchable-encryption paper and makes its behavior observable through traces. The core API keeps period keys in a single in-memory session, while the UI exposes a normal encrypt/search/decrypt path and several attack and measurement tabs. The most interesting engineering choice is to treat corrections and attack evidence as first-class outputs, while being explicit that toy-parameter results are not production security claims.

## 7. Evidence appendix

| Claim | File | Lines | Status |
|---|---|---:|---|
| Project's stated purpose and findings | `README.md` | 1–20 | code-verified |
| Stack and run commands | `README.md` | 25–76 | code-verified |
| React root state and UI sections | `frontend/src/App.jsx` | 19–85, 136–148 | code-verified |
| FastAPI app, session, CORS and response envelope | `backend/api.py` | 1–108 | code-verified |
| Core API handlers | `backend/api.py` | 190–457 | code-verified |
| Parameter validation | `backend/ppseb/params.py` | 13–112 | code-verified |
| Scheme algorithm inventory | `backend/ppseb/scheme.py` | 1–4 | code-verified |
| Vite proxy | `frontend/vite.config.js` | 1–13 | code-verified |

> The backend route detector in the installed skill targets Express. FastAPI routes were checked directly in `backend/api.py`; the generated graph records the core routes and groups the additional modules under backend services.
