# Personalized Learning Path — PPSEB Analysis Lab

This path follows the repository's actual stack and crypto flow: React/Vite UI, a FastAPI JSON API, and NumPy-based lattice primitives. It does not assume Express, MongoDB, or authentication, none of which are part of this codebase.

| Stage | Topic | Project connection | Practice task |
|---:|---|---|---|
| 1 | Python data structures and functions | Backend attack and scheme modules are Python packages. | Trace the inputs/outputs of `peks_encrypt` and `verify` without changing behavior. |
| 2 | React components and local state | `App` manages parameters, initialization and tab selection; each tab owns its own view state. | Add a small controlled input to an existing tab and explain its state lifecycle. |
| 3 | HTTP, JSON and fetch | `frontend/src/api.js` wraps GET/POST requests and surfaces non-2xx responses. | Add a typed-by-convention API method for an existing endpoint and exercise its error case. |
| 4 | FastAPI and Pydantic | `backend/api.py` maps request models to route handlers and envelopes results. | Add a validation constraint to one request model and test the 422 response. |
| 5 | Modular arithmetic and lattice basics | `params.py`, `linalg.py`, and `trapgen.py` define the core mathematical objects. | Write a test that checks `A @ T == 0 mod q` for a generated trapdoor. |
| 6 | Trapdoor sampling and basis delegation | `samplers.py` implements SamplePre/NewBasisDel; `scheme.py` chains periods. | Follow one KeyExt period and annotate every matrix shape and modulus. |
| 7 | Trace design and scientific claims | `trace.py` makes corrections, norms and decisions inspectable. | Add a trace event to one primitive and assert its type/data in a focused test. |
| 8 | Reproducible experiments and async jobs | Sweep/recovery modules persist results and expose start/status routes. | Run a small bounded experiment twice with fixed seeds and compare the output schema. |
| 9 | Testing scientific edge cases | `backend/tests/` covers correctness, attacks, hashes and API behavior. | Add a negative control proving a mismatched keyword is rejected. |
| 10 | Rebuild challenge | Combine the UI, API, scheme and tests. | Rebuild a minimal `/api/encrypt-search` path from scratch: validate params, generate keys, encrypt, verify, conditionally decrypt, emit trace, and test matching plus non-matching cases. |

## Suggested reading order

1. `frontend/src/App.jsx` and `frontend/src/api.js`
2. `backend/api.py` request models and core endpoints
3. `backend/ppseb/params.py` and `backend/ppseb/scheme.py`
4. `backend/ppseb/linalg.py`, `trapgen.py`, and `samplers.py`
5. `backend/attacks/spec_defect.py`, `kga.py`, and `forward_sec.py`
6. Focused tests under `backend/tests/`

The measurements use deliberately small parameters. Treat them as experiments about this implementation and parameter set, not as security certification for a production-size scheme.
