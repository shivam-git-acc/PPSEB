# PPSEB Analysis Lab

An interactive lab for analyzing the PPSEB paper (Xu et al., 2022) — a
lattice-based searchable-encryption scheme on blockchain — and demonstrating three
concrete findings against it: an offline keyword-guessing attack, a forward-security
norm experiment, and a specification defect in the key-evolution algorithm.

## For Claude Code

**Start by reading `CLAUDE.md` in full.** It is the complete build specification:
architecture, the exact (corrected) crypto to implement, the three findings, the
FastAPI surface, the trace format, and the React UI. Build in the order given in
`CLAUDE.md §9`, commit after each step, and follow the guardrails in §10 — especially:
mark every deviation from the paper as a `correction` event, and never fake a result
(the Finding-2 verdict must follow from measured norms).

## Running (once built)

```bash
# backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn api:app --reload --port 8000

# frontend (separate terminal)
cd frontend
npm install
npm run dev
```

Open the Vite dev URL, set parameters in the left rail, and work through the tabs:
Overview → Spec Defect → KGA Attack → Forward Security → Happy Path.
