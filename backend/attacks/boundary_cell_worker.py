"""Runs ONE security-boundary cell and prints it as JSON.

Same reasoning as attacks/nq_cell_worker.py: a plain subprocess, so the
per-cell timeout can stop a running BKZ and no parent __main__ is re-imported.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ppseb.trace import jsonable  # noqa: E402
from attacks.boundary import run_boundary_cell  # noqa: E402

MARKER = "@@BOUNDARY_JSON@@"


def main() -> None:
    a = json.loads(sys.argv[1])
    cell = run_boundary_cell(a["n"], a["q"], a["J"], a["records_per_period"], a["seed"],
                             tuple(a["beta_ladder"]), a["attack_budget_s"],
                             run_stolen=a.get("run_stolen", True))
    print(MARKER + json.dumps(jsonable(cell)))


if __name__ == "__main__":
    main()
