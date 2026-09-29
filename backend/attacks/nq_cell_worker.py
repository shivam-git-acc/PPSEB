"""Runs ONE (n, q) cell and prints it as JSON. Invoked as a subprocess by
`nq_sweep.run_cell_with_timeout`.

A separate process (rather than a thread) is what makes the per-cell timeout
real: a running BKZ cannot be interrupted inside a thread. It is a plain
subprocess rather than multiprocessing because both spawn and forkserver pass
the parent's __main__ path to the child -- which is "<stdin>" under
`python - <<EOF` (every cell of a real grid run died that way) and the server's
entry script under uvicorn. This module is also the child's main module, so
fpylll/cysignals initialise on its main thread.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ppseb.trace import jsonable  # noqa: E402
from attacks.nq_sweep import run_cell  # noqa: E402

MARKER = "@@CELL_JSON@@"


def main() -> None:
    args = json.loads(sys.argv[1])
    cell = run_cell(
        args["n"], args["q"], args["J"], args["repeats"],
        args["records_per_period"], args["seed_base"],
    )
    # Marker-delimited: fpylll and friends may write to stdout/stderr.
    print(MARKER + json.dumps(jsonable(cell)))


if __name__ == "__main__":
    main()
