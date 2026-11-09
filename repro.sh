#!/usr/bin/env bash
# repro.sh — regenerate the headline attack and cost numbers (Requirement 8.3).
#
#   ./repro.sh            # seed 42, full grids
#   ./repro.sh 1234       # a different seed
#   ./repro.sh 42 --fast  # smaller grids, for a quick check
#
# Writes backend/results/repro.json, a committed file. Must finish in under
# 600 seconds; on the dev laptop it takes about 10.
#
# On Windows without bash, use repro.cmd — same arguments, same module.
set -euo pipefail

cd "$(dirname "$0")/backend"

SEED="${1:-42}"
shift || true

exec python -m medvault.repro --seed "$SEED" --output results/repro.json "$@"
