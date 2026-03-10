#!/usr/bin/env bash
# scripts/mutation-test.sh — Run mutation testing on security-critical modules.
#
# mutmut injects small changes (mutants) into the source code and checks
# whether our test suite catches them. A surviving mutant = a weak/missing
# assertion.
#
# Usage:
#   ./scripts/mutation-test.sh              # full run (5 modules)
#   ./scripts/mutation-test.sh --results    # show last results
#   ./scripts/mutation-test.sh --survivors  # show surviving mutants
#
# Prerequisites:
#   pip install mutmut  (or: pip install -e '.[dev]')
#
# Copyright 2025-2026 Invariant Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# ── Helpers ───────────────────────────────────────────────────────────

usage() {
    echo "Usage: $0 [--results] [--survivors] [--max-children N]"
    echo ""
    echo "Options:"
    echo "  --results       Show results from last run"
    echo "  --survivors     Show only surviving mutants (needs results)"
    echo "  --max-children  Number of parallel test runners (default: 4)"
    echo "  --help          Show this help"
    exit 0
}

# ── Parse args ────────────────────────────────────────────────────────

ACTION="run"
MAX_CHILDREN=4

while [[ $# -gt 0 ]]; do
    case "$1" in
        --results)
            ACTION="results"
            shift
            ;;
        --survivors)
            ACTION="survivors"
            shift
            ;;
        --max-children)
            MAX_CHILDREN="$2"
            shift 2
            ;;
        --help|-h)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# ── Actions ───────────────────────────────────────────────────────────

case "$ACTION" in
    results)
        echo "═══ Mutation Testing Results ═══"
        python3 -c "
import sys, json
from pathlib import Path
mutants_dir = Path('mutants/aiir')
if not mutants_dir.exists():
    print('(no results yet — run mutation tests first)')
    sys.exit(0)
total = killed = survived = pending = 0
for meta in sorted(mutants_dir.glob('*.meta')):
    data = json.loads(meta.read_text())
    codes = data.get('exit_code_by_key', {})
    for name, code in codes.items():
        total += 1
        if code is None: pending += 1
        elif code == 0: survived += 1
        else: killed += 1
    stem = meta.stem
    k = sum(1 for v in codes.values() if v is not None and v != 0)
    s = sum(1 for v in codes.values() if v == 0)
    p = sum(1 for v in codes.values() if v is None)
    t = len(codes)
    print(f'  {stem}: {t} mutants — killed={k} survived={s} pending={p}')
print()
if total > 0:
    score = killed / (killed + survived) * 100 if (killed + survived) > 0 else 0
    print(f'Total: {total} mutants — killed={killed} survived={survived} pending={pending}')
    print(f'Mutation score: {score:.1f}% ({killed}/{killed+survived} tested mutants killed)')
"
        exit 0
        ;;
    survivors)
        echo "═══ Surviving Mutants ═══"
        echo "(These represent weak/missing assertions)"
        echo ""
        python3 -c "
import json
from pathlib import Path
mutants_dir = Path('mutants/aiir')
if not mutants_dir.exists():
    print('(no results yet — run mutation tests first)')
    exit(0)
found = False
for meta in sorted(mutants_dir.glob('*.meta')):
    data = json.loads(meta.read_text())
    codes = data.get('exit_code_by_key', {})
    for name, code in codes.items():
        if code == 0:
            if not found:
                found = True
            print(f'  SURVIVED: {name}')
if not found:
    print('  (no survivors — all tested mutants were killed!)')
"
        exit 0
        ;;
    run)
        ;;
esac

# ── Run mutation testing ──────────────────────────────────────────────

echo "═══ AIIR Mutation Testing ═══"
echo ""
echo "Config: pyproject.toml [tool.mutmut]"
echo "Parallelism: --max-children $MAX_CHILDREN"
echo ""

# Workaround for mutmut v3 bug (#805-ish):
# When run as `python -m mutmut`, the module is registered as __main__ in
# sys.modules, not as mutmut.__main__. The trampoline code does:
#   from mutmut.__main__ import record_trampoline_hit
# which re-imports the module and hits set_start_method('fork') again.
# Fix: import mutmut.__main__ explicitly so it's cached in sys.modules,
# then invoke the CLI entry point.
python3 -c "
import sys
import mutmut.__main__  # ensure cached as 'mutmut.__main__' in sys.modules
sys.argv = ['mutmut', 'run', '--max-children', '$MAX_CHILDREN']
mutmut.__main__.cli()
"

echo ""
echo "═══ Summary ═══"
"$0" --results || true

echo ""
echo "To see surviving mutants: $0 --survivors"
