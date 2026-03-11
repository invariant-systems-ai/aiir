#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON:-python3}"
PROFILE="${1:-required}"

cd "$ROOT_DIR"

run() {
  echo
  echo ">>> $*"
  "$@"
}

run_shell() {
  echo
  echo ">>> $*"
  bash -euo pipefail -c "$*"
}

install_requirements() {
  local file="$1"
  run "$PYTHON_BIN" -m pip install --require-hashes --no-deps -r "$file"
}

run_in_isolated_env() {
  local tmpdir
  tmpdir="$(mktemp -d)"

  run "$PYTHON_BIN" -m venv "$tmpdir"
  run "$tmpdir/bin/python" -m pip install --upgrade pip
  run "$tmpdir/bin/python" -m pip install --require-hashes --no-deps -r .github/requirements/pip-audit.txt
  run "$tmpdir/bin/python" -m pip install --require-hashes --no-deps -r .github/requirements/pip-licenses.txt
  run "$tmpdir/bin/python" -m pip install '.[dev,sign]'
  run_shell "cd '$ROOT_DIR' && '$tmpdir/bin/pip' freeze | grep -iv '^aiir' > _audit_reqs.txt && '$tmpdir/bin/pip-audit' --strict --desc -r _audit_reqs.txt && '$tmpdir/bin/pip-licenses' --format=json --output-file=licenses.json && '$tmpdir/bin/python' scripts/check_licenses.py licenses.json && rm -f _audit_reqs.txt licenses.json"
  rm -rf "$tmpdir"
}

package_smoke() {
  local tmpdir
  tmpdir="$(mktemp -d)"

  run "$PYTHON_BIN" -m pip install .
  run aiir --version
  run aiir-mcp-server --version

  run_shell "cd '$tmpdir' && git init && git config user.email ci@test && git config user.name CI && echo hello > file.txt && git add . && git commit -m init && aiir --pretty && python3 -c \"import pathlib, sys; sys.exit(0 if pathlib.Path('.aiir/receipts.jsonl').exists() else 1)\" && python3 -c \"import pathlib, sys; sys.exit(0 if pathlib.Path('.aiir/index.json').exists() else 1)\" && aiir -o .receipts/ && aiir --verify .receipts/*.json"

  run "$PYTHON_BIN" -c "from pathlib import Path; import aiir; p = Path(aiir.__file__).parent / 'py.typed'; assert p.exists(), f'py.typed missing at {p}'"
  rm -rf "$tmpdir"
}

run_required() {
  install_requirements .github/requirements/test.txt
  run "$PYTHON_BIN" -m pytest tests/ -v --tb=short --ignore=tests/test_fuzz.py

  install_requirements .github/requirements/fuzz.txt
  run "$PYTHON_BIN" -m pytest tests/test_fuzz.py -v --tb=short

  install_requirements .github/requirements/coverage.txt
  run coverage erase
  run coverage run --source=aiir -m pytest tests/ --ignore=tests/test_fuzz.py -q --tb=short
  run coverage report --show-missing
  run coverage report --fail-under=100

  run "$PYTHON_BIN" scripts/sync-version.py --check
  package_smoke
}

run_quality_security() {
  install_requirements .github/requirements/typecheck.txt
  run mypy aiir/

  install_requirements .github/requirements/yamllint.txt
  run yamllint -d '{extends: relaxed, rules: {line-length: disable}}' templates/ examples/

  install_requirements .github/requirements/ruff.txt
  run ruff check aiir/ tests/ scripts/
  run ruff format --check aiir/ tests/ scripts/

  install_requirements .github/requirements/bandit.txt
  run bandit -r aiir/ -ll

  install_requirements .github/requirements/semgrep.txt
  run semgrep scan --config p/python --config p/security-audit --config p/secrets --error aiir/

  run_in_isolated_env

  run_shell "MISSING=0; for f in \
    \$(find aiir/ tests/ scripts/ -name '*.py' -not -path '*__pycache__*' -not -name '__init__.py'); do \
      if ! grep -q 'SPDX-License-Identifier' \"\$f\"; then echo \"Missing SPDX-License-Identifier header: \$f\"; MISSING=\$((MISSING + 1)); fi; \
    done; \
    if [[ \"\$MISSING\" -gt 0 ]]; then exit 1; fi"
}

run_mutation_smoke() {
  install_requirements .github/requirements/mutation.txt
  run_shell 'original=$(mktemp) && cp pyproject.toml "$original" && trap "cp \"$original\" pyproject.toml; rm -f \"$original\"" EXIT && python3 - <<"PY"
from pathlib import Path
import re

cfg = Path("pyproject.toml")
original = cfg.read_text()
exclude = sorted(
    f"aiir/{path.name}"
    for path in Path("aiir").glob("*.py")
    if path.name not in {"_verify.py", "_canonical_cbor.py", "_verify_cbor.py"}
)
new_block = "do_not_mutate = [\n" + "".join(f"    \"{item}\",\n" for item in exclude) + "]"
patched = re.sub(r"do_not_mutate\s*=\s*\[.*?\]", new_block, original, flags=re.DOTALL, count=1)
cfg.write_text(patched)
PY
python3 -m mutmut run --max-children 4'

  run "$PYTHON_BIN" -c 'import json, sys; from pathlib import Path; mutants_dir = Path("mutants/aiir"); killed = survived = 0; 
for meta in mutants_dir.glob("*.meta"):
    data = json.loads(meta.read_text())
    for code in data.get("exit_code_by_key", {}).values():
        if code is None:
            continue
        if code == 0:
            survived += 1
        else:
            killed += 1
tested = killed + survived
assert tested > 0, "No mutants tested"
score = killed / tested * 100
print(f"Mutation score: {score:.1f}% ({killed}/{tested})")
assert score >= 75, f"Mutation score {score:.1f}% is below 75% threshold"'
}

case "$PROFILE" in
  required)
    run_required
    ;;
  full)
    run_required
    run_quality_security
    ;;
  mutation)
    run_mutation_smoke
    ;;
  all)
    run_required
    run_quality_security
    run_mutation_smoke
    ;;
  *)
    echo "Usage: scripts/ci-local.sh [required|full|mutation|all]" >&2
    exit 2
    ;;
esac

echo
echo "Local CI profile '$PROFILE' passed"