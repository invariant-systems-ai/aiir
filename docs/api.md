# AIIR Python API Reference

> **Module**: `aiir` · **Version**: 1.2.4 · **License**: Apache 2.0
>
> Zero dependencies — Python standard library only.

```python
from aiir import generate_receipt, verify_receipt, detect_ai_signals
```

All symbols below are importable directly from `aiir` and listed in `__all__`.

---

## Receipt Generation

### `generate_receipt`

```python
def generate_receipt(
    commit_ref: str = "HEAD",
    cwd: Optional[str] = None,
    ai_only: bool = False,
    redact_files: bool = False,
    instance_id: Optional[str] = None,
    namespace: Optional[str] = None,
    agent_attestation: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]
```

Generate a cryptographic receipt for a single commit. Returns `None` if the commit is skipped (e.g. `ai_only=True` and no AI signals detected).

### `generate_receipts_for_range`

```python
def generate_receipts_for_range(
    range_spec: str,
    cwd: Optional[str] = None,
    ai_only: bool = False,
    redact_files: bool = False,
    instance_id: Optional[str] = None,
    namespace: Optional[str] = None,
    agent_attestation: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]
```

Generate receipts for all commits in a git range (e.g. `"main..HEAD"`).

### `format_receipt_pretty`

```python
def format_receipt_pretty(
    receipt: Dict[str, Any],
    signed: str = "none",
) -> str
```

Human-readable receipt summary. `signed` controls the signing status line (e.g. `"YES (sigstore)"` or `"none"`).

### `wrap_in_toto_statement`

```python
def wrap_in_toto_statement(receipt: Dict[str, Any]) -> Dict[str, Any]
```

Wrap an AIIR receipt in an [in-toto Statement v1](https://in-toto.io/Statement/v1) envelope. Compatible with SLSA verifiers, Sigstore policy-controller, Kyverno, OPA/Gatekeeper, and Tekton Chains.

---

## Detection

### `detect_ai_signals`

```python
def detect_ai_signals(
    message: str,
    author_name: str = "",
    author_email: str = "",
    committer_name: str = "",
    committer_email: str = "",
) -> Tuple[List[str], List[str]]
```

Detect AI authorship and automation/bot signals in commit metadata. Returns `(ai_signals, bot_signals)` where each is a list of human-readable signal descriptions. **AI signals** = declared AI coding assistance (Copilot, ChatGPT, Claude, etc.). **Bot signals** = pure automation (Dependabot, Renovate, github-actions, etc.).

---

## Verification

### `verify_receipt`

```python
def verify_receipt(receipt: Dict[str, Any]) -> Dict[str, Any]
```

Verify a receipt's content-addressed integrity. Recomputes `content_hash` and `receipt_id` from the receipt core and checks they match the stored values. Returns a dict with `verified` (bool), `reason` (str), and `schema_errors` (list).

### `verify_receipt_file`

```python
def verify_receipt_file(filepath: str) -> Dict[str, Any]
```

Load and verify a receipt JSON file. Handles single receipts or arrays. Rejects symlinks and oversized files (>10 MB).

### `explain_verification`

```python
def explain_verification(result: Dict[str, Any]) -> str
```

Return a human-readable explanation of a verification result. Covers: why it passed, why it failed, and schema warnings.

---

## Schema Validation

### `validate_receipt`

```python
def validate_receipt(receipt: Any) -> List[str]
```

Validate a receipt dict against the `aiir/commit_receipt.v1` schema. Returns a list of human-readable error strings. An empty list means the receipt passes structural validation. Does **not** verify `content_hash` or `receipt_id` integrity — use `verify_receipt()` for that.

> **Note**: This is aliased from `validate_receipt_schema` for ergonomic import.

---

## Ledger

### `append_to_ledger`

```python
def append_to_ledger(
    receipts: List[Dict[str, Any]],
    ledger_dir: Optional[str] = None,
) -> Tuple[int, int, str]
```

Append receipts to the JSONL ledger, skipping duplicates. Returns `(appended_count, skipped_count, ledger_path)`.

### `export_ledger`

```python
def export_ledger(ledger_dir: Optional[str] = None) -> Dict[str, Any]
```

Bundle the ledger into a portable JSON export. The format is designed so that managed services can ingest it in a single upload.

---

## Stats & Policy

### `format_stats`

```python
def format_stats(
    index: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
) -> str
```

Format a human-readable stats dashboard from the ledger index.

### `format_badge`

```python
def format_badge(
    index: Dict[str, Any],
    namespace: Optional[str] = None,
) -> Dict[str, str]
```

Generate a shields.io badge URL and Markdown snippet from ledger stats. Returns a dict with `url`, `markdown`, and `label` keys.

### `check_policy`

```python
def check_policy(
    index: Dict[str, Any],
    *,
    max_ai_percent: Optional[float] = None,
) -> Tuple[bool, str]
```

Evaluate policy gates against ledger stats. Returns `(passed, message)`. `passed` is `True` when all gates pass.

### `load_policy`

```python
def load_policy(
    ledger_dir: str = ".aiir",
    preset: Optional[str] = None,
) -> Dict[str, Any]
```

Load policy from `.aiir/policy.json`, or fall back to a preset. Priority: (1) explicit preset, (2) policy file, (3) `"balanced"` default.

### `evaluate_receipt_policy`

```python
def evaluate_receipt_policy(
    receipt: Dict[str, Any],
    policy: Dict[str, Any],
    *,
    is_signed: bool = False,
    schema_errors: Optional[List[str]] = None,
) -> List[PolicyViolation]
```

Evaluate a single receipt against a policy. Returns a list of violations. Empty list = all checks passed.

### `evaluate_ledger_policy`

```python
def evaluate_ledger_policy(
    index: Dict[str, Any],
    policy: Dict[str, Any],
) -> Tuple[bool, str, List[PolicyViolation]]
```

Evaluate ledger-level aggregate policy checks. Returns `(passed, summary, violations)`.

### `POLICY_PRESETS`

```python
POLICY_PRESETS: Dict[str, Dict[str, Any]]
```

Three built-in policy presets:

| Preset | Use Case | Signing | Max AI % |
|--------|----------|---------|----------|
| `"strict"` | Enterprise / regulated | Required | 50% |
| `"balanced"` | Standard teams | Recommended | No cap |
| `"permissive"` | Open source / experimentation | Optional | No cap |

---

## Low-Level (Third-Party Implementors)

### `_canonical_json`

```python
def _canonical_json(obj: Any) -> str
```

Deterministic JSON serialization (sorted keys, no whitespace). Uses an explicit depth limit (max 64) to prevent stack overflow. This is the serialization algorithm used to compute `content_hash`.

### `_sha256`

```python
def _sha256(data: str) -> str
```

SHA-256 hex digest of a UTF-8 string. Used for `content_hash` and `receipt_id` computation.

---

## Quick Examples

### Generate and verify a receipt

```python
from aiir import generate_receipt, verify_receipt, explain_verification

receipt = generate_receipt()  # current HEAD
if receipt:
    result = verify_receipt(receipt)
    print(explain_verification(result))
```

### Detect AI signals

```python
from aiir import detect_ai_signals

ai_signals, bot_signals = detect_ai_signals(
    message="feat: add login page\n\nGenerated by GitHub Copilot",
    author_name="Alice",
    author_email="alice@example.com",
)
print(f"AI: {ai_signals}, Bot: {bot_signals}")
```

### Policy enforcement

```python
from aiir import load_policy, evaluate_receipt_policy

policy = load_policy(preset="strict")
violations = evaluate_receipt_policy(receipt, policy, is_signed=True)
if violations:
    for v in violations:
        print(f"⚠ {v}")
```
