#!/usr/bin/env python3
"""
Property-based tests for AIIR — algebraic invariants that MUST hold.

Unlike test_fuzz.py (which tests sanitization/injection defenses), these
tests verify structural properties of the receipt system:

  1. Content-addressing is deterministic
  2. Self-generated receipts always self-verify
  3. Tampering with any core field breaks verification
  4. Schema validation passes on all self-generated receipts
  5. Policy evaluation is monotone (strict ⊇ balanced ⊇ permissive)
  6. In-toto wrapping is structure-preserving
  7. Canonical JSON is idempotent and deterministic
  8. Agent attestation sanitization is idempotent
  9. AI signal detection is pure (deterministic)
 10. _normalize_for_detection is idempotent

Run:
    python3 -m pytest tests/test_properties.py -v --tb=short
    python3 -m pytest tests/test_properties.py -v --hypothesis-show-statistics

Copyright 2025-2026 Invariant Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import copy
import json
import string

import pytest

hypothesis = pytest.importorskip("hypothesis", reason="hypothesis not installed")
from hypothesis import assume, given, settings, HealthCheck  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

HAS_HYPOTHESIS = True

from aiir._core import (  # noqa: E402
    CommitInfo,
    _canonical_json,
    _normalize_for_detection,
    _sha256,
    _strip_terminal_escapes,
    _strip_url_credentials,
)
from aiir._detect import detect_ai_signals  # noqa: E402
from aiir._policy import (  # noqa: E402
    POLICY_PRESETS,
    evaluate_ledger_policy,
    evaluate_receipt_policy,
)
from aiir._receipt import (  # noqa: E402
    _sanitize_agent_attestation,
    build_commit_receipt,
    format_receipt_detail,
    format_receipt_pretty,
    wrap_in_toto_statement,
)
from aiir._schema import validate_receipt_schema  # noqa: E402
from aiir._verify import verify_receipt  # noqa: E402

# ── Strategies ────────────────────────────────────────────────────────

# SHA-256 hex strings (40 or 64 chars)
sha_hex_40 = st.text(
    alphabet=st.sampled_from(list("0123456789abcdef")),
    min_size=40,
    max_size=40,
)

sha_hex_64 = st.text(
    alphabet=st.sampled_from(list("0123456789abcdef")),
    min_size=64,
    max_size=64,
)

# Safe text for commit fields (printable ASCII, no NUL)
safe_text = st.text(
    alphabet=st.sampled_from(
        list(
            string.printable.replace("\x00", "").replace("\x0b", "").replace("\x0c", "")
        )
    ),
    min_size=1,
    max_size=200,
)

# ISO 8601 dates
iso_date = st.from_regex(
    r"20[0-9]{2}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9][+-][0-9]{2}:[0-9]{2}",
    fullmatch=True,
)

# File paths
file_paths = st.lists(
    st.text(
        alphabet=st.sampled_from(list(string.ascii_lowercase + string.digits + "/._-")),
        min_size=1,
        max_size=50,
    ),
    min_size=0,
    max_size=20,
)

# AI signal strings from the canonical list
ai_signal_strs = st.lists(
    st.text(
        alphabet=st.sampled_from(list(string.ascii_lowercase + " :-_")),
        min_size=3,
        max_size=50,
    ),
    min_size=0,
    max_size=5,
)

# Authorship classes
authorship_classes = st.sampled_from(
    ["human", "ai_assisted", "ai_generated", "bot", "ai+bot"]
)

# Full CommitInfo strategy
commit_info_st = st.builds(
    CommitInfo,
    sha=sha_hex_40,
    author_name=safe_text,
    author_email=safe_text.map(lambda s: s[:20] + "@example.com"),
    author_date=iso_date,
    committer_name=safe_text,
    committer_email=safe_text.map(lambda s: s[:20] + "@example.com"),
    committer_date=iso_date,
    subject=safe_text,
    body=safe_text,
    diff_stat=safe_text,
    diff_hash=sha_hex_64.map(lambda h: "sha256:" + h),
    files_changed=file_paths,
    ai_signals_detected=ai_signal_strs,
    is_ai_authored=st.booleans(),
    bot_signals_detected=ai_signal_strs,
    is_bot_authored=st.booleans(),
    authorship_class=authorship_classes,
)

# Agent attestation dicts
agent_attestation_st = st.one_of(
    st.none(),
    st.fixed_dictionaries(
        {},
        optional={
            "tool_id": safe_text,
            "model_class": safe_text,
            "session_id": safe_text,
            "run_context": st.sampled_from(["ide", "cli", "ci", "mcp"]),
            "tool_version": st.from_regex(r"[0-9]+\.[0-9]+\.[0-9]+", fullmatch=True),
            "confidence": st.sampled_from(["declared", "inferred", "verified"]),
        },
    ),
)

# JSON-serializable primitive values
json_primitives = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53), max_value=2**53),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(min_size=0, max_size=100),
)

# Shallow JSON objects (depth 1-2) for canonical JSON tests
json_objects = st.recursive(
    json_primitives,
    lambda children: st.one_of(
        st.lists(children, max_size=8),
        st.dictionaries(st.text(min_size=1, max_size=20), children, max_size=8),
    ),
    max_leaves=30,
)


# ── Helpers ───────────────────────────────────────────────────────────


def _build_receipt(commit: CommitInfo, attestation=None) -> dict:
    """Build a receipt from a CommitInfo, mocking git remote."""
    import unittest.mock

    with unittest.mock.patch(
        "aiir._receipt._run_git", return_value="https://github.com/test/repo"
    ):
        return build_commit_receipt(
            commit,
            repo_root="/tmp/test",
            agent_attestation=attestation,
        )


# ═══════════════════════════════════════════════════════════════════════
# PROPERTY 1: Content-addressing is deterministic
# ═══════════════════════════════════════════════════════════════════════


class TestContentAddressingDeterministic:
    """Same CommitInfo → same receipt_id, always."""

    @given(commit=commit_info_st)
    @settings(
        max_examples=200,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_same_commit_same_receipt_id(self, commit: CommitInfo):
        """Building a receipt twice from identical input produces identical IDs."""
        r1 = _build_receipt(commit)
        r2 = _build_receipt(commit)
        assert r1["receipt_id"] == r2["receipt_id"]
        assert r1["content_hash"] == r2["content_hash"]

    @given(commit=commit_info_st, att=agent_attestation_st)
    @settings(
        max_examples=200,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_extensions_dont_affect_content_hash(self, commit: CommitInfo, att):
        """Extensions (incl. agent_attestation) are NOT in the content hash."""
        r1 = _build_receipt(commit, attestation=None)
        r2 = _build_receipt(commit, attestation=att)
        # Content hash and receipt_id should be the same
        assert r1["content_hash"] == r2["content_hash"]
        assert r1["receipt_id"] == r2["receipt_id"]


# ═══════════════════════════════════════════════════════════════════════
# PROPERTY 2: Self-generated receipts always self-verify
# ═══════════════════════════════════════════════════════════════════════


class TestSelfVerification:
    """Every receipt we build must pass our own verifier."""

    @given(commit=commit_info_st)
    @settings(
        max_examples=300,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_receipt_round_trip(self, commit: CommitInfo):
        """build_commit_receipt → verify_receipt must return valid=True."""
        receipt = _build_receipt(commit)
        result = verify_receipt(receipt)
        assert result["valid"], f"Self-verification failed: {result.get('errors')}"

    @given(commit=commit_info_st)
    @settings(
        max_examples=200,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_receipt_survives_json_round_trip(self, commit: CommitInfo):
        """Receipt → JSON → parse → verify must still pass."""
        receipt = _build_receipt(commit)
        serialized = json.dumps(receipt, sort_keys=True)
        deserialized = json.loads(serialized)
        result = verify_receipt(deserialized)
        assert result["valid"], (
            f"JSON round-trip broke verification: {result.get('errors')}"
        )


# ═══════════════════════════════════════════════════════════════════════
# PROPERTY 3: Tampering with any core field breaks verification
# ═══════════════════════════════════════════════════════════════════════


class TestTamperDetection:
    """Modifying ANY core field must cause verify_receipt to return valid=False."""

    @given(commit=commit_info_st, new_subject=safe_text)
    @settings(
        max_examples=200,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_tamper_commit_subject(self, commit: CommitInfo, new_subject: str):
        """Changing commit.subject after receipt creation must break hash."""
        receipt = _build_receipt(commit)
        assume(new_subject != receipt["commit"]["subject"])
        tampered = copy.deepcopy(receipt)
        tampered["commit"]["subject"] = new_subject
        result = verify_receipt(tampered)
        assert not result["valid"], "Tampered subject was not detected"

    @given(commit=commit_info_st)
    @settings(
        max_examples=200,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_tamper_ai_flag(self, commit: CommitInfo):
        """Flipping is_ai_authored must break verification."""
        receipt = _build_receipt(commit)
        tampered = copy.deepcopy(receipt)
        tampered["ai_attestation"]["is_ai_authored"] = not receipt["ai_attestation"][
            "is_ai_authored"
        ]
        result = verify_receipt(tampered)
        assert not result["valid"], "Tampered AI flag was not detected"

    @given(commit=commit_info_st, fake_sha=sha_hex_40)
    @settings(
        max_examples=200,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_tamper_commit_sha(self, commit: CommitInfo, fake_sha: str):
        """Replacing commit SHA must break verification."""
        receipt = _build_receipt(commit)
        assume(fake_sha != receipt["commit"]["sha"])
        tampered = copy.deepcopy(receipt)
        tampered["commit"]["sha"] = fake_sha
        result = verify_receipt(tampered)
        assert not result["valid"], "Tampered SHA was not detected"

    @given(commit=commit_info_st, fake_hash=sha_hex_64)
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_tamper_content_hash(self, commit: CommitInfo, fake_hash: str):
        """Replacing content_hash must break verification."""
        receipt = _build_receipt(commit)
        tampered = copy.deepcopy(receipt)
        tampered["content_hash"] = "sha256:" + fake_hash
        assume(tampered["content_hash"] != receipt["content_hash"])
        result = verify_receipt(tampered)
        assert not result["valid"], "Tampered content_hash was not detected"

    @given(commit=commit_info_st, extra_signal=safe_text)
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_tamper_inject_signal(self, commit: CommitInfo, extra_signal: str):
        """Injecting an extra AI signal post-creation must break hash."""
        receipt = _build_receipt(commit)
        tampered = copy.deepcopy(receipt)
        tampered["ai_attestation"]["signals_detected"].append(extra_signal)
        tampered["ai_attestation"]["signal_count"] += 1
        result = verify_receipt(tampered)
        assert not result["valid"], "Injected signal was not detected"


# ═══════════════════════════════════════════════════════════════════════
# PROPERTY 4: Schema validation passes on all self-generated receipts
# ═══════════════════════════════════════════════════════════════════════


class TestSchemaOnSelfGenerated:
    """Our own receipts must always pass our own schema validator."""

    @given(commit=commit_info_st)
    @settings(
        max_examples=300,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_self_generated_receipts_pass_schema(self, commit: CommitInfo):
        """build_commit_receipt output must pass validate_receipt_schema."""
        receipt = _build_receipt(commit)
        errors = validate_receipt_schema(receipt)
        assert errors == [], f"Schema errors on self-generated receipt: {errors}"


# ═══════════════════════════════════════════════════════════════════════
# PROPERTY 5: Policy strictness is monotone
# ═══════════════════════════════════════════════════════════════════════


class TestPolicyMonotonicity:
    """strict ⊇ balanced ⊇ permissive — anything strict rejects, so do the others."""

    @given(commit=commit_info_st, is_signed=st.booleans())
    @settings(
        max_examples=200,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_permissive_accepts_superset_of_balanced(
        self, commit: CommitInfo, is_signed: bool
    ):
        """If balanced accepts a receipt, permissive must also accept."""
        receipt = _build_receipt(commit)
        balanced = {**POLICY_PRESETS["balanced"], "preset": "balanced"}
        permissive = {**POLICY_PRESETS["permissive"], "preset": "permissive"}

        v_balanced = evaluate_receipt_policy(receipt, balanced, is_signed=is_signed)
        v_permissive = evaluate_receipt_policy(receipt, permissive, is_signed=is_signed)

        if not v_balanced:  # balanced passes → permissive must pass
            assert not v_permissive, (
                f"Balanced accepted but permissive rejected: {[v.to_dict() for v in v_permissive]}"
            )

    @given(commit=commit_info_st, is_signed=st.booleans())
    @settings(
        max_examples=200,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_balanced_accepts_superset_of_strict(
        self, commit: CommitInfo, is_signed: bool
    ):
        """If strict accepts, balanced must also accept."""
        receipt = _build_receipt(commit)
        strict = {**POLICY_PRESETS["strict"], "preset": "strict"}
        balanced = {**POLICY_PRESETS["balanced"], "preset": "balanced"}

        v_strict = evaluate_receipt_policy(receipt, strict, is_signed=is_signed)
        v_balanced = evaluate_receipt_policy(receipt, balanced, is_signed=is_signed)

        if not v_strict:  # strict passes → balanced must pass
            assert not v_balanced, (
                f"Strict accepted but balanced rejected: {[v.to_dict() for v in v_balanced]}"
            )


# ═══════════════════════════════════════════════════════════════════════
# PROPERTY 6: In-toto wrapping is structure-preserving
# ═══════════════════════════════════════════════════════════════════════


class TestInTotoWrapping:
    """The in-toto envelope must preserve the receipt verbatim."""

    @given(commit=commit_info_st)
    @settings(
        max_examples=200,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_predicate_is_original_receipt(self, commit: CommitInfo):
        """wrap_in_toto_statement(r)['predicate'] == r."""
        receipt = _build_receipt(commit)
        statement = wrap_in_toto_statement(receipt)

        assert statement["_type"] == "https://in-toto.io/Statement/v1"
        assert statement["predicate"] == receipt
        assert isinstance(statement["subject"], list)
        assert len(statement["subject"]) == 1

    @given(commit=commit_info_st)
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_subject_contains_commit_sha(self, commit: CommitInfo):
        """Subject digest must contain the commit SHA."""
        receipt = _build_receipt(commit)
        statement = wrap_in_toto_statement(receipt)
        subject = statement["subject"][0]
        assert subject["digest"]["gitCommit"] == commit.sha


# ═══════════════════════════════════════════════════════════════════════
# PROPERTY 7: Canonical JSON is idempotent and deterministic
# ═══════════════════════════════════════════════════════════════════════


class TestCanonicalJson:
    """_canonical_json must produce a stable, unique representation."""

    @given(obj=json_objects)
    @settings(
        max_examples=500,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_idempotent_round_trip(self, obj):
        """canonical_json(parse(canonical_json(x))) == canonical_json(x)."""
        try:
            cj1 = _canonical_json(obj)
        except (ValueError, OverflowError):
            return  # Object too deep or has disallowed values
        parsed = json.loads(cj1)
        cj2 = _canonical_json(parsed)
        assert cj1 == cj2, f"Not idempotent: {cj1!r} != {cj2!r}"

    @given(obj=json_objects)
    @settings(
        max_examples=500,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_deterministic(self, obj):
        """Same object → same canonical JSON, every time."""
        try:
            cj1 = _canonical_json(obj)
            cj2 = _canonical_json(obj)
        except (ValueError, OverflowError):
            return
        assert cj1 == cj2

    @given(obj=json_objects)
    @settings(
        max_examples=300,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_no_whitespace(self, obj):
        """Canonical JSON has no unnecessary whitespace."""
        try:
            cj = _canonical_json(obj)
        except (ValueError, OverflowError):
            return
        # The only spaces are inside string values, never structural
        parsed_back = json.loads(cj)
        cj_min = json.dumps(
            parsed_back, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        assert cj == cj_min

    @given(
        d=st.dictionaries(
            st.text(
                min_size=1,
                max_size=10,
                alphabet=st.sampled_from(list(string.ascii_letters)),
            ),
            st.integers(min_value=0, max_value=100),
            min_size=2,
            max_size=10,
        )
    )
    @settings(max_examples=200, suppress_health_check=[HealthCheck.differing_executors])
    def test_key_order_irrelevant(self, d: dict):
        """Key insertion order must not affect canonical output."""
        import random

        keys = list(d.keys())
        random.shuffle(keys)
        d_shuffled = {k: d[k] for k in keys}
        assert _canonical_json(d) == _canonical_json(d_shuffled)


# ═══════════════════════════════════════════════════════════════════════
# PROPERTY 8: Agent attestation sanitization is idempotent
# ═══════════════════════════════════════════════════════════════════════


class TestAgentAttestationSanitization:
    """Sanitizing twice must produce the same result as sanitizing once."""

    @given(att=agent_attestation_st)
    @settings(
        max_examples=300,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_idempotent(self, att):
        """sanitize(sanitize(x)) == sanitize(x)."""
        s1 = _sanitize_agent_attestation(att)
        s2 = _sanitize_agent_attestation(s1)
        assert s1 == s2

    @given(att=agent_attestation_st)
    @settings(
        max_examples=200,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_only_allowed_keys(self, att):
        """Output must contain only whitelisted keys."""
        from aiir._receipt import _AGENT_ATTESTATION_KEYS

        result = _sanitize_agent_attestation(att)
        assert isinstance(result, dict)
        for k in result:
            assert k in _AGENT_ATTESTATION_KEYS, f"Unexpected key: {k}"

    @given(
        att=st.dictionaries(
            st.text(min_size=1, max_size=30),
            st.text(min_size=0, max_size=300),
            max_size=20,
        )
    )
    @settings(max_examples=200, suppress_health_check=[HealthCheck.differing_executors])
    def test_unknown_keys_stripped(self, att: dict):
        """Keys not in the allowlist must not appear in output."""
        from aiir._receipt import _AGENT_ATTESTATION_KEYS

        result = _sanitize_agent_attestation(att)
        for k in result:
            assert k in _AGENT_ATTESTATION_KEYS

    @given(att=agent_attestation_st)
    @settings(max_examples=200, suppress_health_check=[HealthCheck.differing_executors])
    def test_values_are_strings(self, att):
        """All output values must be strings."""
        result = _sanitize_agent_attestation(att)
        for k, v in result.items():
            assert isinstance(v, str), f"{k} value is {type(v).__name__}, expected str"


# ═══════════════════════════════════════════════════════════════════════
# PROPERTY 9: AI signal detection is pure (deterministic)
# ═══════════════════════════════════════════════════════════════════════


class TestDetectionPurity:
    """detect_ai_signals is a pure function — same inputs, same outputs."""

    @given(
        message=safe_text,
        author_name=safe_text,
        author_email=safe_text,
        committer_name=safe_text,
        committer_email=safe_text,
    )
    @settings(
        max_examples=300,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_deterministic(
        self, message, author_name, author_email, committer_name, committer_email
    ):
        """Calling detect twice with same args gives same result."""
        r1 = detect_ai_signals(
            message, author_name, author_email, committer_name, committer_email
        )
        r2 = detect_ai_signals(
            message, author_name, author_email, committer_name, committer_email
        )
        assert r1 == r2

    @given(
        message=st.sampled_from(
            [
                "fix: update README",
                "Co-authored-by: Copilot <copilot@github.com>",
                "Generated by ChatGPT",
                "chore: bump deps",
                "feat: add new feature\n\nGenerated-by: claude",
            ]
        ),
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.differing_executors])
    def test_known_signals_detected(self, message: str):
        """Known AI messages must produce non-empty ai_signals."""
        ai_signals, _ = detect_ai_signals(message)
        if any(
            kw in message.lower()
            for kw in ["copilot", "chatgpt", "claude", "generated-by"]
        ):
            assert len(ai_signals) > 0, f"Expected AI signals in: {message!r}"

    @given(
        committer_email=st.sampled_from(
            [
                "41898282+github-actions[bot]@users.noreply.github.com",
                "dependabot[bot]@users.noreply.github.com",
                "renovate[bot]@users.noreply.github.com",
            ]
        ),
    )
    @settings(max_examples=30, suppress_health_check=[HealthCheck.differing_executors])
    def test_bot_signals_detected(self, committer_email: str):
        """Known bot emails must produce bot_signals (not AI signals)."""
        _, bot_signals = detect_ai_signals(
            "chore: automated update",
            committer_email=committer_email,
        )
        assert len(bot_signals) > 0, f"Expected bot signals for: {committer_email}"


# ═══════════════════════════════════════════════════════════════════════
# PROPERTY 10: _normalize_for_detection is idempotent
# ═══════════════════════════════════════════════════════════════════════


class TestNormalizationIdempotent:
    """Normalization must converge: repeated application must stabilize."""

    @given(text=st.text(min_size=0, max_size=500))
    @settings(
        max_examples=500,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_convergent(self, text: str):
        """normalize(normalize(normalize(x))) == normalize(normalize(x)).

        The confusable table may have chains (e.g. Ѐ→Е→E) so strict
        idempotency (n(n(x))==n(x)) doesn't hold.  But normalization MUST
        converge: applying it 3 times must equal applying it twice.
        """
        n1 = _normalize_for_detection(text)
        n2 = _normalize_for_detection(n1)
        n3 = _normalize_for_detection(n2)
        assert n2 == n3, f"Not convergent after 2 passes: {n2!r} != {n3!r}"

    @given(text=st.text(min_size=0, max_size=200))
    @settings(
        max_examples=300,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_output_is_string(self, text: str):
        """Output must always be a string."""
        result = _normalize_for_detection(text)
        assert isinstance(result, str)


# ═══════════════════════════════════════════════════════════════════════
# PROPERTY 11: _sha256 is deterministic and has correct format
# ═══════════════════════════════════════════════════════════════════════


class TestSha256Properties:
    """SHA-256 helper properties."""

    @given(data=st.text(min_size=0, max_size=1000))
    @settings(
        max_examples=300,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_deterministic(self, data: str):
        """Same input → same hash."""
        assert _sha256(data) == _sha256(data)

    @given(data=st.text(min_size=0, max_size=1000))
    @settings(
        max_examples=300,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_hex_format(self, data: str):
        """Output must be 64 lowercase hex chars."""
        h = _sha256(data)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    @given(a=st.text(min_size=1, max_size=100), b=st.text(min_size=1, max_size=100))
    @settings(
        max_examples=300,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_collision_resistance(self, a: str, b: str):
        """Different inputs should produce different hashes (probabilistic)."""
        assume(a != b)
        assert _sha256(a) != _sha256(b)


# ═══════════════════════════════════════════════════════════════════════
# PROPERTY 12: Receipt formatting never crashes
# ═══════════════════════════════════════════════════════════════════════


class TestFormattingRobustness:
    """Pretty and detail formatters must never crash on valid receipts."""

    @given(commit=commit_info_st)
    @settings(
        max_examples=200,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_pretty_format_never_crashes(self, commit: CommitInfo):
        """format_receipt_pretty must return a string for any valid receipt."""
        receipt = _build_receipt(commit)
        result = format_receipt_pretty(receipt)
        assert isinstance(result, str)
        assert len(result) > 0

    @given(commit=commit_info_st)
    @settings(
        max_examples=200,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_detail_format_never_crashes(self, commit: CommitInfo):
        """format_receipt_detail must return a string for any valid receipt."""
        receipt = _build_receipt(commit)
        result = format_receipt_detail(receipt)
        assert isinstance(result, str)
        assert len(result) > 0

    @given(commit=commit_info_st, signed=safe_text)
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_pretty_with_arbitrary_signed_string(self, commit: CommitInfo, signed: str):
        """Signed status with arbitrary text must not crash."""
        receipt = _build_receipt(commit)
        result = format_receipt_pretty(receipt, signed=signed)
        assert isinstance(result, str)


# ═══════════════════════════════════════════════════════════════════════
# PROPERTY 13: URL credential stripping is safe
# ═══════════════════════════════════════════════════════════════════════


class TestUrlCredentialStripping:
    """_strip_url_credentials must remove credentials without crashing."""

    @given(
        url=st.one_of(
            st.from_regex(
                r"https?://([a-z0-9]+:[a-z0-9]+@)?[a-z]{2,10}\.[a-z]{2,4}(/[a-z0-9]*)*",
                fullmatch=True,
            ),
            st.text(min_size=0, max_size=200),
        )
    )
    @settings(
        max_examples=300,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_never_crashes(self, url: str):
        """Must never raise on any input."""
        result = _strip_url_credentials(url)
        assert isinstance(result, str)

    @given(
        user=st.text(
            alphabet=st.sampled_from(list(string.ascii_lowercase)),
            min_size=3,
            max_size=10,
        ),
        password=st.text(
            alphabet=st.sampled_from(list(string.ascii_lowercase + string.digits)),
            min_size=8,
            max_size=20,
        ),
        host=st.text(
            alphabet=st.sampled_from(list(string.ascii_lowercase)),
            min_size=4,
            max_size=10,
        ),
    )
    @settings(
        max_examples=200,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_credentials_actually_removed(self, user: str, password: str, host: str):
        """Embedded user:pass@ must not appear in output."""
        url = f"https://{user}:{password}@{host}.com/repo.git"
        result = _strip_url_credentials(url)
        # The credential pair user:pass must be stripped
        assert f"{user}:{password}@" not in result
        # The @ separator with password must be gone
        assert f"{password}@" not in result


# ═══════════════════════════════════════════════════════════════════════
# PROPERTY 14: _strip_terminal_escapes is idempotent
# ═══════════════════════════════════════════════════════════════════════


class TestStripEscapesIdempotent:
    """Stripping escapes twice = stripping once."""

    @given(text=st.text(min_size=0, max_size=500))
    @settings(
        max_examples=500,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
    )
    def test_idempotent(self, text: str):
        """strip(strip(x)) == strip(x)."""
        s1 = _strip_terminal_escapes(text)
        s2 = _strip_terminal_escapes(s1)
        assert s1 == s2


# ═══════════════════════════════════════════════════════════════════════
# PROPERTY 15: Ledger-level policy evaluation (aggregate)
# ═══════════════════════════════════════════════════════════════════════


class TestLedgerPolicyProperties:
    """Ledger-level policy evaluation has consistent behavior."""

    @given(
        ai_pct=st.floats(min_value=0, max_value=100),
        receipt_count=st.integers(min_value=1, max_value=10000),
    )
    @settings(max_examples=200, suppress_health_check=[HealthCheck.differing_executors])
    def test_permissive_never_rejects_on_ai_percent(
        self, ai_pct: float, receipt_count: int
    ):
        """Permissive allows 100% AI, so it should never fail on ai_percent."""
        index = {
            "receipt_count": receipt_count,
            "ai_percentage": ai_pct,
            "ai_commit_count": int(ai_pct * receipt_count / 100),
        }
        permissive = {**POLICY_PRESETS["permissive"], "preset": "permissive"}
        passed, msg, violations = evaluate_ledger_policy(index, permissive)
        # Permissive max_ai_percent is 100.0, so any pct <= 100 passes
        ai_violations = [v for v in violations if v.rule == "max_ai_percent"]
        if ai_pct <= 100.0:
            assert not ai_violations, f"Permissive rejected {ai_pct}%: {msg}"

    @given(
        ai_pct=st.floats(min_value=50.01, max_value=100.0),
        receipt_count=st.integers(min_value=1, max_value=10000),
    )
    @settings(max_examples=200, suppress_health_check=[HealthCheck.differing_executors])
    def test_strict_rejects_over_threshold(self, ai_pct: float, receipt_count: int):
        """Strict (max 50%) must reject > 50%."""
        index = {
            "receipt_count": receipt_count,
            "ai_percentage": ai_pct,
            "ai_commit_count": int(ai_pct * receipt_count / 100),
        }
        strict = {**POLICY_PRESETS["strict"], "preset": "strict"}
        passed, msg, violations = evaluate_ledger_policy(index, strict)
        ai_violations = [v for v in violations if v.rule == "max_ai_percent"]
        assert len(ai_violations) > 0, f"Strict should reject {ai_pct}% AI"
