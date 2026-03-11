"""Shared fixtures for AIIR CLI tests."""
# Copyright 2025-2026 Invariant Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

import os

try:
    from hypothesis import settings, HealthCheck

    # CI profile: cap examples so fuzz tests finish in ~60 s on shared runners.
    # Activate with  HYPOTHESIS_PROFILE=ci  (set in .gitlab-ci.yml).
    settings.register_profile(
        "ci",
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.differing_executors],
        deadline=None,
        database=None,  # no .hypothesis dir in CI
    )

    # Full local profile (default) — uses per-test @settings as-is.
    # HealthCheck.differing_executors is suppressed so tools like mutmut that
    # use a trampolining executor do not produce spurious health-check failures.
    settings.register_profile(
        "default",
        suppress_health_check=[HealthCheck.differing_executors],
        database=None,
    )

    # Auto-select profile from env
    profile = os.environ.get("HYPOTHESIS_PROFILE", "default")
    settings.load_profile(profile)
except ImportError:
    pass  # hypothesis not installed — skip profile setup
