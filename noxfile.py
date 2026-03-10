"""Nox sessions for AIIR — local multi-version testing.

Run ``nox`` to execute the default sessions (lint + test across Python versions).
Run ``nox -s typecheck`` for mypy only, or ``nox -l`` to list all sessions.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import nox

# Default Python versions matching the CI matrix (ci.yml).
PYTHON_VERSIONS = ["3.9", "3.10", "3.11", "3.12", "3.13"]

nox.options.sessions = ["lint", "test"]
nox.options.reuse_existing_virtualenvs = True


@nox.session(python=PYTHON_VERSIONS)
def test(session: nox.Session) -> None:
    """Run the test suite (excluding fuzz tests)."""
    session.install("pytest")
    session.run(
        "python",
        "-m",
        "pytest",
        "tests/",
        "-v",
        "--tb=short",
        "--ignore=tests/test_fuzz.py",
        *session.posargs,
    )


@nox.session(python="3.12")
def fuzz(session: nox.Session) -> None:
    """Run Hypothesis property-based fuzz tests."""
    session.install("pytest", "hypothesis")
    session.run(
        "python",
        "-m",
        "pytest",
        "tests/test_fuzz.py",
        "tests/test_properties.py",
        "-v",
        "--tb=short",
    )


@nox.session(python="3.12")
def lint(session: nox.Session) -> None:
    """Run Ruff lint + format check."""
    session.install("ruff==0.14.10")
    session.run("ruff", "check", "aiir/", "tests/", "scripts/")
    session.run("ruff", "format", "--check", "aiir/", "tests/", "scripts/")


@nox.session(python="3.12")
def typecheck(session: nox.Session) -> None:
    """Run mypy static type checking."""
    session.install("mypy>=1.10,<2", "pytest", "hypothesis")
    session.run("mypy", "aiir/")


@nox.session(python="3.12")
def coverage(session: nox.Session) -> None:
    """Run tests with coverage and enforce 100% line coverage."""
    session.install("pytest", "coverage")
    session.run(
        "coverage",
        "run",
        "--source=aiir",
        "-m",
        "pytest",
        "tests/",
        "--ignore=tests/test_fuzz.py",
        "-q",
        "--tb=short",
    )
    session.run("coverage", "report", "--show-missing")
    session.run("coverage", "report", "--fail-under=100")


@nox.session(python="3.12")
def benchmark(session: nox.Session) -> None:
    """Run performance benchmarks."""
    session.install("pytest", "pytest-benchmark")
    session.run(
        "python",
        "-m",
        "pytest",
        "tests/test_benchmark.py",
        "-v",
        "--benchmark-only",
        *session.posargs,
    )


@nox.session(python="3.12")
def security(session: nox.Session) -> None:
    """Run Bandit SAST scan."""
    session.install("bandit[toml]")
    session.run("bandit", "-r", "aiir/", "-ll")
