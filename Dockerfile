# AIIR — AI Integrity Receipts
# https://github.com/invariant-systems-ai/aiir
#
# Minimal container image for running AIIR in any CI/CD environment.
# Zero dependencies. Python standard library only.
#
# Usage:
#   docker run --rm -v $(pwd):/repo -w /repo invariantsystems/aiir --pretty
#   docker run --rm -v $(pwd):/repo -w /repo invariantsystems/aiir --range main..HEAD --output .receipts/
#
# Build (source — self-healing, always matches checked-out code):
#   docker build -t invariantsystems/aiir .
#
# Build (pinned PyPI version — deterministic, used by publish.yml):
#   docker build --build-arg AIIR_VERSION=1.0.15 -t invariantsystems/aiir:1.0.15 .

FROM python:3.11-slim@sha256:d6e4d224f70f9e0172a06a3a2eba2f768eb146811a349278b38fff3a36463b47 AS base

# Security: non-root user
RUN groupadd --gid 1000 aiir && \
    useradd --uid 1000 --gid aiir --shell /bin/bash --create-home aiir

# Copy source (needed for local/source builds; harmless for PyPI builds).
# .dockerignore whitelists only aiir/, pyproject.toml, LICENSE, README, CHANGELOG.
COPY . /src/

# Install AIIR:
#   • AIIR_VERSION set  → install pinned version from PyPI  (publish.yml)
#   • AIIR_VERSION empty → install from local source         (self-healing)
ARG AIIR_VERSION=""
RUN if [ -n "$AIIR_VERSION" ]; then \
      pip install --no-cache-dir "aiir==${AIIR_VERSION}"; \
    else \
      pip install --no-cache-dir /src; \
    fi && \
    aiir --version && \
    rm -rf /src

# Git is required for commit scanning
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Mark /repo as safe for git
RUN git config --global --add safe.directory /repo

USER aiir
WORKDIR /repo

ENTRYPOINT ["aiir"]
CMD ["--pretty"]

# Labels for container registries
LABEL org.opencontainers.image.title="AIIR — AI Integrity Receipts"
LABEL org.opencontainers.image.description="Tamper-evident cryptographic receipts for AI-generated code commits"
LABEL org.opencontainers.image.url="https://invariantsystems.io"
LABEL org.opencontainers.image.source="https://github.com/invariant-systems-ai/aiir"
LABEL org.opencontainers.image.documentation="https://github.com/invariant-systems-ai/aiir#readme"
LABEL org.opencontainers.image.vendor="Invariant Systems, Inc."
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.version="${AIIR_VERSION}"
