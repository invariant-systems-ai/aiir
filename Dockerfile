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
# Build:
#   docker build -t invariantsystems/aiir .
#   docker build -t invariantsystems/aiir:1.0.9 --build-arg AIIR_VERSION=1.0.9 .

FROM python:3.11-slim AS base

# Security: non-root user
RUN groupadd --gid 1000 aiir && \
    useradd --uid 1000 --gid aiir --shell /bin/bash --create-home aiir

# Install AIIR from PyPI (zero dependencies, tiny layer)
# Default kept in sync with latest release; publish.yml overrides via --build-arg.
ARG AIIR_VERSION=1.0.9
RUN pip install --no-cache-dir "aiir==${AIIR_VERSION}" && \
    aiir --version

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
