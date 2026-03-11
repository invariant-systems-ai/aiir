#!/bin/bash -eu
# Build script for ClusterFuzzLite / OSS-Fuzz.
# Compiles Atheris-based fuzz targets against source tree without networked
# package resolution.

export PYTHONPATH="/src/aiir:${PYTHONPATH:-}"

# Compile each fuzz target in .clusterfuzzlite/
for fuzzer in /src/aiir/.clusterfuzzlite/fuzz_*.py; do
  compile_python_fuzzer "$fuzzer"
done
