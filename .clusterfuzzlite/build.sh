#!/bin/bash -eu
# Build script for ClusterFuzzLite / OSS-Fuzz.
# Installs the project and compiles Atheris-based fuzz targets.

pip3 install .

# Compile each fuzz target in .clusterfuzzlite/
for fuzzer in /src/aiir/.clusterfuzzlite/fuzz_*.py; do
  compile_python_fuzzer "$fuzzer"
done
