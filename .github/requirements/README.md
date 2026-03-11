# CI Requirements (hash-locked)

These files contain hash-pinned dependencies for CI workflows,
required by OpenSSF Scorecard's Pinned-Dependencies check.

## Regenerating

```bash
# From the repo root:
for f in .github/requirements/*.in; do
  pip-compile --generate-hashes --strip-extras \
    --output-file="${f%.in}.txt" "$f"
done
```

Each `.in` file declares direct dependencies; the corresponding `.txt`
file is the fully-resolved, hash-locked output.
