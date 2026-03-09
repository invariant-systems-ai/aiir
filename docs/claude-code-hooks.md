# Claude Code Hooks → AIIR Receipt

> Auto-generate an AIIR receipt every time Claude Code writes code.
> Uses Claude Code's [hooks system](https://code.claude.com/docs/en/hooks)
> to run `aiir --pretty` after every tool use that modifies files.

## Quick Setup

### 1. Install AIIR

```bash
pip install aiir
```

### 2. Add the hook

Add the following to `.claude/settings.json` in your project root
(or `~/.claude/settings.json` for all projects):

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "cd \"$CLAUDE_PROJECT_DIR\" && git diff --quiet || (git add -A && git commit -m \"claude: auto-commit\" --no-verify && aiir --pretty)"
          }
        ]
      }
    ]
  }
}
```

### What this does

Every time Claude Code uses the `Write` or `Edit` tool:

1. Checks if there are uncommitted changes (`git diff --quiet`)
2. If yes — stages everything, commits with a `claude:` prefix
3. Runs `aiir --pretty` to generate a cryptographic receipt

The receipt is appended to `.aiir/receipts.jsonl` (the default ledger).
Because the commit message starts with `claude:`, AIIR's heuristic
detector will flag it as AI-assisted.

### Example output

```
┌─ Receipt: g1-a3f8b2c1d4e5f6a7b8c9d0e1
│  Commit:  c4dec85630
│  Subject: claude: auto-commit
│  Author:  Jane Dev <jane@example.com>
│  Files:   3 changed
│  AI:      YES (message_match:claude)
│  Hash:    sha256:7f3a...
│  Time:    2026-03-09T14:22:01Z
│  Signed:  none
└──────────────────────────────────────────
```

## Variations

### Signed receipts (recommended for teams)

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "cd \"$CLAUDE_PROJECT_DIR\" && git diff --quiet || (git add -A && git commit -m \"claude: auto-commit\" --no-verify && aiir --sign --output .receipts/)"
          }
        ]
      }
    ]
  }
}
```

Requires `pip install aiir[sign]` and a Sigstore OIDC token (automatic in
most environments).

### With agent attestation

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "cd \"$CLAUDE_PROJECT_DIR\" && git diff --quiet || (git add -A && git commit -m \"claude: auto-commit\" --no-verify && aiir --pretty --agent-tool claude-code --agent-model claude-sonnet --agent-context ide)"
          }
        ]
      }
    ]
  }
}
```

This adds structured metadata to `extensions.agent_attestation`:

```json
{
  "extensions": {
    "agent_attestation": {
      "tool_id": "claude-code",
      "model_class": "claude-sonnet",
      "run_context": "ide",
      "confidence": "declared"
    }
  }
}
```

### In-toto envelope (supply-chain integration)

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "cd \"$CLAUDE_PROJECT_DIR\" && git diff --quiet || (git add -A && git commit -m \"claude: auto-commit\" --no-verify && aiir --in-toto --json > .receipts/latest-intoto.json)"
          }
        ]
      }
    ]
  }
}
```

The output is a standard in-toto Statement v1 envelope that any
SLSA verifier, Sigstore policy-controller, or OPA/Gatekeeper policy
can consume directly.

### AI-only (skip human commits)

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "cd \"$CLAUDE_PROJECT_DIR\" && git diff --quiet || (git add -A && git commit -m \"claude: auto-commit\" --no-verify && aiir --ai-only --pretty)"
          }
        ]
      }
    ]
  }
}
```

### Quiet mode (no terminal output)

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "cd \"$CLAUDE_PROJECT_DIR\" && git diff --quiet || (git add -A && git commit -m \"claude: auto-commit\" --no-verify && aiir --quiet)"
          }
        ]
      }
    ]
  }
}
```

## Combine with MCP

You can also use AIIR as an MCP tool alongside hooks. Add to
`.claude/mcp.json`:

```json
{
  "mcpServers": {
    "aiir": {
      "command": "aiir-mcp-server",
      "args": ["--stdio"]
    }
  }
}
```

Now Claude Code can _also_ call `aiir_receipt` and `aiir_verify`
as tools — useful for verification workflows and on-demand receipting.

## Verify receipts

```bash
# Verify a single receipt
aiir --verify .receipts/receipt_c4dec85630_7f3a1b2c.json

# Verify with human-readable explanation
aiir --verify .receipts/receipt_c4dec85630_7f3a1b2c.json --explain

# Verify all receipts in a directory
for f in .receipts/*.json; do aiir --verify "$f"; done

# Check ledger health
aiir --stats
```

## Policy enforcement

Add a policy to fail CI when too many commits are AI-authored:

```bash
# Initialize strict policy (max 50% AI, signing required)
aiir --policy-init strict

# Check policy against ledger
aiir --check --policy strict
```

---

**Links**: [AIIR on PyPI](https://pypi.org/project/aiir/) ·
[AIIR on GitHub](https://github.com/invariant-systems-ai/aiir) ·
[Claude Code Hooks docs](https://code.claude.com/docs/en/hooks)
