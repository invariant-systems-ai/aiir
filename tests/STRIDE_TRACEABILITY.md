# STRIDE Traceability Matrix

Maps every STRIDE threat from [`THREAT_MODEL.md`](../THREAT_MODEL.md) to the
test classes that exercise the corresponding defence.  Updated whenever new
security tests are added.

> **Notation**: `file.py::ClassName` refers to `tests/<file.py>::<ClassName>`.
> Tests marked ★ use a real GFM parser (markdown-it-py) for differential
> validation.  Tests marked ⚡ use Hypothesis for property-based fuzzing.

---

## Spoofing

| ID | Threat | Test classes |
|----|--------|-------------|
| S-01 | Zero-width Unicode evasion (ZWJ/ZWNJ) | `test_redteam.py::TestRedTeamHardeningR2`, `test_redteam.py::TestRedTeamHardeningR3`, `test_redteam.py::TestRedTeamHardeningR5`, `test_redteam.py::TestHostileAttackR7`, `test_redteam_hostile.py::TestHostileAngle2DetectionEvasion`, `test_redteam_hostile.py::TestHostileCrossAngle`, `test_redteam_hostile.py::TestHostileAngle2NormalizationEdgeCases`, `test_redteam_hostile.py::TestHostileSanitizeMdGfmInjection`, `test_detect.py::TestSignalEvasion`, `test_core.py::TestNormalizeForDetection`, `test_fuzz.py::TestFuzzNormalizeDetection` ⚡, `test_properties.py::TestNormalizationConvergence` ⚡, `test_hardening.py::TestSanitizeMdDifferentialUnicode` ★ |
| S-02 | Homoglyph evasion (Cyrillic/Armenian/fullwidth) | `test_redteam.py::TestHostileAttackR7`, `test_redteam.py::TestHostileIntegrationR7`, `test_redteam_hostile.py::TestHostileAngle2DetectionEvasion`, `test_redteam_hostile.py::TestHostileAngle2NormalizationEdgeCases`, `test_detect.py::TestSignalEvasion`, `test_core.py::TestNormalizeForDetection`, `test_fuzz.py::TestFuzzDetectUnicodeConfusables` ⚡, `test_properties.py::TestNormalizationConvergence` ⚡ |
| S-03 | Stolen OIDC token (Sigstore) | *(Infrastructure-layer threat — mitigated by Sigstore's OIDC verification; no direct unit test possible)* |
| S-04 | Forged receipt with matching content_hash | `test_redteam.py::TestRedTeamHardeningR3`, `test_redteam.py::TestR5ForgeryDefense`, `test_redteam.py::TestTechnicalExpertR7`, `test_redteam.py::TestAcademicPhilosophicalR7`, `test_redteam.py::TestSecurityMaliciousR7`, `test_redteam_hostile.py::TestHostileAngle3VerificationBypass`, `test_redteam_hostile.py::TestHostileAngle6SchemaBypass`, `test_core.py::TestSha256Helpers`, `test_fuzz.py::TestFuzzSchemaValidation` ⚡, `test_properties.py::TestSha256Properties` ⚡ |

## Tampering

| ID | Threat | Test classes |
|----|--------|-------------|
| T-01 | Receipt hash/id tampering | `test_redteam.py::TestRedTeamHardeningR3` … `test_redteam.py::TestIntegrationWithGitR8`, `test_redteam_hostile.py::TestHostileAngle1CanonicalDeterminism`, `test_redteam_hostile.py::TestHostileAngle3VerificationBypass`, `test_redteam_hostile.py::TestHostileAngle4PolicyEscape`, `test_redteam_hostile.py::TestHostileAngle5SupplyChain`, `test_redteam_hostile.py::TestHostileCrossAngle`, `test_redteam_hostile.py::TestHostileAngle6SchemaBypass`, `test_verify.py::TestVerifyReceiptArray`, `test_core.py::TestCanonicalJson`, `test_core.py::TestSha256Helpers`, `test_fuzz.py::TestFuzzCanonicalJson` ⚡, `test_fuzz.py::TestFuzzSchemaValidation` ⚡, `test_properties.py::TestReceiptIdDeterminism` ⚡, `test_properties.py::TestSelfVerification` ⚡, `test_properties.py::TestTamperDetection` ⚡, `test_properties.py::TestSchemaCompliance` ⚡, `test_hardening.py::TestConstantTimeComparisonGuard` |
| T-02 | Timing side-channel on verification | `test_redteam.py::TestRedTeamHardeningR3`, `test_redteam.py::TestRedTeamHardeningR4`, `test_redteam_hostile.py::TestHostileAngle3VerificationBypass`, `test_hardening.py::TestConstantTimeComparisonGuard` |
| T-03 | Path traversal via crafted receipt_id | `test_redteam.py::TestRedTeamHardeningR2`, `test_redteam.py::TestSecurityMaliciousR7`, `test_redteam_hostile.py::TestHostileAngle5SupplyChain`, `test_redteam_hostile.py::TestHostileMcpProtocolAttacks`, `test_verify.py::TestVerifyIntegration`, `test_core.py::TestPathTraversalGuards` |
| T-04 | GITHUB_OUTPUT injection via crafted key/value | `test_redteam.py::TestRedTeamHardeningR3`, `test_redteam.py::TestRedTeamHardeningR5`, `test_redteam.py::TestSecurityMaliciousR7`, `test_redteam_hostile.py::TestHostileAngle5SupplyChain`, `test_core.py::TestGithubOutputSafety`, `test_fuzz.py::TestFuzzGithubOutput` ⚡ |
| T-05 | Symlink attack on receipt files | `test_redteam.py::TestRedTeamHardeningR4`, `test_redteam.py::TestRedTeamHardeningR5`, `test_redteam.py::TestSecurityMaliciousR7`, `test_redteam_hostile.py::TestHostileAngle5SupplyChain`, `test_verify.py::TestVerifyFileEdgeCases`, `test_fuzz.py::TestFuzzVerifyReceiptFile` ⚡ |
| T-06 | Git command injection | `test_redteam.py::TestRedTeamHardeningR4`, `test_redteam.py::TestRedTeamIntegrationR4` |

## Repudiation

| ID | Threat | Test classes |
|----|--------|-------------|
| R-01 | Developer denies AI tool usage | `test_redteam.py::TestHostileAttackR7`, `test_redteam.py::TestHostileIntegrationR7`, `test_redteam.py::TestAcademicPhilosophicalR7`, `test_redteam.py::TestIntegrationWithGitR7`, `test_redteam.py::TestIntegrationWithGitR8`, `test_redteam_hostile.py::TestHostileAngle2DetectionEvasion`, `test_redteam_hostile.py::TestHostileAngle4PolicyEscape`, `test_redteam_hostile.py::TestHostileCrossAngle`, `test_detect.py::TestDetectAISignals`, `test_detect.py::TestSignalEvasion`, `test_detect.py::TestAIToolCoverage`, `test_detect.py::TestBotDetection`, `test_detect.py::TestAISignalsList`, `test_fuzz.py::TestFuzzDetectAISignals` ⚡, `test_properties.py::TestDetectionClassification` ⚡, `test_properties.py::TestPolicyProperties` ⚡ |
| R-02 | Developer claims receipt fabricated | `test_redteam.py::TestAcademicPhilosophicalR8`, `test_properties.py::TestReceiptIdDeterminism` ⚡ |
| R-03 | Unsigned receipts — fabrication risk | `test_redteam.py::TestAcademicPhilosophicalR8` |

## Information Disclosure

| ID | Threat | Test classes |
|----|--------|-------------|
| I-01 | Git stderr leaks paths/URLs | `test_redteam.py::TestRedTeamHardeningR5`, `test_redteam.py::TestSecurityMaliciousR7`, `test_redteam.py::TestSecurityMaliciousR8`, `test_verify.py::TestVerifyReceiptSignatureRedaction`, `test_core.py::TestRunGitDefensive` |
| I-02 | URL credential leaks in receipts | `test_redteam.py::TestRedTeamHardeningR2`, `test_redteam.py::TestRedTeamHardeningR3`, `test_redteam.py::TestRedTeamIntegrationWithGit`, `test_redteam.py::TestRedTeamIntegration`, `test_fuzz.py::TestFuzzStripUrlCredentials` ⚡, `test_properties.py::TestUrlSanitization` ⚡ |
| I-03 | Trailer value leakage | `test_detect.py::TestDetectAISignals`, `test_detect.py::TestDetectMutationKilling` |
| I-04 | Sigstore error information disclosure | `test_redteam.py::TestRedTeamHardeningR4`, `test_redteam.py::TestSecurityMaliciousR7`, `test_redteam.py::TestSecurityMaliciousR8`, `test_redteam_hostile.py::TestHostileAngle3VerificationBypass`, `test_verify.py::TestVerifyReceiptSignatureRedaction` |
| I-05 | Summary output injection | `test_redteam.py::TestIntegrationWithGitR7`, `test_redteam_hostile.py::TestHostileAngle6SchemaBypass`, `test_hardening.py::TestSanitizeMdDifferentialLinks` ★ |

## Denial of Service

| ID | Threat | Test classes |
|----|--------|-------------|
| D-01 | Unbounded commit loop | `test_redteam.py::TestRedTeamHardeningR3`, `test_redteam.py::TestListCommitsLimits`, `test_redteam.py::TestSecurityMaliciousR8`, `test_redteam.py::TestIntegrationWithGitR8`, `test_redteam_hostile.py::TestHostileAngle5SupplyChain` |
| D-02 | Enormous diff (multi-GB) | `test_redteam.py::TestRedTeamHardeningR2`, `test_redteam.py::TestRedTeamIntegrationWithGit`, `test_redteam.py::TestHostileIntegrationR7`, `test_redteam.py::TestIntegrationWithGitR7`, `test_core.py::TestHashDiffStreamingCleanup`, `test_core.py::TestHashDiffStreamingKill`, `test_core.py::TestHashDiffStreamingKillReturn` |
| D-03 | Git subprocess hangs | `test_redteam.py::TestRedTeamHardeningR5`, `test_redteam_hostile.py::TestHostileAngle5SupplyChain`, `test_core.py::TestHashDiffStreamingCleanup`, `test_core.py::TestHashDiffStreamingKill`, `test_core.py::TestHashDiffStreamingKillReturn` |
| D-04 | Multi-GB JSON receipt file | `test_redteam.py::TestRedTeamHardeningR4`, `test_redteam.py::TestRedTeamHardeningR5`, `test_redteam_hostile.py::TestHostileAngle5SupplyChain`, `test_verify.py::TestVerifyFileEdgeCases`, `test_fuzz.py::TestFuzzVerifyReceiptFile` ⚡ |
| D-05 | Receipt array — quadratic CPU | `test_redteam.py::TestRedTeamHardeningR4`, `test_redteam.py::TestIntegrationWithGitR7`, `test_redteam_hostile.py::TestHostileAngle6SchemaBypass`, `test_verify.py::TestVerifyReceiptArray` |
| D-06 | Overlong ref string | `test_redteam.py::TestRedTeamHardeningR2`, `test_redteam.py::TestRedTeamHardeningR3`, `test_redteam_hostile.py::TestHostileMcpProtocolAttacks`, `test_core.py::TestValidateRef`, `test_fuzz.py::TestFuzzValidateRef` ⚡ |
| D-07 | Deep JSON nesting | `test_redteam_hostile.py::TestHostileAngle1CanonicalDeterminism`, `test_verify.py::TestDeepNestingVerify`, `test_fuzz.py::TestFuzzCanonicalJson` ⚡ |

## Elevation of Privilege

| ID | Threat | Test classes |
|----|--------|-------------|
| E-01 | Git argument injection via ref | `test_redteam.py::TestRedTeamHardeningR2`, `test_redteam.py::TestRedTeamHardeningR3`, `test_redteam.py::TestHostileAttackR7`, `test_core.py::TestValidateRef`, `test_core.py::TestRunGitDefensive`, `test_core.py::TestShaValidation`, `test_fuzz.py::TestFuzzValidateRef` ⚡ |
| E-02 | Shell injection via COMMIT_RANGE | `test_redteam.py::TestSecurityMaliciousR8` |
| E-03 | Workflow output injection via newline | `test_redteam.py::TestRedTeamHardeningR3`, `test_redteam.py::TestRedTeamHardeningR5`, `test_redteam.py::TestRedTeamIntegrationR5`, `test_redteam.py::TestSecurityMaliciousR7`, `test_redteam_hostile.py::TestHostileAngle5SupplyChain`, `test_core.py::TestGithubOutputSafety`, `test_fuzz.py::TestFuzzGithubOutput` ⚡ |
| E-04 | XSS via commit subject in GFM summary | `test_redteam.py::TestRedTeamHardeningR3`, `test_redteam.py::TestHostileAttackR7`, `test_redteam.py::TestR5BacktickBreakout`, `test_redteam.py::TestSecurityMaliciousR8`, `test_redteam.py::TestIntegrationWithGitR8`, `test_redteam_hostile.py::TestHostileSanitizeMdGfmInjection`, `test_core.py::TestSanitizeMd`, `test_core.py::TestSanitizeMdBackslash`, `test_core.py::TestSanitizeMdAutolink`, `test_core.py::TestSanitizeMdAmpersand`, `test_core.py::TestSanitizeMdEmphasis`, `test_core.py::TestSanitizeMdNonDictFields`, `test_fuzz.py::TestFuzzSanitizeMd` ⚡, `test_fuzz.py::TestFuzzRegressionTargets` ⚡, `test_fuzz.py::TestFuzzGithubSummary` ⚡, `test_fuzz.py::TestFuzzSanitizeMdEmphasis` ⚡, `test_fuzz.py::TestFuzzSanitizeMdBackslashPipe` ⚡, `test_hardening.py::TestSanitizeMdDifferentialHTML` ★, `test_hardening.py::TestSanitizeMdDifferentialTable` ★, `test_hardening.py::TestSanitizeMdDifferentialEmphasis` ★, `test_hardening.py::TestSanitizeMdDifferentialComposed` ★ |
| E-05 | Terminal escape injection | `test_redteam.py::TestRedTeamHardeningR5`, `test_redteam.py::TestHostileAttackR7`, `test_redteam.py::TestSecurityMaliciousR7`, `test_redteam.py::TestTechnicalExpertR8`, `test_redteam.py::TestIntegrationWithGitR8`, `test_redteam_hostile.py::TestHostileAngle3VerificationBypass`, `test_redteam_hostile.py::TestHostileAngle5SupplyChain`, `test_redteam_hostile.py::TestHostileCrossAngle`, `test_redteam_hostile.py::TestHostileTerminalInjection`, `test_core.py::TestStripTerminalEscapes`, `test_core.py::TestStripC1Controls`, `test_core.py::TestFormatPrettySignals`, `test_core.py::TestFormatPrettyAuthor`, `test_core.py::TestFormatPrettyNonDict`, `test_fuzz.py::TestFuzzStripTerminalEscapes` ⚡, `test_fuzz.py::TestFuzzRegressionTargets` ⚡, `test_fuzz.py::TestFuzzPmApcStripping` ⚡, `test_fuzz.py::TestFuzzFormatPrettyNonDict` ⚡, `test_fuzz.py::TestFuzzFormatPrettyBot` ⚡, `test_properties.py::TestSanitizeMdIdempotent` ⚡, `test_properties.py::TestReceiptDetailRobustness` ⚡, `test_properties.py::TestStripTerminalEscapesIdempotent` ⚡ |
| E-06 | Path traversal in MCP/ledger | `test_redteam.py::TestRedTeamHardeningR2`, `test_redteam.py::TestRedTeamHardeningR3`, `test_redteam.py::TestSecurityMaliciousR7`, `test_redteam_hostile.py::TestHostileAngle5SupplyChain`, `test_redteam_hostile.py::TestHostileMcpProtocolAttacks`, `test_verify.py::TestVerifyIntegration`, `test_verify.py::TestVerifyFileEdgeCases`, `test_core.py::TestPathTraversalGuards` |

---

## Coverage Summary

| STRIDE category | IDs covered | IDs total | Coverage |
|----------------|-------------|-----------|----------|
| Spoofing       | 3/4         | 4         | 75% (S-03 is infrastructure-layer) |
| Tampering      | 6/6         | 6         | 100% |
| Repudiation    | 3/3         | 3         | 100% |
| Info Disclosure| 5/5         | 5         | 100% |
| DoS            | 7/7         | 7         | 100% |
| EoP            | 6/6         | 6         | 100% |
| **Total**      | **30/31**   | **31**    | **96.8%** |

> S-03 (stolen Sigstore OIDC token) is mitigated by Sigstore's OIDC provider
> infrastructure and cannot be meaningfully unit-tested.  See THREAT_MODEL.md
> for the mitigation details.

---

*Generated from test suite analysis on 2026-03-09.  Verify with:*

```bash
grep -rn "Covers:" tests/ | sort
```
