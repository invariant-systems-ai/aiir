"""Tests for sigstore signing and verification."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

# Import the module under test
import aiir.cli as cli


class TestSigstoreAvailability(unittest.TestCase):
    """Tests for _sigstore_available() and graceful degradation."""

    def test_sigstore_available_when_installed(self):
        """_sigstore_available() returns True when sigstore is importable."""
        # Use a mock that makes the import succeed
        import types

        fake_sigstore = types.ModuleType("sigstore")
        with patch.dict("sys.modules", {"sigstore": fake_sigstore}):
            self.assertTrue(cli._sigstore_available())

    def test_sigstore_not_available_when_missing(self):
        """_sigstore_available() returns False when sigstore is not installed."""
        with patch.dict("sys.modules", {"sigstore": None}):
            self.assertFalse(cli._sigstore_available())

    def test_sign_receipt_raises_without_sigstore(self):
        """sign_receipt() raises RuntimeError with helpful message when sigstore missing."""
        with patch.dict("sys.modules", {
            "sigstore": None,
            "sigstore.models": None,
            "sigstore.oidc": None,
            "sigstore.sign": None,
        }):
            with self.assertRaises(RuntimeError) as ctx:
                cli.sign_receipt(b'{"test": true}')
            self.assertIn("pip install sigstore", str(ctx.exception))

    def test_verify_signature_raises_without_sigstore(self):
        """verify_receipt_signature() raises RuntimeError when sigstore missing."""
        with patch.dict("sys.modules", {
            "sigstore": None,
            "sigstore.models": None,
            "sigstore.verify": None,
            "sigstore.verify.policy": None,
        }):
            import tempfile
            # Use real files so we reach the sigstore import check
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as rf:
                rf.write("{}")
                rpath = rf.name
            bpath = rpath + ".sigstore"
            with open(bpath, "w") as bf:
                bf.write("{}")
            try:
                with self.assertRaises(RuntimeError) as ctx:
                    cli.verify_receipt_signature(rpath, bpath)
                self.assertIn("pip install sigstore", str(ctx.exception))
            finally:
                os.unlink(rpath)
                os.unlink(bpath)


class TestSigstoreSigning(unittest.TestCase):
    """Tests for sign_receipt() and sign_receipt_file() with mocked sigstore."""

    def test_sign_receipt_returns_bundle_json(self):
        """sign_receipt() calls sigstore API and returns bundle JSON."""
        fake_bundle_json = '{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3"}'

        mock_bundle = unittest.mock.MagicMock()
        mock_bundle.to_json.return_value = fake_bundle_json

        mock_signer = unittest.mock.MagicMock()
        mock_signer.__enter__ = unittest.mock.MagicMock(return_value=mock_signer)
        mock_signer.__exit__ = unittest.mock.MagicMock(return_value=False)
        mock_signer.sign_artifact.return_value = mock_bundle

        mock_ctx = unittest.mock.MagicMock()
        mock_ctx.signer.return_value = mock_signer

        mock_identity_token = unittest.mock.MagicMock()

        with patch.dict("sys.modules", {}):  # Clear cache
            with patch("aiir.cli.sign_receipt.__module__", "cli"):
                # Patch at the function level using a wrapper
                from unittest.mock import MagicMock
                import types

                # Create mock modules
                mock_sigstore_sign = types.ModuleType("sigstore.sign")
                mock_sigstore_sign.SigningContext = MagicMock()
                mock_sigstore_sign.SigningContext.from_trust_config.return_value = mock_ctx

                mock_sigstore_models = types.ModuleType("sigstore.models")
                mock_sigstore_models.ClientTrustConfig = MagicMock()
                mock_sigstore_models.ClientTrustConfig.production.return_value = MagicMock()

                mock_sigstore_oidc = types.ModuleType("sigstore.oidc")
                mock_sigstore_oidc.detect_credential = MagicMock(return_value="fake-token")
                mock_sigstore_oidc.IdentityToken = MagicMock(return_value=mock_identity_token)
                mock_sigstore_oidc.Issuer = MagicMock()

                with patch.dict("sys.modules", {
                    "sigstore": types.ModuleType("sigstore"),
                    "sigstore.sign": mock_sigstore_sign,
                    "sigstore.models": mock_sigstore_models,
                    "sigstore.oidc": mock_sigstore_oidc,
                }):
                    result = cli.sign_receipt(b'{"test": true}')
                    self.assertEqual(result, fake_bundle_json)
                    mock_signer.sign_artifact.assert_called_once_with(b'{"test": true}')

    def test_sign_receipt_file_writes_bundle(self):
        """sign_receipt_file() writes .sigstore bundle next to receipt."""
        fake_bundle = '{"mediaType": "test-bundle"}'

        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_path = os.path.join(tmpdir, "receipt_test.json")
            Path(receipt_path).write_text('{"type": "test"}', encoding="utf-8")

            with patch("aiir._sign.sign_receipt", return_value=fake_bundle):
                bundle_path = cli.sign_receipt_file(receipt_path)

            self.assertEqual(bundle_path, receipt_path + ".sigstore")
            self.assertTrue(Path(bundle_path).exists())
            self.assertEqual(
                Path(bundle_path).read_text(encoding="utf-8"),
                fake_bundle,
            )

    def test_sign_receipt_file_not_found(self):
        """sign_receipt_file() raises FileNotFoundError for missing files."""
        with self.assertRaises(FileNotFoundError):
            cli.sign_receipt_file("/tmp/nonexistent_receipt_xyz.json")


class TestSigstoreVerification(unittest.TestCase):
    """Tests for verify_receipt_signature() with mocked sigstore."""

    def test_verify_missing_receipt(self):
        """verify_receipt_signature() returns error for missing receipt file."""
        # Need sigstore modules available for the function to proceed past import
        import types

        mock_sigstore = types.ModuleType("sigstore")
        mock_verify = types.ModuleType("sigstore.verify")
        mock_verify.Verifier = unittest.mock.MagicMock()
        mock_policy = types.ModuleType("sigstore.verify.policy")
        mock_policy.UnsafeNoOp = unittest.mock.MagicMock()
        mock_policy.Identity = unittest.mock.MagicMock()
        mock_models = types.ModuleType("sigstore.models")
        mock_models.Bundle = unittest.mock.MagicMock()

        with patch.dict("sys.modules", {
            "sigstore": mock_sigstore,
            "sigstore.verify": mock_verify,
            "sigstore.verify.policy": mock_policy,
            "sigstore.models": mock_models,
        }):
            result = cli.verify_receipt_signature("/tmp/no_such_receipt_xyz.json")
        self.assertFalse(result["valid"])
        self.assertIn("not found", result["error"])

    def test_verify_missing_bundle(self):
        """verify_receipt_signature() returns error when .sigstore bundle missing."""
        import types

        mock_sigstore = types.ModuleType("sigstore")
        mock_verify = types.ModuleType("sigstore.verify")
        mock_verify.Verifier = unittest.mock.MagicMock()
        mock_policy = types.ModuleType("sigstore.verify.policy")
        mock_policy.UnsafeNoOp = unittest.mock.MagicMock()
        mock_policy.Identity = unittest.mock.MagicMock()
        mock_models = types.ModuleType("sigstore.models")
        mock_models.Bundle = unittest.mock.MagicMock()

        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_path = os.path.join(tmpdir, "receipt.json")
            Path(receipt_path).write_text("{}", encoding="utf-8")

            with patch.dict("sys.modules", {
                "sigstore": mock_sigstore,
                "sigstore.verify": mock_verify,
                "sigstore.verify.policy": mock_policy,
                "sigstore.models": mock_models,
            }):
                result = cli.verify_receipt_signature(receipt_path)
            self.assertFalse(result["valid"])
            self.assertIn("bundle not found", result["error"].lower())

    def test_verify_successful_signature(self):
        """verify_receipt_signature() returns valid=True when verification passes."""
        import types

        mock_verifier = unittest.mock.MagicMock()
        mock_verifier.verify_artifact.return_value = None  # No exception = success

        mock_sigstore = types.ModuleType("sigstore")
        mock_verify_mod = types.ModuleType("sigstore.verify")
        mock_verify_mod.Verifier = unittest.mock.MagicMock()
        mock_verify_mod.Verifier.production.return_value = mock_verifier
        mock_policy = types.ModuleType("sigstore.verify.policy")
        mock_policy.UnsafeNoOp = unittest.mock.MagicMock()
        mock_policy.Identity = unittest.mock.MagicMock()
        mock_models = types.ModuleType("sigstore.models")
        mock_models.Bundle = unittest.mock.MagicMock()

        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_path = os.path.join(tmpdir, "receipt.json")
            bundle_path = receipt_path + ".sigstore"
            Path(receipt_path).write_text('{"type":"test"}', encoding="utf-8")
            Path(bundle_path).write_text('{"mediaType":"bundle"}', encoding="utf-8")

            with patch.dict("sys.modules", {
                "sigstore": mock_sigstore,
                "sigstore.verify": mock_verify_mod,
                "sigstore.verify.policy": mock_policy,
                "sigstore.models": mock_models,
            }):
                result = cli.verify_receipt_signature(receipt_path)
            self.assertTrue(result["valid"])
            self.assertTrue(result["signature_valid"])
            self.assertEqual(result["policy"], "any")


class TestSignCLIFlags(unittest.TestCase):
    """Tests for --sign and --verify-signature CLI flag parsing."""

    def test_sign_without_output_fails(self):
        """--sign without --output should exit with error."""
        with patch("aiir.cli.get_repo_root", return_value="/tmp"):
            with patch("aiir.cli.generate_receipt", return_value={"type": "test"}):
                with patch("aiir.cli._sigstore_available", return_value=True):
                    ret = cli.main(["--commit", "HEAD", "--sign"])
        self.assertEqual(ret, 1)

    def test_sign_without_sigstore_fails(self):
        """--sign when sigstore not installed should exit with error."""
        with patch("aiir.cli.get_repo_root", return_value="/tmp"):
            with patch("aiir.cli.generate_receipt", return_value={"type": "test"}):
                with patch("aiir.cli._sigstore_available", return_value=False):
                    ret = cli.main(["--commit", "HEAD", "--sign", "--output", "/tmp/out"])
        self.assertEqual(ret, 1)

    def test_verify_signature_flag_parsed(self):
        """--verify-signature flag is correctly parsed by argparse."""
        with patch("aiir.cli.verify_receipt_file") as mock_verify:
            mock_verify.return_value = {"valid": True, "receipt_id": "g1-abc", "commit_sha": "abc123"}
            with patch("aiir.cli.verify_receipt_signature") as mock_sig:
                mock_sig.return_value = {"valid": True, "signature_valid": True, "policy": "any"}
                ret = cli.main(["--verify", "/dev/null", "--verify-signature"])
        # verify_receipt_file was called
        mock_verify.assert_called_once()
        # verify_receipt_signature was also called
        mock_sig.assert_called_once()

    def test_verify_with_identity_pinning(self):
        """--signer-identity and --signer-issuer are passed through to verification."""
        with patch("aiir.cli.verify_receipt_file") as mock_verify:
            mock_verify.return_value = {"valid": True, "receipt_id": "g1-abc", "commit_sha": "abc123"}
            with patch("aiir.cli.verify_receipt_signature") as mock_sig:
                mock_sig.return_value = {"valid": True, "signature_valid": True, "policy": "identity"}
                ret = cli.main([
                    "--verify", "/dev/null",
                    "--verify-signature",
                    "--signer-identity", "user@example.com",
                    "--signer-issuer", "https://accounts.google.com",
                ])
        mock_sig.assert_called_once_with(
            "/dev/null",
            expected_identity="user@example.com",
            expected_issuer="https://accounts.google.com",
        )

    def test_verify_signature_failure_returns_nonzero(self):
        """Failed signature verification returns exit code 1."""
        with patch("aiir.cli.verify_receipt_file") as mock_verify:
            mock_verify.return_value = {"valid": True, "receipt_id": "g1-abc", "commit_sha": "abc123"}
            with patch("aiir.cli.verify_receipt_signature") as mock_sig:
                mock_sig.return_value = {"valid": False, "signature_valid": False, "error": "bad sig"}
                ret = cli.main(["--verify", "/dev/null", "--verify-signature"])
        self.assertEqual(ret, 1)


class TestSignCIDetection(unittest.TestCase):
    """Tests for CI environment detection when ambient OIDC credential is missing."""

    def test_sign_in_github_actions_no_oidc_raises_clear_error(self):
        """sign_receipt() in GitHub Actions without OIDC gives a targeted error."""
        import types

        mock_sigstore_sign = types.ModuleType("sigstore.sign")
        mock_sigstore_sign.SigningContext = unittest.mock.MagicMock()

        mock_sigstore_models = types.ModuleType("sigstore.models")
        mock_sigstore_models.ClientTrustConfig = unittest.mock.MagicMock()

        mock_sigstore_oidc = types.ModuleType("sigstore.oidc")
        mock_sigstore_oidc.detect_credential = unittest.mock.MagicMock(return_value=None)
        mock_sigstore_oidc.IdentityToken = unittest.mock.MagicMock()
        mock_sigstore_oidc.Issuer = unittest.mock.MagicMock()

        with patch.dict("sys.modules", {
            "sigstore": types.ModuleType("sigstore"),
            "sigstore.sign": mock_sigstore_sign,
            "sigstore.models": mock_sigstore_models,
            "sigstore.oidc": mock_sigstore_oidc,
        }):
            with patch.dict("os.environ", {"GITHUB_ACTIONS": "true", "CI": "true"}, clear=False):
                with self.assertRaises(RuntimeError) as ctx:
                    cli.sign_receipt(b'{"test": true}')
                self.assertIn("id-token: write", str(ctx.exception))
                self.assertIn("no ambient OIDC credential", str(ctx.exception))

    def test_sign_in_github_actions_fork_pr_mentions_fork(self):
        """sign_receipt() on a fork PR mentions fork limitation in error."""
        import types

        mock_sigstore_sign = types.ModuleType("sigstore.sign")
        mock_sigstore_sign.SigningContext = unittest.mock.MagicMock()

        mock_sigstore_models = types.ModuleType("sigstore.models")
        mock_sigstore_models.ClientTrustConfig = unittest.mock.MagicMock()

        mock_sigstore_oidc = types.ModuleType("sigstore.oidc")
        mock_sigstore_oidc.detect_credential = unittest.mock.MagicMock(return_value=None)
        mock_sigstore_oidc.IdentityToken = unittest.mock.MagicMock()
        mock_sigstore_oidc.Issuer = unittest.mock.MagicMock()

        with patch.dict("sys.modules", {
            "sigstore": types.ModuleType("sigstore"),
            "sigstore.sign": mock_sigstore_sign,
            "sigstore.models": mock_sigstore_models,
            "sigstore.oidc": mock_sigstore_oidc,
        }):
            with patch.dict("os.environ", {
                "GITHUB_ACTIONS": "true",
                "CI": "true",
                "GITHUB_EVENT_NAME": "pull_request",
            }, clear=False):
                with self.assertRaises(RuntimeError) as ctx:
                    cli.sign_receipt(b'{"test": true}')
                self.assertIn("Fork PRs", str(ctx.exception))

    def test_sign_in_generic_ci_no_oidc_raises_clear_error(self):
        """sign_receipt() in generic CI without OIDC gives a clear error."""
        import types

        mock_sigstore_sign = types.ModuleType("sigstore.sign")
        mock_sigstore_sign.SigningContext = unittest.mock.MagicMock()

        mock_sigstore_models = types.ModuleType("sigstore.models")
        mock_sigstore_models.ClientTrustConfig = unittest.mock.MagicMock()

        mock_sigstore_oidc = types.ModuleType("sigstore.oidc")
        mock_sigstore_oidc.detect_credential = unittest.mock.MagicMock(return_value=None)
        mock_sigstore_oidc.IdentityToken = unittest.mock.MagicMock()
        mock_sigstore_oidc.Issuer = unittest.mock.MagicMock()

        with patch.dict("sys.modules", {
            "sigstore": types.ModuleType("sigstore"),
            "sigstore.sign": mock_sigstore_sign,
            "sigstore.models": mock_sigstore_models,
            "sigstore.oidc": mock_sigstore_oidc,
        }):
            with patch.dict("os.environ", {"CI": "true"}, clear=False):
                # Remove GitHub-specific env vars
                with patch.dict("os.environ", {
                    "GITHUB_ACTIONS": "",
                    "GITLAB_CI": "",
                }, clear=False):
                    env_backup = os.environ.copy()
                    os.environ.pop("GITHUB_ACTIONS", None)
                    os.environ.pop("GITLAB_CI", None)
                    try:
                        with self.assertRaises(RuntimeError) as ctx:
                            cli.sign_receipt(b'{"test": true}')
                        self.assertIn("no ambient OIDC credential", str(ctx.exception))
                        self.assertIn("sign: false", str(ctx.exception))
                        self.assertIn("SIGSTORE_ID_TOKEN", str(ctx.exception))
                    finally:
                        os.environ.update(env_backup)


# ---------------------------------------------------------------------------
# Round 4 red-team hardening tests (R4-XX)
# ---------------------------------------------------------------------------

