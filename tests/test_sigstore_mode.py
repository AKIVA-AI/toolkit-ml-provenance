"""Sigstore keyless mode for sign-file / verify-file.

The online tests verify real Sigstore bundles from sigstore-python's own test
assets (``tests/fixtures/sigstore``, see its README). They need network access
to the Sigstore TUF repositories and skip without it, unless
``MLSBOM_REQUIRE_NETWORK=1`` is set (CI sets it), in which case they fail.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest

from toolkit_ml_sbom.cli import (
    EXIT_CLI_ERROR,
    EXIT_SUCCESS,
    EXIT_VERIFICATION_FAILED,
    main,
)
from toolkit_ml_sbom.envelope import build_report, canonical_dumps

pytest.importorskip("sigstore")

FIXTURES = Path(__file__).parent / "fixtures" / "sigstore"
GH_ISSUER = "https://token.actions.githubusercontent.com"
# Production bundle: rfc8785 0.1.2 wheel signed by its release workflow.
WHL = FIXTURES / "bundle_v3_github.whl"
WHL_BUNDLE = FIXTURES / "bundle_v3_github.whl.sigstore"
WHL_IDENTITY = (
    "https://github.com/trailofbits/rfc8785.py/.github/workflows/release.yml"
    "@refs/tags/v0.1.2"
)
# Staging DSSE bundle whose in-toto subject does NOT match a.dsse...txt's digest.
DSSE_FILE = FIXTURES / "a.dsse.staging-rekor-v2.txt"
DSSE_BUNDLE = FIXTURES / "a.dsse.staging-rekor-v2.txt.sigstore.json"
DSSE_IDENTITY = (
    "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon"
    "/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main"
)


@pytest.fixture(scope="module")
def online() -> None:
    try:
        from sigstore.models import ClientTrustConfig

        ClientTrustConfig.production()
        ClientTrustConfig.staging()
    except Exception as exc:  # noqa: BLE001
        if os.environ.get("MLSBOM_REQUIRE_NETWORK") == "1":
            raise
        pytest.skip(f"Sigstore TUF repository unreachable: {exc}")


def _verify(
    capsys: pytest.CaptureFixture[str], *args: str
) -> tuple[int, dict[str, Any]]:
    capsys.readouterr()
    rc = main(["verify-file", *args])
    out = capsys.readouterr().out
    return rc, (json.loads(out) if out.strip() else {})


# --- online, real bundles --------------------------------------------------------


def test_verifies_real_production_bundle(
    online: None, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, report = _verify(
        capsys,
        str(WHL),
        "--signature",
        str(WHL_BUNDLE),
        "--identity",
        WHL_IDENTITY,
        "--issuer",
        GH_ISSUER,
    )
    assert rc == EXIT_SUCCESS, report
    pred = report["predicate"]
    assert (pred["verdict"], pred["summary"]["mode"]) == ("pass", "sigstore")
    assert pred["details"]["bundle_kind"] == "message_signature"


def test_wrong_identity_fails(online: None, capsys: pytest.CaptureFixture[str]) -> None:
    rc, report = _verify(
        capsys,
        str(WHL),
        "--signature",
        str(WHL_BUNDLE),
        "--identity",
        "https://github.com/attacker/repo/.github/workflows/x.yml@refs/heads/main",
        "--issuer",
        GH_ISSUER,
    )
    assert rc == EXIT_VERIFICATION_FAILED
    assert report["predicate"]["summary"]["signature"] == "failed"


def test_wrong_issuer_fails(online: None, capsys: pytest.CaptureFixture[str]) -> None:
    rc, _ = _verify(
        capsys,
        str(WHL),
        "--signature",
        str(WHL_BUNDLE),
        "--identity",
        WHL_IDENTITY,
        "--issuer",
        "https://accounts.google.com",
    )
    assert rc == EXIT_VERIFICATION_FAILED


def test_tampered_artifact_fails(
    online: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    f = tmp_path / WHL.name
    f.write_bytes(WHL.read_bytes() + b"\0")
    rc, _ = _verify(
        capsys,
        str(f),
        "--signature",
        str(WHL_BUNDLE),
        "--identity",
        WHL_IDENTITY,
        "--issuer",
        GH_ISSUER,
    )
    assert rc == EXIT_VERIFICATION_FAILED


def test_valid_dsse_signature_that_does_not_cover_the_file_fails(
    online: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """The DSSE signature verifies, but its in-toto subject names other content."""
    rc, report = _verify(
        capsys,
        str(DSSE_FILE),
        "--signature",
        str(DSSE_BUNDLE),
        "--identity",
        DSSE_IDENTITY,
        "--issuer",
        GH_ISSUER,
        "--staging",
    )
    assert rc == EXIT_VERIFICATION_FAILED
    pred = report["predicate"]
    assert pred["summary"]["signature"] == "ok"
    assert pred["summary"]["reason"] == "subject_digest_mismatch"
    assert pred["details"]["bundle_kind"] == "dsse"


# --- offline -------------------------------------------------------------------


class _FakeVerifier:
    """Stands in for sigstore's Verifier after its signature checks passed."""

    def __init__(self, payload: bytes, payload_type: str) -> None:
        self.payload, self.payload_type = payload, payload_type
        self.policy: Any = None

    def verify_dsse(self, bundle: Any, policy: Any) -> tuple[str, bytes]:
        self.policy = policy
        return self.payload_type, self.payload


def test_dsse_payload_binding_logic(tmp_path: Path) -> None:
    from toolkit_ml_sbom.filesign import DSSE_PAYLOAD_TYPE, payload_for_file
    from toolkit_ml_sbom.sigstore_mode import verify_bundle

    f = tmp_path / "report.json"
    f.write_bytes(
        canonical_dumps(
            build_report(
                kind="aibom.verify",
                verdict="pass",
                exit_code=0,
                subject=[{"name": "m", "digest": {"sha256": "a" * 64}}],
            )
        )
    )
    bundle = DSSE_BUNDLE.read_bytes()

    fake = _FakeVerifier(payload_for_file(f), DSSE_PAYLOAD_TYPE)
    ok = verify_bundle(bundle, f, identity="a@b.c", issuer="https://x", verifier=fake)
    assert ok.ok and ok.binding is not None
    assert ok.binding.reason == "payload_is_file"
    assert fake.policy._identity == "a@b.c"

    wrong_type = _FakeVerifier(payload_for_file(f), "text/plain")
    bad = verify_bundle(
        bundle, f, identity="a@b.c", issuer="https://x", verifier=wrong_type
    )
    assert not bad.ok and bad.reason == "unexpected_payload_type"


def test_malformed_bundle_fails_closed(tmp_path: Path) -> None:
    from toolkit_ml_sbom.sigstore_mode import verify_bundle

    f = tmp_path / "x"
    f.write_bytes(b"x")
    res = verify_bundle(b"{}", f, identity="a@b.c", issuer="https://x")
    assert not res.ok and res.reason.startswith("bundle_invalid")


def test_identity_and_issuer_are_mandatory(tmp_path: Path) -> None:
    from toolkit_ml_sbom.sigstore_mode import verify_bundle

    f = tmp_path / "x"
    f.write_bytes(b"x")
    with pytest.raises(ValueError):
        verify_bundle(b"{}", f, identity="", issuer="https://x")
    with pytest.raises(ValueError):
        verify_bundle(b"{}", f, identity="a@b.c", issuer="")


def test_sign_file_sigstore_signs_the_report_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import toolkit_ml_sbom.sigstore_mode as sm

    seen: dict[str, Any] = {}

    def fake_sign(payload: bytes, *, identity_token: Any, staging: bool) -> str:
        seen.update(payload=payload, token=identity_token, staging=staging)
        return '{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"}'

    monkeypatch.setattr(sm, "sign_payload", fake_sign)
    f = tmp_path / "report.json"
    f.write_bytes(
        canonical_dumps(
            build_report(
                kind="aibom.generate",
                verdict="pass",
                exit_code=0,
                subject=[{"name": "m", "digest": {"sha256": "b" * 64}}],
            )
        )
    )

    rc = main(["sign-file", str(f), "--sigstore", "--identity-token", "tok"])

    assert rc == EXIT_SUCCESS
    assert seen == {"payload": f.read_bytes(), "token": "tok", "staging": False}
    assert (tmp_path / "report.json.sigstore.json").is_file()


def test_audit_log_never_records_identity_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import toolkit_ml_sbom.sigstore_mode as sm

    monkeypatch.setattr(sm, "sign_payload", lambda payload, **kw: "{}")
    log = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MLSBOM_AUDIT_LOG", str(log))
    f = tmp_path / "x.bin"
    f.write_bytes(b"x")

    main(["sign-file", str(f), "--sigstore", "--identity-token", "SECRET-TOKEN"])

    assert "SECRET-TOKEN" not in log.read_text(encoding="utf-8")


def test_verify_file_rejects_identity_without_issuer_before_network(
    tmp_path: Path,
) -> None:
    f = tmp_path / "x"
    f.write_bytes(b"x")
    shutil.copy(WHL_BUNDLE, tmp_path / "x.sigstore.json")
    assert main(["verify-file", str(f), "--identity", WHL_IDENTITY]) == EXIT_CLI_ERROR


def test_sign_file_sigstore_failure_is_a_clean_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """OIDC, Fulcio or Rekor failures exit 2 without writing a signature."""
    import toolkit_ml_sbom.sigstore_mode as sm

    def boom(payload: bytes, **kw: Any) -> str:
        raise ConnectionError("rekor unavailable")

    monkeypatch.setattr(sm, "sign_payload", boom)
    f = tmp_path / "x.bin"
    f.write_bytes(b"x")

    assert main(["sign-file", str(f), "--sigstore"]) == EXIT_CLI_ERROR
    assert not (tmp_path / "x.bin.sigstore.json").exists()


def test_sign_payload_keeps_signer_key_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """sigstore-python 4 signs with a fresh key per call when cache=False, which
    does not match the Fulcio certificate; the signer must use the default cache.
    """
    import toolkit_ml_sbom.sigstore_mode as sm

    calls: dict[str, Any] = {}

    class FakeSigner:
        def sign_dsse(self, statement: Any) -> Any:
            class B:
                def to_json(self) -> str:
                    return "{}"

            return B()

    class FakeCtx:
        def signer(self, token: Any, **kw: Any) -> Any:
            calls["kw"] = kw
            import contextlib

            return contextlib.nullcontext(FakeSigner())

    monkeypatch.setattr(sm, "_trust_config", lambda staging: object())
    monkeypatch.setattr(sm, "_identity_token", lambda cfg, explicit: "tok")
    import sigstore.sign

    monkeypatch.setattr(
        sigstore.sign.SigningContext, "from_trust_config", lambda cfg: FakeCtx()
    )
    payload = canonical_dumps(
        build_report(
            kind="aibom.generate",
            verdict="pass",
            exit_code=0,
            subject=[{"name": "m", "digest": {"sha256": "c" * 64}}],
        )
    )

    assert sm.sign_payload(payload) == "{}"
    assert calls["kw"].get("cache", True) is True
