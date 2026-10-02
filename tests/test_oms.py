"""OpenSSF Model Signing (OMS) via the model-signing library (the `oms` extra).

Interoperability is checked both ways against the reference implementation:
signatures made by ``sign-model`` verify with ``model_signing``'s own API, and
signatures made by ``model_signing`` verify with ``verify-model``.
"""

from __future__ import annotations

import builtins
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from toolkit_ml_sbom.cli import (
    EXIT_CLI_ERROR,
    EXIT_SUCCESS,
    EXIT_VERIFICATION_FAILED,
    main,
)

model_signing = pytest.importorskip("model_signing")

SCHEMA = json.loads(
    (
        Path(__file__).resolve().parents[1] / "schemas" / "report-envelope.v1.json"
    ).read_text(encoding="utf-8")
)


def _model(tmp_path: Path) -> Path:
    root = tmp_path / "tiny-model"
    (root / "weights").mkdir(parents=True)
    (root / "weights" / "model.safetensors").write_bytes(b"\x00" * 64)
    (root / "config.json").write_text('{"model_type": "gpt2"}', encoding="utf-8")
    return root


def _ec_keys(tmp_path: Path, name: str = "ec") -> tuple[Path, Path]:
    priv, pub = tmp_path / f"{name}.pem", tmp_path / f"{name}.pub"
    rc = main(
        [
            "keygen",
            "--algorithm",
            "ecdsa-p256",
            "--private-key",
            str(priv),
            "--public-key",
            str(pub),
        ]
    )
    assert rc == EXIT_SUCCESS
    return priv, pub


def _verify(
    capsys: pytest.CaptureFixture[str], *args: str
) -> tuple[int, dict[str, Any]]:
    capsys.readouterr()
    rc = main(["verify-model", *args])
    out = capsys.readouterr().out
    return rc, (json.loads(out) if out.strip() else {})


def test_keygen_ecdsa_p256(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    priv, _ = _ec_keys(tmp_path)
    key = serialization.load_pem_private_key(priv.read_bytes(), password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert key.curve.name == "secp256r1"


def test_sign_and_verify_model_round_trip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    model = _model(tmp_path)
    priv, pub = _ec_keys(tmp_path)

    assert main(["sign-model", str(model), "--key", str(priv)]) == EXIT_SUCCESS
    sig = tmp_path / "tiny-model.oms.sig"
    assert sig.is_file()

    rc, report = _verify(capsys, str(model), "--public-key", str(pub))

    assert rc == EXIT_SUCCESS
    Draft202012Validator(SCHEMA).validate(report)
    pred = report["predicate"]
    assert pred["kind"] == "aibom.verify-model"
    assert (pred["verdict"], pred["summary"]["format"]) == ("pass", "oms")
    assert pred["summary"]["files"] == 2
    # The subject digest is the OMS model digest from the signed statement.
    bundle = json.loads(sig.read_text(encoding="utf-8"))
    import base64

    statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
    assert statement["predicateType"] == "https://model_signing/signature/v1.0"
    assert report["subject"] == [
        {"name": "tiny-model", "digest": statement["subject"][0]["digest"]}
    ]


def test_signature_verifies_with_reference_implementation(tmp_path: Path) -> None:
    model = _model(tmp_path)
    priv, pub = _ec_keys(tmp_path)
    sig = tmp_path / "m.sig"
    assert (
        main(["sign-model", str(model), "--key", str(priv), "--out", str(sig)])
        == EXIT_SUCCESS
    )

    model_signing.verifying.Config().use_elliptic_key_verifier(public_key=pub).verify(
        model, sig
    )


def test_reference_signature_verifies_with_verify_model(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    model = _model(tmp_path)
    priv, pub = _ec_keys(tmp_path)
    sig = tmp_path / "ref.sig"
    model_signing.signing.Config().use_elliptic_key_signer(private_key=priv).sign(
        model, sig
    )

    rc, _ = _verify(
        capsys, str(model), "--signature", str(sig), "--public-key", str(pub)
    )

    assert rc == EXIT_SUCCESS


@pytest.mark.parametrize("change", ["modify", "delete", "add"])
def test_changed_model_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], change: str
) -> None:
    model = _model(tmp_path)
    priv, pub = _ec_keys(tmp_path)
    main(["sign-model", str(model), "--key", str(priv)])
    if change == "modify":
        (model / "config.json").write_text('{"model_type": "evil"}', encoding="utf-8")
    elif change == "delete":
        (model / "config.json").unlink()
    else:
        (model / "weights" / "payload.pkl").write_bytes(b"\x80\x04.")

    rc, report = _verify(capsys, str(model), "--public-key", str(pub))

    assert rc == EXIT_VERIFICATION_FAILED
    Draft202012Validator(SCHEMA).validate(report)
    assert report["predicate"]["verdict"] == "fail"


def test_wrong_key_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    model = _model(tmp_path)
    priv, _ = _ec_keys(tmp_path, "a")
    _, other = _ec_keys(tmp_path, "b")
    main(["sign-model", str(model), "--key", str(priv)])

    rc, _ = _verify(capsys, str(model), "--public-key", str(other))

    assert rc == EXIT_VERIFICATION_FAILED


def test_signature_inside_model_dir_is_not_signed_over(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    model = _model(tmp_path)
    priv, pub = _ec_keys(tmp_path)
    sig = model / "model.sig"

    assert main(["sign-model", str(model), "--key", str(priv), "--out", str(sig)]) == 0
    rc, _ = _verify(
        capsys, str(model), "--signature", str(sig), "--public-key", str(pub)
    )

    assert rc == EXIT_SUCCESS


def test_ed25519_key_is_rejected_cleanly(tmp_path: Path) -> None:
    model = _model(tmp_path)
    priv, pub = tmp_path / "ed.pem", tmp_path / "ed.pub"
    main(["keygen", "--private-key", str(priv), "--public-key", str(pub)])

    assert main(["sign-model", str(model), "--key", str(priv)]) == EXIT_CLI_ERROR


def test_mode_validation(tmp_path: Path) -> None:
    model = _model(tmp_path)
    priv, pub = _ec_keys(tmp_path)
    main(["sign-model", str(model), "--key", str(priv)])

    assert main(["sign-model", str(model)]) == EXIT_CLI_ERROR
    assert main(["sign-model", str(model), "--key", str(priv), "--sigstore"]) == 2
    assert main(["verify-model", str(model)]) == EXIT_CLI_ERROR
    assert main(["verify-model", str(model), "--identity", "a@b.c"]) == EXIT_CLI_ERROR
    assert (
        main(
            [
                "verify-model",
                str(model),
                "--public-key",
                str(pub),
                "--identity",
                "a@b.c",
                "--issuer",
                "https://accounts.google.com",
            ]
        )
        == EXIT_CLI_ERROR
    )
    assert main(["verify-model", str(tmp_path / "nope"), "--public-key", str(pub)]) == 2


def test_missing_extra_is_a_clean_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    model = _model(tmp_path)
    priv, _ = _ec_keys(tmp_path)
    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "model_signing":
            raise ImportError("No module named 'model_signing'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    assert main(["sign-model", str(model), "--key", str(priv)]) == EXIT_CLI_ERROR
