"""sign-file / verify-file in Ed25519 key mode (offline, real cryptography)."""

from __future__ import annotations

import base64
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
from toolkit_ml_sbom.envelope import build_report, canonical_dumps, sha256_bytes
from toolkit_ml_sbom.filesign import (
    DSSE_PAYLOAD_TYPE,
    FILE_PREDICATE_TYPE,
    check_binding,
    pae,
    payload_for_file,
)

pytest.importorskip("cryptography")

SCHEMA = json.loads(
    (
        Path(__file__).resolve().parents[1] / "schemas" / "report-envelope.v1.json"
    ).read_text(encoding="utf-8")
)


def _keys(tmp_path: Path, name: str = "k") -> tuple[Path, Path]:
    priv, pub = tmp_path / f"{name}.pem", tmp_path / f"{name}.pub"
    rc = main(["keygen", "--private-key", str(priv), "--public-key", str(pub)])
    assert rc == EXIT_SUCCESS
    return priv, pub


def _verify(
    capsys: pytest.CaptureFixture[str], *args: str
) -> tuple[int, dict[str, Any]]:
    capsys.readouterr()
    rc = main(["verify-file", *args])
    out = capsys.readouterr().out
    return rc, (json.loads(out) if out.strip() else {})


# --- DSSE pre-authentication encoding ---------------------------------------


def test_pae_matches_dsse_spec_example() -> None:
    """Worked example from the DSSE protocol spec (protocol.md, "PAE"):
    https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
    """
    assert (
        pae("http://example.com/HelloWorld", b"hello world")
        == b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    )


def test_pae_matches_sigstore_reference_implementation() -> None:
    """Cross-check against sigstore-python's own PAE (reference implementation)."""
    dsse = pytest.importorskip("sigstore.dsse")
    payload = canonical_dumps({"a": 1})
    assert pae(DSSE_PAYLOAD_TYPE, payload) == dsse._pae(DSSE_PAYLOAD_TYPE, payload)


# --- payload selection --------------------------------------------------------


def test_payload_for_binary_file_is_statement_naming_its_digest(tmp_path: Path) -> None:
    f = tmp_path / "model.safetensors"
    f.write_bytes(b"\x00\x01weights")
    stmt = json.loads(payload_for_file(f))
    assert stmt["_type"] == "https://in-toto.io/Statement/v1"
    assert stmt["predicateType"] == FILE_PREDICATE_TYPE
    assert stmt["subject"] == [
        {
            "name": "model.safetensors",
            "digest": {"sha256": sha256_bytes(f.read_bytes())},
        }
    ]
    assert payload_for_file(f) == canonical_dumps(stmt), "payload is canonical JSON"


def test_payload_for_report_envelope_is_the_file_itself(tmp_path: Path) -> None:
    report = build_report(
        kind="aibom.verify",
        verdict="pass",
        exit_code=0,
        subject=[{"name": "m", "digest": {"sha256": "a" * 64}}],
    )
    f = tmp_path / "report.json"
    f.write_bytes(canonical_dumps(report))
    assert payload_for_file(f) == f.read_bytes()


def test_non_statement_json_is_signed_by_digest(tmp_path: Path) -> None:
    f = tmp_path / "config.json"
    f.write_text('{"model_type": "gpt2"}', encoding="utf-8")
    assert json.loads(payload_for_file(f))["predicateType"] == FILE_PREDICATE_TYPE


def test_check_binding_rejects_non_statement_payload(tmp_path: Path) -> None:
    f = tmp_path / "x"
    f.write_bytes(b"x")
    assert check_binding(b"not json", f).reason == "payload_not_json"
    assert check_binding(b'{"a": 1}', f).reason == "payload_not_in_toto_statement"


# --- CLI round trips -----------------------------------------------------------


def test_sign_and_verify_binary_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    priv, pub = _keys(tmp_path)
    f = tmp_path / "weights.bin"
    f.write_bytes(bytes(range(256)) * 10)

    assert main(["sign-file", str(f), "--key", str(priv)]) == EXIT_SUCCESS
    sig = tmp_path / "weights.bin.sig.json"
    env = json.loads(sig.read_text(encoding="utf-8"))
    assert env["payloadType"] == DSSE_PAYLOAD_TYPE
    assert len(env["signatures"]) == 1 and len(env["signatures"][0]["keyid"]) == 64

    rc, report = _verify(capsys, str(f), "--public-key", str(pub))
    assert rc == EXIT_SUCCESS
    Draft202012Validator(SCHEMA).validate(report)
    pred = report["predicate"]
    assert pred["kind"] == "aibom.verify-file"
    assert (pred["verdict"], pred["exit_code"]) == ("pass", 0)
    assert pred["summary"]["mode"] == "ed25519"
    assert pred["details"]["binding"] == "subject_digest_match"
    assert report["subject"][0]["digest"]["sha256"] == sha256_bytes(f.read_bytes())


def test_tampered_file_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    priv, pub = _keys(tmp_path)
    f = tmp_path / "weights.bin"
    f.write_bytes(b"original")
    main(["sign-file", str(f), "--key", str(priv)])
    f.write_bytes(b"tampered")

    rc, report = _verify(capsys, str(f), "--public-key", str(pub))

    assert rc == EXIT_VERIFICATION_FAILED
    Draft202012Validator(SCHEMA).validate(report)
    pred = report["predicate"]
    assert (pred["verdict"], pred["exit_code"]) == ("fail", EXIT_VERIFICATION_FAILED)
    assert pred["summary"]["signature"] == "ok"
    assert pred["summary"]["reason"] == "subject_digest_mismatch"


def test_signed_report_detects_a_single_byte_change(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    priv, pub = _keys(tmp_path)
    report = build_report(
        kind="aibom.verify",
        verdict="pass",
        exit_code=0,
        subject=[{"name": "m", "digest": {"sha256": "a" * 64}}],
    )
    f = tmp_path / "report.json"
    f.write_bytes(canonical_dumps(report))
    main(["sign-file", str(f), "--key", str(priv)])

    rc, out = _verify(capsys, str(f), "--public-key", str(pub))
    assert rc == EXIT_SUCCESS
    assert out["predicate"]["details"]["binding"] == "payload_is_file"

    f.write_bytes(f.read_bytes().replace(b'"pass"', b'"fail"'))
    rc, out = _verify(capsys, str(f), "--public-key", str(pub))
    assert rc == EXIT_VERIFICATION_FAILED


def test_wrong_key_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    priv, _ = _keys(tmp_path, "a")
    _, other_pub = _keys(tmp_path, "b")
    f = tmp_path / "x.bin"
    f.write_bytes(b"x")
    main(["sign-file", str(f), "--key", str(priv)])

    rc, report = _verify(capsys, str(f), "--public-key", str(other_pub))

    assert rc == EXIT_VERIFICATION_FAILED
    assert report["predicate"]["summary"]["signature"] == "failed"


def test_swapped_payload_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An attacker who re-points the payload at their own file keeps a stale signature."""
    priv, pub = _keys(tmp_path)
    good, evil = tmp_path / "good.bin", tmp_path / "evil.bin"
    good.write_bytes(b"good")
    evil.write_bytes(b"evil")
    main(["sign-file", str(good), "--key", str(priv)])
    env = json.loads((tmp_path / "good.bin.sig.json").read_text(encoding="utf-8"))
    env["payload"] = base64.b64encode(payload_for_file(evil)).decode()
    forged = tmp_path / "evil.bin.sig.json"
    forged.write_text(json.dumps(env), encoding="utf-8")

    rc, report = _verify(capsys, str(evil), "--public-key", str(pub))

    assert rc == EXIT_VERIFICATION_FAILED
    assert report["predicate"]["summary"]["reason"] == "signature_invalid"


def test_wrong_payload_type_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    priv, pub = _keys(tmp_path)
    f = tmp_path / "x.bin"
    f.write_bytes(b"x")
    main(["sign-file", str(f), "--key", str(priv)])
    sig = tmp_path / "x.bin.sig.json"
    env = json.loads(sig.read_text(encoding="utf-8"))
    env["payloadType"] = "text/plain"
    sig.write_text(json.dumps(env), encoding="utf-8")

    rc, report = _verify(capsys, str(f), "--public-key", str(pub))

    assert rc == EXIT_VERIFICATION_FAILED
    assert report["predicate"]["summary"]["reason"] == "unexpected_payload_type"


@pytest.mark.parametrize(
    "content", ["not json", "[]", '{"payloadType": "application/vnd.in-toto+json"}']
)
def test_garbage_signature_file_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: str
) -> None:
    _, pub = _keys(tmp_path)
    f = tmp_path / "x.bin"
    f.write_bytes(b"x")
    sig = tmp_path / "x.sig"
    sig.write_text(content, encoding="utf-8")

    rc, report = _verify(
        capsys, str(f), "--signature", str(sig), "--public-key", str(pub)
    )

    assert rc == EXIT_VERIFICATION_FAILED
    assert report["predicate"]["verdict"] == "fail"


def test_sign_file_needs_exactly_one_mode(tmp_path: Path) -> None:
    priv, _ = _keys(tmp_path)
    f = tmp_path / "x.bin"
    f.write_bytes(b"x")
    assert main(["sign-file", str(f)]) == EXIT_CLI_ERROR
    assert (
        main(["sign-file", str(f), "--key", str(priv), "--sigstore"]) == EXIT_CLI_ERROR
    )


def test_verify_file_needs_exactly_one_mode(tmp_path: Path) -> None:
    priv, pub = _keys(tmp_path)
    f = tmp_path / "x.bin"
    f.write_bytes(b"x")
    main(["sign-file", str(f), "--key", str(priv)])
    assert main(["verify-file", str(f)]) == EXIT_CLI_ERROR
    assert (
        main(["verify-file", str(f), "--public-key", str(pub), "--identity", "a@b.c"])
        == EXIT_CLI_ERROR
    )
    # An identity without an issuer (or the reverse) is never "any issuer".
    assert main(["verify-file", str(f), "--identity", "a@b.c"]) == EXIT_CLI_ERROR
    assert (
        main(["verify-file", str(f), "--issuer", "https://accounts.google.com"])
        == EXIT_CLI_ERROR
    )


def test_verify_file_missing_signature_is_usage_error(tmp_path: Path) -> None:
    _, pub = _keys(tmp_path)
    f = tmp_path / "x.bin"
    f.write_bytes(b"x")
    assert main(["verify-file", str(f), "--public-key", str(pub)]) == EXIT_CLI_ERROR


def test_verify_file_report_flag_and_table(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    priv, pub = _keys(tmp_path)
    f = tmp_path / "x.bin"
    f.write_bytes(b"x")
    main(["sign-file", str(f), "--key", str(priv), "--out", str(tmp_path / "s.json")])
    report_path = tmp_path / "r.json"
    capsys.readouterr()

    rc = main(
        [
            "verify-file",
            str(f),
            "--signature",
            str(tmp_path / "s.json"),
            "--public-key",
            str(pub),
            "--format",
            "table",
            "--report",
            str(report_path),
        ]
    )

    assert rc == EXIT_SUCCESS
    assert "Status: PASS" in capsys.readouterr().out
    raw = report_path.read_bytes()
    assert raw == canonical_dumps(json.loads(raw))
