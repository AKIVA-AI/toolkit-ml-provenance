"""Report envelope v1: in-toto Statement output for generate and verify.

The envelope must validate against ``schemas/report-envelope.v1.json``, be
canonical JSON, and carry a verdict that agrees with the exit code.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from toolkit_ml_sbom import __version__
from toolkit_ml_sbom.cli import (
    EXIT_CLI_ERROR,
    EXIT_SUCCESS,
    EXIT_VERIFICATION_FAILED,
    main,
)
from toolkit_ml_sbom.envelope import (
    PREDICATE_TYPE,
    STATEMENT_TYPE,
    build_report,
    canonical_dumps,
    tree_digest,
)

SCHEMA = json.loads(
    (
        Path(__file__).resolve().parents[1] / "schemas" / "report-envelope.v1.json"
    ).read_text(encoding="utf-8")
)


def _validate(report: dict[str, Any]) -> None:
    Draft202012Validator(SCHEMA).validate(report)


def _model(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "model"
    (root / "weights").mkdir(parents=True)
    (root / "weights" / "a.bin").write_bytes(b"weights")
    (root / "config.json").write_text('{"model_type": "gpt2"}', encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    assert (
        main(
            [
                "generate",
                "--root",
                str(root),
                "--out",
                str(manifest),
                "--include",
                "**/*",
            ]
        )
        == EXIT_SUCCESS
    )
    return root, manifest


def test_schema_file_is_a_valid_json_schema() -> None:
    Draft202012Validator.check_schema(SCHEMA)


def test_canonical_dumps_is_sorted_compact_with_newline() -> None:
    assert canonical_dumps({"b": 1, "a": [1, 2], "c": "é"}) == (
        '{"a":[1,2],"b":1,"c":"é"}\n'.encode()
    )


def test_canonical_dumps_rejects_nan() -> None:
    with pytest.raises(ValueError):
        canonical_dumps({"x": float("nan")})


@pytest.mark.parametrize(("verdict", "code"), [("pass", 4), ("fail", 0), ("error", 0)])
def test_build_report_rejects_inconsistent_verdict(verdict: str, code: int) -> None:
    with pytest.raises(ValueError):
        build_report(
            kind="aibom.verify",
            verdict=verdict,
            exit_code=code,
            subject=[{"name": "x", "digest": {"sha256": "0" * 64}}],
        )


def test_build_report_rejects_unknown_verdict() -> None:
    with pytest.raises(ValueError):
        build_report(
            kind="aibom.verify",
            verdict="ok",
            exit_code=0,
            subject=[{"name": "x", "digest": {"sha256": "0" * 64}}],
        )


def test_tree_digest_is_order_independent_and_content_sensitive() -> None:
    a = {"path": "a", "sha256": "1" * 64, "size": 1}
    b = {"path": "b", "sha256": "2" * 64, "size": 2}
    assert tree_digest([a, b]) == tree_digest([b, a])
    assert tree_digest([a, b]) != tree_digest([a, {**b, "sha256": "3" * 64}])


def test_generate_report_envelope(tmp_path: Path) -> None:
    root, _ = _model(tmp_path)
    manifest = tmp_path / "m2.json"
    report_path = tmp_path / "gen-report.json"

    rc = main(
        [
            "generate",
            "--root",
            str(root),
            "--out",
            str(manifest),
            "--include",
            "**/*",
            "--report",
            str(report_path),
        ]
    )

    assert rc == EXIT_SUCCESS
    raw = report_path.read_bytes()
    report = json.loads(raw)
    _validate(report)
    assert raw == canonical_dumps(report), "report file must be canonical JSON"
    assert report["_type"] == STATEMENT_TYPE
    assert report["predicateType"] == PREDICATE_TYPE
    pred = report["predicate"]
    assert pred["tool"] == {"name": "toolkit-ml-provenance", "version": __version__}
    assert pred["kind"] == "aibom.generate"
    assert (pred["verdict"], pred["exit_code"]) == ("pass", 0)
    assert pred["summary"]["files"] == 2
    entries = json.loads(manifest.read_text(encoding="utf-8"))["entries"]
    assert report["subject"] == [
        {"name": "model", "digest": {"sha256": tree_digest(entries)}}
    ]
    assert pred["details"]["output"]["digest"]["sha256"] == (
        hashlib.sha256(manifest.read_bytes()).hexdigest()
    )


def test_generate_never_lists_its_report(tmp_path: Path) -> None:
    root, _ = _model(tmp_path)
    manifest = tmp_path / "m.json"
    report_path = root / "report.json"
    report_path.write_text("{}", encoding="utf-8")

    main(
        [
            "generate",
            "--root",
            str(root),
            "--out",
            str(manifest),
            "--include",
            "**/*",
            "--report",
            str(report_path),
        ]
    )

    paths = [
        e["path"] for e in json.loads(manifest.read_text(encoding="utf-8"))["entries"]
    ]
    assert "report.json" not in paths


def test_verify_stdout_is_envelope_and_passes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, manifest = _model(tmp_path)
    capsys.readouterr()

    rc = main(["verify", "--manifest", str(manifest)])

    assert rc == EXIT_SUCCESS
    report = json.loads(capsys.readouterr().out)
    _validate(report)
    pred = report["predicate"]
    assert pred["kind"] == "aibom.verify"
    assert (pred["verdict"], pred["exit_code"]) == ("pass", 0)
    assert pred["summary"]["signature"] == "not_checked"
    assert pred["summary"]["files_checked"] == 2
    assert pred["inputs"][0]["name"] == "manifest.json"
    assert pred["inputs"][0]["digest"]["sha256"] == (
        hashlib.sha256(manifest.read_bytes()).hexdigest()
    )


def test_verify_failure_envelope_counts_reasons(tmp_path: Path) -> None:
    root, manifest = _model(tmp_path)
    (root / "weights" / "a.bin").write_bytes(b"tampered")
    (root / "config.json").unlink()
    (root / "weights" / "evil.pkl").write_bytes(b"x")
    out = tmp_path / "verify.json"

    rc = main(["verify", "--manifest", str(manifest), "--out", str(out)])

    assert rc == EXIT_VERIFICATION_FAILED
    raw = out.read_bytes()
    report = json.loads(raw)
    _validate(report)
    assert raw == canonical_dumps(report)
    pred = report["predicate"]
    assert (pred["verdict"], pred["exit_code"]) == ("fail", EXIT_VERIFICATION_FAILED)
    assert pred["summary"] == {
        "ok": False,
        "files_checked": 2,
        "missing": 1,
        "hash_mismatch": 1,
        "hash_errors": 0,
        "unlisted": 1,
        "signature": "not_checked",
    }
    assert pred["details"]["unlisted"] == ["weights/evil.pkl"]


def test_verify_report_flag_writes_envelope_alongside_table(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, manifest = _model(tmp_path)
    report_path = tmp_path / "r.json"
    capsys.readouterr()

    rc = main(
        [
            "verify",
            "--manifest",
            str(manifest),
            "--format",
            "table",
            "--report",
            str(report_path),
        ]
    )

    assert rc == EXIT_SUCCESS
    assert "PASS" in capsys.readouterr().out
    _validate(json.loads(report_path.read_bytes()))


def test_verify_legacy_json_keeps_old_shape(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, manifest = _model(tmp_path)
    capsys.readouterr()

    rc = main(["verify", "--manifest", str(manifest), "--format", "legacy-json"])

    assert rc == EXIT_SUCCESS
    assert json.loads(capsys.readouterr().out) == {
        "ok": True,
        "failures": [],
        "signature_ok": None,
        "unlisted": [],
    }


def test_verify_unreadable_manifest_writes_error_envelope(tmp_path: Path) -> None:
    manifest = tmp_path / "broken.json"
    manifest.write_text("{not json", encoding="utf-8")
    report_path = tmp_path / "r.json"

    rc = main(["verify", "--manifest", str(manifest), "--report", str(report_path)])

    assert rc == EXIT_CLI_ERROR
    report = json.loads(report_path.read_bytes())
    _validate(report)
    assert report["predicate"]["verdict"] == "error"
    assert report["predicate"]["exit_code"] == EXIT_CLI_ERROR
