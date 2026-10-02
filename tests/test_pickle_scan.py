"""Static pickle scanning: never unpickles; cross-checked against picklescan.

Fixtures are built with ``pickle.dumps`` on objects whose ``__reduce__``
returns the callable to import. Dumping only records the import; nothing is
ever loaded.
"""

from __future__ import annotations

import io
import json
import os
import pickle
import struct
import sys
import types
import zipfile
from collections import OrderedDict
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cdx_schema import validate_bom
from jsonschema import Draft202012Validator

from toolkit_ml_sbom.cli import EXIT_SUCCESS, EXIT_VERIFICATION_FAILED, main
from toolkit_ml_sbom.pickle_scan import (
    TORCH_LEGACY_MAGIC,
    classify,
    extract_globals,
    scan_bytes,
    scan_file,
)

SCHEMA = json.loads(
    (
        Path(__file__).resolve().parents[1] / "schemas" / "report-envelope.v1.json"
    ).read_text(encoding="utf-8")
)


class _Call:
    """Pickles as ``func(*args)``."""

    def __init__(self, func: Any, *args: Any) -> None:
        self.func, self.args = func, args

    def __reduce__(self) -> tuple[Any, tuple[Any, ...]]:
        return self.func, self.args


@pytest.fixture
def fake_torch() -> Iterator[types.ModuleType]:
    """A stand-in ``torch._utils`` module so pickles reference the real names."""
    mod = types.ModuleType("torch._utils")

    def _rebuild_tensor_v2(*args: Any) -> None: ...

    _rebuild_tensor_v2.__module__ = "torch._utils"
    _rebuild_tensor_v2.__qualname__ = "_rebuild_tensor_v2"
    mod._rebuild_tensor_v2 = _rebuild_tensor_v2  # type: ignore[attr-defined]
    parent = types.ModuleType("torch")
    parent._utils = mod  # type: ignore[attr-defined]
    saved = {k: sys.modules.get(k) for k in ("torch", "torch._utils")}
    sys.modules.update({"torch": parent, "torch._utils": mod})
    yield mod
    for key, value in saved.items():
        if value is None:
            sys.modules.pop(key, None)
        else:
            sys.modules[key] = value


def _evil(protocol: int) -> bytes:
    return pickle.dumps(_Call(os.system, "echo pwned"), protocol=protocol)


def _state_dict(torch_utils: types.ModuleType, protocol: int = 2) -> bytes:
    state = OrderedDict(
        weight=_Call(torch_utils._rebuild_tensor_v2, "storage", 0, (2, 2), (2, 1))
    )
    return pickle.dumps(state, protocol=protocol)


def _custom_class_pickle() -> bytes:
    # An importable global that is neither allowlisted nor denylisted.
    return pickle.dumps(_Call(json.JSONDecoder), protocol=4)


# --- classification ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("module", "name", "expected"),
    [
        ("posix", "system", "dangerous"),
        ("nt", "system", "dangerous"),
        ("os.path", "join", "dangerous"),  # submodule of a "*" module
        ("subprocess", "Popen", "dangerous"),
        ("builtins", "eval", "dangerous"),
        ("builtins", "set", "safe"),
        ("collections", "OrderedDict", "safe"),
        ("torch._utils", "_rebuild_tensor_v2", "safe"),
        ("numpy.core.multiarray", "_reconstruct", "safe"),
        ("json.decoder", "JSONDecoder", "unknown"),
        ("<unknown>", "system", "dangerous"),
    ],
)
def test_classify(module: str, name: str, expected: str) -> None:
    assert classify(module, name) == expected


# --- extraction ---------------------------------------------------------------------


@pytest.mark.parametrize("protocol", [0, 1, 2, 3, 4, 5])
def test_detects_os_system_in_every_protocol(protocol: int) -> None:
    found = extract_globals(io.BytesIO(_evil(protocol)))
    assert (os.system.__module__, "system") in found


def test_stack_global_through_memo() -> None:
    """Protocol 4 fetches a repeated module name from the memo (BINGET)."""
    data = pickle.dumps([_Call(os.system, "a"), _Call(os.getcwd)], protocol=4)
    ops = [op.name for op, _, _ in __import__("pickletools").genops(data)]
    assert "BINGET" in ops, "fixture must exercise the memo path"
    found = extract_globals(io.BytesIO(data))
    assert {(os.system.__module__, "system"), (os.getcwd.__module__, "getcwd")} <= found


def test_safe_state_dict(fake_torch: types.ModuleType) -> None:
    finding = scan_bytes(_state_dict(fake_torch), "sd.pkl")
    assert finding is not None
    assert finding.verdict == "safe"
    assert {(g["module"], g["name"]) for g in finding.globals} == {
        ("collections", "OrderedDict"),
        ("torch._utils", "_rebuild_tensor_v2"),
    }


def test_unknown_global(tmp_path: Path) -> None:
    finding = scan_bytes(_custom_class_pickle(), "x.pkl")
    assert finding is not None and finding.verdict == "unknown"


def test_second_appended_pickle_is_scanned() -> None:
    data = pickle.dumps({"a": 1}, protocol=2) + _evil(2)
    finding = scan_bytes(data, "x.pkl")
    assert finding is not None and finding.verdict == "dangerous"


def test_legacy_torch_file_stops_after_five_pickles(
    fake_torch: types.ModuleType,
) -> None:
    """Raw tensor bytes after the five pickles are never parsed as a pickle."""
    parts = [
        pickle.dumps(TORCH_LEGACY_MAGIC, protocol=2),
        pickle.dumps(1001, protocol=2),
        pickle.dumps({"little_endian": True}, protocol=2),
        _state_dict(fake_torch),
        pickle.dumps(["0"], protocol=2),
    ]
    raw_tensor_bytes = b"\x80\x02cposix\nsystem\n" + os.urandom(64)
    finding = scan_bytes(b"".join(parts) + raw_tensor_bytes, "pytorch_model.bin")
    assert finding is not None
    assert finding.verdict == "safe", finding.globals


def test_malformed_pickle_is_error_not_safe() -> None:
    finding = scan_bytes(b"\x80\x04\x95garbage", "x.pkl")
    assert finding is not None and finding.verdict == "error"


def test_partial_pickle_keeps_dangerous_verdict() -> None:
    finding = scan_bytes(_evil(2)[:-1] + b"\xff", "x.pkl")
    assert finding is not None and finding.verdict == "dangerous"


# --- file formats ---------------------------------------------------------------------


def test_pytorch_zip_checkpoint(tmp_path: Path) -> None:
    path = tmp_path / "model.pt"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("archive/data.pkl", _evil(2))
        zf.writestr("archive/data/0", b"\x00" * 16)
        zf.writestr("archive/version", "3\n")
    finding = scan_file(path)
    assert finding is not None
    assert (finding.format, finding.verdict) == ("pytorch-zip", "dangerous")


def _npy_object(payload: bytes) -> bytes:
    header = "{'descr': '|O', 'fortran_order': False, 'shape': (1,), }"
    header += " " * (63 - (10 + len(header)) % 64) + "\n"
    return (
        b"\x93NUMPY\x01\x00"
        + struct.pack("<H", len(header))
        + header.encode()
        + payload
    )


def test_numpy_object_array(tmp_path: Path) -> None:
    path = tmp_path / "arr.npy"
    path.write_bytes(_npy_object(_evil(2)))
    finding = scan_file(path)
    assert finding is not None
    assert (finding.format, finding.verdict) == ("numpy-object", "dangerous")


def test_non_pickle_files_are_skipped(tmp_path: Path) -> None:
    raw = tmp_path / "ggml-model.bin"
    raw.write_bytes(b"\x00\x01\x02\x03" * 16)
    assert scan_file(raw) is None
    numeric = tmp_path / "arr.npy"
    numeric.write_bytes(
        b"\x93NUMPY\x01\x00"
        + struct.pack("<H", 54)
        + b"{'descr': '<f4', 'fortran_order': False, 'shape': (1,), }\n"[:54]
        + b"\x00" * 4
    )
    assert scan_file(numeric) is None


def test_pkl_that_is_not_a_pickle_is_error(tmp_path: Path) -> None:
    path = tmp_path / "x.pkl"
    path.write_text("hello", encoding="utf-8")
    finding = scan_file(path)
    assert finding is not None and finding.verdict == "error"


# --- cross-check against the picklescan reference implementation -----------------


def _fixtures(fake_torch: types.ModuleType) -> dict[str, bytes]:
    return {
        **{f"evil-p{p}": _evil(p) for p in range(6)},
        "memo": pickle.dumps([_Call(os.system, "a"), _Call(os.getcwd)], protocol=4),
        "state-dict-p2": _state_dict(fake_torch, 2),
        "state-dict-p4": _state_dict(fake_torch, 4),
        "custom": _custom_class_pickle(),
        "eval": pickle.dumps(_Call(eval, "1+1"), protocol=4),
        "plain": pickle.dumps({"a": [1, 2.0, "x"]}, protocol=5),
    }


def test_matches_picklescan_reference(fake_torch: types.ModuleType) -> None:
    """Same extracted globals, and same dangerous/not-dangerous decision, as
    picklescan (https://github.com/mmaitre314/picklescan) on every fixture."""
    scanner = pytest.importorskip("picklescan.scanner")
    for name, data in _fixtures(fake_torch).items():
        ref = scanner.scan_pickle_bytes(io.BytesIO(data), name)
        ref_globals = {(g.module, g.name) for g in ref.globals}
        ours = scan_bytes(data, name)
        assert ours is not None, name
        our_globals = {(g["module"], g["name"]) for g in ours.globals}
        assert our_globals == ref_globals, name
        assert (ours.verdict == "dangerous") == (ref.issues_count > 0), name


# --- CLI ------------------------------------------------------------------------------


def _model_with(tmp_path: Path, name: str, data: bytes) -> Path:
    root = tmp_path / "model"
    root.mkdir(exist_ok=True)
    (root / "model.safetensors").write_bytes(b"\x00" * 8)
    (root / name).write_bytes(data)
    return root


def test_scan_pickle_command_fails_on_dangerous(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _model_with(tmp_path, "optimizer.pt", _evil(2))
    capsys.readouterr()

    rc = main(["scan-pickle", str(root)])

    assert rc == EXIT_VERIFICATION_FAILED
    report = json.loads(capsys.readouterr().out)
    Draft202012Validator(SCHEMA).validate(report)
    pred = report["predicate"]
    assert pred["kind"] == "aibom.scan-pickle"
    assert (pred["summary"]["pickle_files"], pred["summary"]["dangerous"]) == (1, 1)
    assert pred["details"]["findings"][0]["path"] == "optimizer.pt"


def test_scan_pickle_strict_fails_on_unknown(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _model_with(tmp_path, "custom.pkl", _custom_class_pickle())

    assert main(["scan-pickle", str(root)]) == EXIT_SUCCESS
    assert main(["scan-pickle", "--strict", str(root)]) == EXIT_VERIFICATION_FAILED


def test_scan_pickle_safe_file(
    tmp_path: Path, fake_torch: types.ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _model_with(tmp_path, "pytorch_model.bin", _state_dict(fake_torch))
    assert main(["scan-pickle", "--strict", str(root / "pytorch_model.bin")]) == 0


def test_generate_records_findings_and_gates(tmp_path: Path) -> None:
    root = _model_with(tmp_path, "optimizer.pt", _evil(2))
    bom_path, report_path = tmp_path / "bom.json", tmp_path / "report.json"
    args = [
        "generate",
        "--root",
        str(root),
        "--out",
        str(bom_path),
        "--include",
        "*",
        "--format",
        "cyclonedx",
        "--report",
        str(report_path),
    ]

    assert main(args) == EXIT_SUCCESS  # report-only by default
    bom = json.loads(bom_path.read_text(encoding="utf-8"))
    validate_bom(bom)
    files = {c["name"]: c for c in bom["components"][0]["components"]}
    props = {p["name"]: p["value"] for p in files["optimizer.pt"]["properties"]}
    assert props["aibom:pickle-scan"] == "dangerous"
    assert f"{os.system.__module__}.system" in props["aibom:pickle-imports"]
    report = json.loads(report_path.read_bytes())
    assert report["predicate"]["summary"]["pickle"]["dangerous"] == 1

    assert main([*args, "--fail-on-pickle", "dangerous"]) == EXIT_VERIFICATION_FAILED
    report = json.loads(report_path.read_bytes())
    Draft202012Validator(SCHEMA).validate(report)
    assert report["predicate"]["verdict"] == "fail"
    assert bom_path.is_file(), "outputs are still written when the gate fails"


def test_generate_no_pickle_scan(tmp_path: Path) -> None:
    root = _model_with(tmp_path, "optimizer.pt", _evil(2))
    report_path = tmp_path / "r.json"
    rc = main(
        [
            "generate",
            "--root",
            str(root),
            "--out",
            str(tmp_path / "m.json"),
            "--include",
            "*",
            "--no-pickle-scan",
            "--report",
            str(report_path),
        ]
    )
    assert rc == EXIT_SUCCESS
    summary = json.loads(report_path.read_bytes())["predicate"]["summary"]
    assert summary["pickle"] == "not_scanned"


def test_npz_archive_member(tmp_path: Path) -> None:
    path = tmp_path / "arrays.npz"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("x.npy", _npy_object(_evil(2)))
    finding = scan_file(path)
    assert finding is not None
    assert (finding.format, finding.verdict) == ("zip", "dangerous")
