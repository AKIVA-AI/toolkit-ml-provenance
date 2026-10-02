"""Importers: Hugging Face Hub (mocked, plus one online test) and MLflow runs."""

from __future__ import annotations

import builtins
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cdx_schema import validate_bom
from jsonschema import Draft202012Validator

from toolkit_ml_sbom.cli import EXIT_CLI_ERROR, EXIT_SUCCESS, main

SCHEMA = json.loads(
    (
        Path(__file__).resolve().parents[1] / "schemas" / "report-envelope.v1.json"
    ).read_text(encoding="utf-8")
)
MLRUNS = Path(__file__).parent / "fixtures" / "mlflow" / "mlruns"
RUN_DIR = MLRUNS / "791104385478783971" / "dffbb4c66f8f4f75a9ed14c43a743b91"
RUN_ID = "dffbb4c66f8f4f75a9ed14c43a743b91"

# --- Hugging Face (mocked) ---------------------------------------------------------

REPO = "acme/tiny-classifier"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
WEIGHTS = b"\x00" * 256
FILES = {
    "config.json": json.dumps({"model_type": "bert", "architectures": ["BertModel"]}),
    "README.md": "---\nlicense: mit\n---\n# tiny\n",
    "model.safetensors": WEIGHTS,
}
CARD = {
    "license": "mit",
    "base_model": "google-bert/bert-base-uncased",
    "datasets": ["stanfordnlp/sst2"],
    "pipeline_tag": "text-classification",
}


@pytest.fixture
def fake_hub(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    hf = pytest.importorskip("huggingface_hub")
    calls: dict[str, Any] = {"lfs_sha256": hashlib.sha256(WEIGHTS).hexdigest()}

    class FakeApi:
        def __init__(self, token: Any = None) -> None:
            pass

        def model_info(self, repo_id: str, revision: Any, files_metadata: bool) -> Any:
            calls["model_info"] = (repo_id, revision, files_metadata)
            siblings = [
                SimpleNamespace(rfilename="config.json", lfs=None),
                SimpleNamespace(rfilename="README.md", lfs=None),
                SimpleNamespace(
                    rfilename="model.safetensors",
                    lfs=SimpleNamespace(sha256=calls["lfs_sha256"]),
                ),
            ]
            return SimpleNamespace(
                sha=COMMIT,
                siblings=siblings,
                card_data=SimpleNamespace(to_dict=lambda: dict(CARD)),
            )

    def fake_snapshot_download(
        repo_id: str, revision: str, local_dir: str, allow_patterns: Any, token: Any
    ) -> str:
        calls["snapshot"] = (repo_id, revision, allow_patterns)
        root = Path(local_dir)
        for name, content in FILES.items():
            data = content if isinstance(content, bytes) else content.encode()
            (root / name).write_bytes(data)
        meta = root / ".cache" / "huggingface" / "download"
        meta.mkdir(parents=True)
        (meta / "model.safetensors.metadata").write_text("x", encoding="utf-8")
        return local_dir

    monkeypatch.setattr(hf, "HfApi", FakeApi)
    monkeypatch.setattr(hf, "snapshot_download", fake_snapshot_download)
    return calls


def _hf_generate(tmp_path: Path, *extra: str) -> tuple[int, Path, Path]:
    out, report = tmp_path / "aibom.cdx.json", tmp_path / "report.json"
    rc = main(
        [
            "generate",
            "--from-hf",
            REPO,
            "--root",
            str(tmp_path / "dl"),
            "--out",
            str(out),
            "--format",
            "cyclonedx",
            "--report",
            str(report),
            *extra,
        ]
    )
    return rc, out, report


def test_hf_import_builds_pinned_mlbom(
    tmp_path: Path, fake_hub: dict[str, Any]
) -> None:
    rc, out, report = _hf_generate(tmp_path, "--hf-revision", "main")

    assert rc == EXIT_SUCCESS
    assert fake_hub["model_info"] == (REPO, "main", True)
    # The download is pinned to the resolved commit, not the moving branch.
    assert fake_hub["snapshot"][1] == COMMIT
    assert not (tmp_path / "dl" / ".cache").exists()

    bom = json.loads(out.read_text(encoding="utf-8"))
    validate_bom(bom)
    model = bom["components"][0]
    assert model["name"] == "tiny-classifier"
    assert model["version"] == COMMIT
    assert model["purl"] == f"pkg:huggingface/{REPO}@{COMMIT}"
    assert model["externalReferences"][0]["url"] == f"https://huggingface.co/{REPO}"
    assert model["licenses"] == [{"license": {"id": "MIT"}}]
    assert model["pedigree"]["ancestors"][0]["name"] == "google-bert/bert-base-uncased"
    assert model["modelCard"]["modelParameters"]["task"] == "text-classification"
    assert sorted(c["name"] for c in model["components"]) == sorted(FILES)
    props = {p["name"]: p["value"] for p in model["properties"]}
    assert props["hf:lfs-files-verified"] == "1"

    Draft202012Validator(SCHEMA).validate(json.loads(report.read_bytes()))


def test_hf_lfs_mismatch_fails(tmp_path: Path, fake_hub: dict[str, Any]) -> None:
    fake_hub["lfs_sha256"] = "f" * 64

    rc, out, _ = _hf_generate(tmp_path)

    assert rc == EXIT_CLI_ERROR
    assert not out.exists()


def test_hf_needs_empty_root(tmp_path: Path, fake_hub: dict[str, Any]) -> None:
    (tmp_path / "dl").mkdir()
    (tmp_path / "dl" / "old.bin").write_bytes(b"x")

    rc, _, _ = _hf_generate(tmp_path)

    assert rc == EXIT_CLI_ERROR


def test_hf_needs_root(tmp_path: Path, fake_hub: dict[str, Any]) -> None:
    rc = main(["generate", "--from-hf", REPO, "--out", str(tmp_path / "x.json")])
    assert rc == EXIT_CLI_ERROR


def test_hf_missing_extra_is_clean_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_import = builtins.__import__

    def no_hf(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "huggingface_hub":
            raise ImportError("no huggingface_hub")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_hf)
    rc, _, _ = _hf_generate(tmp_path)
    assert rc == EXIT_CLI_ERROR


def test_generate_still_requires_include_without_importer(tmp_path: Path) -> None:
    rc = main(["generate", "--root", str(tmp_path), "--out", str(tmp_path / "m.json")])
    assert rc == EXIT_CLI_ERROR


def test_hf_real_tiny_public_model(tmp_path: Path) -> None:
    """Online: hf-internal-testing/tiny-random-gpt2 at a pinned commit."""
    pytest.importorskip("huggingface_hub")
    rev = "71034c5d8bde858ff824298bdedc65515b97d2b9"
    try:
        rc, out, report = _real_hf(tmp_path, rev)
    except OSError as exc:  # pragma: no cover - network dependent
        if os.environ.get("MLSBOM_REQUIRE_NETWORK") == "1":
            raise
        pytest.skip(f"Hugging Face Hub unreachable: {exc}")
    if rc != EXIT_SUCCESS and os.environ.get("MLSBOM_REQUIRE_NETWORK") != "1":
        pytest.skip("Hugging Face Hub unreachable")
    assert rc == EXIT_SUCCESS
    bom = json.loads(out.read_text(encoding="utf-8"))
    validate_bom(bom)
    model = bom["components"][0]
    assert (
        model["purl"] == f"pkg:huggingface/hf-internal-testing/tiny-random-gpt2@{rev}"
    )
    assert model["modelCard"]["modelParameters"]["architectureFamily"] == "gpt2"
    summary = json.loads(report.read_bytes())["predicate"]["summary"]
    # A real PyTorch checkpoint uses only allowlisted globals.
    assert summary["pickle"]["pickle_files"] == 1
    assert summary["pickle"]["safe"] == 1


def _real_hf(tmp_path: Path, rev: str) -> tuple[int, Path, Path]:
    out, report = tmp_path / "aibom.cdx.json", tmp_path / "report.json"
    rc = main(
        [
            "generate",
            "--from-hf",
            "hf-internal-testing/tiny-random-gpt2",
            "--hf-revision",
            rev,
            "--hf-allow",
            "config.json",
            "--hf-allow",
            "model.safetensors",
            "--hf-allow",
            "pytorch_model.bin",
            "--root",
            str(tmp_path / "tiny"),
            "--out",
            str(out),
            "--format",
            "cyclonedx",
            "--report",
            str(report),
        ]
    )
    return rc, out, report


# --- MLflow ------------------------------------------------------------------------------


def test_mlflow3_run_fixture(tmp_path: Path) -> None:
    pytest.importorskip("yaml")  # MLmodel flavors are nested YAML
    out, report = tmp_path / "aibom.cdx.json", tmp_path / "report.json"

    rc = main(
        [
            "generate",
            "--from-mlflow",
            str(RUN_DIR),
            "--out",
            str(out),
            "--format",
            "cyclonedx",
            "--report",
            str(report),
        ]
    )

    assert rc == EXIT_SUCCESS
    bom = json.loads(out.read_text(encoding="utf-8"))
    validate_bom(bom)
    model = bom["components"][0]
    assert (model["name"], model["version"]) == ("tiny-addn", RUN_ID)
    props = {p["name"]: p["value"] for p in model["properties"]}
    assert props["mlflow:run_id"] == RUN_ID
    assert (
        props["mlflow:source-git-commit"] == "0123456789abcdef0123456789abcdef01234567"
    )
    assert props["mlflow:python_version"] == "3.12.14"
    card = model["modelCard"]
    card_props = {p["name"]: p["value"] for p in card["properties"]}
    assert card_props["mlflow:param:n"] == "3"
    assert card_props["mlflow:param:learning_rate"] == "0.01"
    assert card_props["mlflow:flavors"] == "python_function"
    # Latest step of the accuracy metric (steps 0, 1, 2 -> 0.9).
    assert card["quantitativeAnalysis"]["performanceMetrics"] == [
        {"type": "accuracy", "value": "0.9"}
    ]
    refs = {c["bom-ref"] for c in bom["components"]}
    assert {"pkg:pypi/mlflow@3.16.1", "pkg:pypi/numpy@1.26.4"} <= refs
    files = {c["name"]: c for c in model["components"]}
    assert "MLmodel" in files and "python_model.pkl" in files
    pickle_props = {
        p["name"]: p["value"] for p in files["python_model.pkl"]["properties"]
    }
    assert pickle_props["aibom:pickle-scan"] == "dangerous"  # cloudpickle runs code
    summary = json.loads(report.read_bytes())["predicate"]["summary"]
    assert summary["pickle"]["dangerous"] == 1


def test_mlflow2_layout_with_sklearn_flavor(tmp_path: Path) -> None:
    pytest.importorskip("yaml")
    run = tmp_path / "mlruns" / "1" / "abc123"
    (run / "params").mkdir(parents=True)
    (run / "metrics").mkdir()
    (run / "tags").mkdir()
    model = run / "artifacts" / "clf"
    model.mkdir(parents=True)
    (run / "meta.yaml").write_text(
        "run_id: abc123\nexperiment_id: '1'\nrun_name: rf\n", encoding="utf-8"
    )
    (run / "params" / "max_depth").write_text("5", encoding="utf-8")
    (run / "metrics" / "f1").write_text("1700000000000 0.8 0\n", encoding="utf-8")
    (model / "MLmodel").write_text(
        "flavors:\n  sklearn:\n    sklearn_version: 1.5.2\n    pickled_model: model.pkl\n"
        "  python_function:\n    python_version: 3.11.9\nmlflow_version: 2.17.0\n",
        encoding="utf-8",
    )
    (model / "model.pkl").write_bytes(b"\x80\x04N.")  # pickle of None
    out = tmp_path / "bom.json"

    rc = main(
        [
            "generate",
            "--from-mlflow",
            str(run),
            "--mlflow-model",
            "clf",
            "--out",
            str(out),
            "--format",
            "cyclonedx",
        ]
    )

    assert rc == EXIT_SUCCESS
    bom = json.loads(out.read_text(encoding="utf-8"))
    validate_bom(bom)
    refs = {c["bom-ref"]: c for c in bom["components"]}
    assert refs["pkg:pypi/scikit-learn@1.5.2"]["type"] == "framework"
    assert "pkg:pypi/mlflow@2.17.0" in refs
    assert bom["components"][0]["name"] == "rf"


def test_mlflow_unknown_model_and_bad_dir(tmp_path: Path) -> None:
    out = str(tmp_path / "bom.json")
    assert (
        main(
            [
                "generate",
                "--from-mlflow",
                str(RUN_DIR),
                "--mlflow-model",
                "nope",
                "--out",
                out,
            ]
        )
        == EXIT_CLI_ERROR
    )
    assert (
        main(["generate", "--from-mlflow", str(tmp_path), "--out", out])
        == EXIT_CLI_ERROR
    )


def test_hf_and_mlflow_together_is_an_error(tmp_path: Path) -> None:
    rc = main(
        [
            "generate",
            "--from-hf",
            REPO,
            "--from-mlflow",
            str(RUN_DIR),
            "--root",
            str(tmp_path / "x"),
            "--out",
            str(tmp_path / "b.json"),
        ]
    )
    assert rc == EXIT_CLI_ERROR
