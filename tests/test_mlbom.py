"""CycloneDX 1.6 ML-BOM output, validated against the official 1.6 JSON schema."""

from __future__ import annotations

import builtins
import hashlib
import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from cdx_schema import all_bom_refs, validate_bom

from toolkit_ml_sbom.cli import EXIT_CLI_ERROR, EXIT_SUCCESS, main
from toolkit_ml_sbom.model_info import (
    _parse_simple_yaml,
    parse_front_matter,
    parse_requirements,
)

MODEL_CARD = """---
license: apache-2.0
base_model: openai-community/gpt2
datasets:
  - stanfordnlp/imdb
pipeline_tag: text-classification
library_name: transformers
language:
  - en
tags: [sentiment, demo]
model-index:
  - name: tiny-sentiment
    results:
      - task:
          type: text-classification
        dataset:
          name: imdb
          type: stanfordnlp/imdb
        metrics:
          - type: accuracy
            value: 0.91
          - type: f1
            value: 0.9
---

# tiny-sentiment

A demo model.
"""


def _hf_model(tmp_path: Path) -> Path:
    root = tmp_path / "tiny-sentiment"
    root.mkdir()
    (root / "config.json").write_text(
        json.dumps(
            {
                "model_type": "gpt2",
                "architectures": ["GPT2ForSequenceClassification"],
                "transformers_version": "4.44.2",
                "torch_dtype": "float32",
            }
        ),
        encoding="utf-8",
    )
    (root / "README.md").write_text(MODEL_CARD, encoding="utf-8")
    (root / "requirements.txt").write_text(
        "torch==2.4.1\nnumpy>=1.26  # any\n-e .\n", encoding="utf-8"
    )
    (root / "model.safetensors").write_bytes(b"\x00" * 128)
    (root / "tokenizer.json").write_text("{}", encoding="utf-8")
    return root


def _generate(tmp_path: Path, root: Path, *extra: str) -> dict[str, Any]:
    out = tmp_path / "bom.cdx.json"
    rc = main(
        [
            "generate",
            "--root",
            str(root),
            "--out",
            str(out),
            "--include",
            "**/*",
            "--format",
            "cyclonedx",
            *extra,
        ]
    )
    assert rc == EXIT_SUCCESS
    bom: dict[str, Any] = json.loads(out.read_text(encoding="utf-8"))
    return bom


def _by_ref(bom: dict[str, Any], ref: str) -> dict[str, Any]:
    return next(c for c in bom["components"] if c["bom-ref"] == ref)


def test_schema_validator_rejects_invalid_bom() -> None:
    """Sanity check of the validator itself: an unknown component type fails."""
    bad = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [{"type": "model", "name": "x"}],
    }
    with pytest.raises(jsonschema.ValidationError):
        validate_bom(bad)


def test_full_mlbom_validates_and_carries_ml_fields(tmp_path: Path) -> None:
    root = _hf_model(tmp_path)
    data_file = tmp_path / "train.csv"
    data_file.write_text("text,label\nok,1\n", encoding="utf-8")
    data_dir = tmp_path / "eval"
    data_dir.mkdir()
    (data_dir / "part-0.jsonl").write_text('{"x": 1}\n', encoding="utf-8")

    bom = _generate(
        tmp_path,
        root,
        "--model-version",
        "1.0.0",
        "--dataset",
        f"train={data_file}",
        "--dataset",
        str(data_dir),
    )

    validate_bom(bom)
    assert (bom["bomFormat"], bom["specVersion"]) == ("CycloneDX", "1.6")

    model = _by_ref(bom, "model")
    assert model["type"] == "machine-learning-model"
    assert (model["name"], model["version"]) == ("tiny-sentiment", "1.0.0")
    assert model["licenses"] == [{"license": {"id": "Apache-2.0"}}]
    params = model["modelCard"]["modelParameters"]
    assert params["task"] == "text-classification"
    assert params["architectureFamily"] == "gpt2"
    assert params["modelArchitecture"] == "GPT2ForSequenceClassification"
    assert {"ref": "dataset:stanfordnlp/imdb"} in params["datasets"]

    # Files nested under the model, each with its SHA-256.
    files = {c["name"]: c for c in model["components"]}
    assert files["model.safetensors"]["type"] == "file"
    assert files["model.safetensors"]["hashes"] == [
        {
            "alg": "SHA-256",
            "content": hashlib.sha256(b"\x00" * 128).hexdigest(),
        }
    ]
    props = {(p["name"], p["value"]) for p in model["properties"]}
    assert ("aibom:serialization-format", "safetensors") in props

    # Base-model lineage.
    ancestors = model["pedigree"]["ancestors"]
    assert ancestors[0]["name"] == "openai-community/gpt2"
    assert ancestors[0]["purl"] == "pkg:huggingface/openai-community/gpt2"

    # Datasets: hub dataset by URL, local file hashed, local directory hashed per file.
    hub = _by_ref(bom, "dataset:stanfordnlp/imdb")
    assert hub["type"] == "data"
    assert hub["data"][0]["contents"]["url"] == (
        "https://huggingface.co/datasets/stanfordnlp/imdb"
    )
    train = _by_ref(bom, "dataset:train")
    assert (
        train["hashes"][0]["content"]
        == hashlib.sha256(data_file.read_bytes()).hexdigest()
    )
    ev = _by_ref(bom, "dataset:eval")
    assert ev["components"][0]["name"] == "part-0.jsonl"

    # Framework and library packages.
    assert _by_ref(bom, "pkg:pypi/transformers@4.44.2")["type"] == "framework"
    assert _by_ref(bom, "pkg:pypi/torch@2.4.1")["type"] == "framework"
    assert _by_ref(bom, "pkg:pypi/numpy")["type"] == "library"

    # Dependency graph: model -> base model, datasets, packages; refs all resolve.
    deps = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
    assert set(deps["model"]) >= {
        "base-model:openai-community/gpt2",
        "dataset:stanfordnlp/imdb",
        "dataset:train",
        "pkg:pypi/torch@2.4.1",
    }
    refs = all_bom_refs(bom)
    assert len(refs) == len(set(refs)), "bom-refs must be unique"
    for ref, targets in deps.items():
        assert ref in refs
        assert set(targets) <= set(refs)


def test_model_index_metrics_become_performance_metrics(tmp_path: Path) -> None:
    pytest.importorskip("yaml")  # model-index is nested YAML
    bom = _generate(tmp_path, _hf_model(tmp_path))

    validate_bom(bom)
    card = _by_ref(bom, "model")["modelCard"]
    metrics = card["quantitativeAnalysis"]["performanceMetrics"]
    assert {"type": "accuracy", "value": "0.91", "slice": "imdb"} in metrics
    assert {"type": "f1", "value": "0.9", "slice": "imdb"} in metrics


def test_minimal_directory_still_validates(tmp_path: Path) -> None:
    root = tmp_path / "plain"
    root.mkdir()
    (root / "weights.onnx").write_bytes(b"onnx")

    bom = _generate(tmp_path, root)

    validate_bom(bom)
    model = _by_ref(bom, "model")
    assert model["name"] == "plain"
    assert "licenses" not in model
    assert bom["dependencies"] == [{"ref": "model", "dependsOn": []}]


def test_cli_overrides_and_unknown_license(tmp_path: Path) -> None:
    root = tmp_path / "m"
    root.mkdir()
    (root / "w.bin").write_bytes(b"x")

    bom = _generate(
        tmp_path,
        root,
        "--name",
        "custom",
        "--license",
        "llama3",
        "--base-model",
        "meta-llama/Meta-Llama-3-8B",
    )

    validate_bom(bom)
    model = _by_ref(bom, "model")
    assert model["name"] == "custom"
    assert model["licenses"] == [{"license": {"name": "llama3"}}]
    assert model["pedigree"]["ancestors"][0]["name"] == "meta-llama/Meta-Llama-3-8B"


def test_missing_dataset_path_is_usage_error(tmp_path: Path) -> None:
    root = tmp_path / "m"
    root.mkdir()
    (root / "w.bin").write_bytes(b"x")
    out = tmp_path / "bom.json"

    rc = main(
        [
            "generate",
            "--root",
            str(root),
            "--out",
            str(out),
            "--include",
            "*",
            "--format",
            "cyclonedx",
            "--dataset",
            str(tmp_path / "missing.csv"),
        ]
    )

    assert rc == EXIT_CLI_ERROR


def test_front_matter_without_pyyaml_keeps_flat_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_import = builtins.__import__

    def no_yaml(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "yaml":
            raise ImportError("no yaml")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_yaml)
    card = parse_front_matter(MODEL_CARD)

    assert card["license"] == "apache-2.0"
    assert card["base_model"] == "openai-community/gpt2"
    assert card["datasets"] == ["stanfordnlp/imdb"]
    assert card["tags"] == ["sentiment", "demo"]
    assert "model-index" not in card  # nested: skipped, never mis-parsed


def test_simple_yaml_parser_quotes_and_nesting() -> None:
    parsed = _parse_simple_yaml(
        'license: "mit"\nwidget:\n  text: hi\nbase_model:\n- "a/b"\n- c/d\n'
    )
    assert parsed == {"license": "mit", "base_model": ["a/b", "c/d"]}


def test_no_front_matter_is_empty() -> None:
    assert parse_front_matter("# Title\nno metadata\n") == {}


def test_parse_requirements() -> None:
    pkgs = parse_requirements(
        "torch==2.4.1\nNumPy>=1.26\ntransformers[torch]==4.44.2 ; python_version>'3'\n"
        "# comment\n-r other.txt\ngit+https://x/y\n"
    )
    assert [(p.name, p.version) for p in pkgs] == [
        ("torch", "2.4.1"),
        ("NumPy", ""),
        ("transformers", "4.44.2"),
    ]
    assert pkgs[1].purl == "pkg:pypi/numpy"


def test_bom_is_deterministic_apart_from_serial_and_time(tmp_path: Path) -> None:
    root = _hf_model(tmp_path)
    a = _generate(tmp_path, root)
    b = _generate(tmp_path, root)
    for bom in (a, b):
        bom.pop("serialNumber")
        bom["metadata"].pop("timestamp")
    assert a == b
