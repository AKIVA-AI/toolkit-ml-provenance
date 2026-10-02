"""Importers: build the ML-BOM model description from a Hugging Face Hub repo or
a local MLflow run directory.

* Hugging Face (``hf`` extra, ``huggingface_hub``): downloads a pinned commit
  of a model repo into an empty directory, checks every LFS file against the
  SHA-256 the Hub declares, and records the repo, commit and model-card data.
* MLflow (``mlflow`` extra for full ``MLmodel`` parsing; the flat parts need no
  dependency): reads a run directory of MLflow's file store
  (``mlruns/<experiment_id>/<run_id>/``): ``meta.yaml``, ``params/``,
  ``metrics/``, ``tags/`` and the logged model under ``artifacts/``.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .hashing import sha256_file
from .model_info import (
    ModelInfo,
    PackageInfo,
    _parse_simple_yaml,
    apply_model_card,
    parse_requirements,
)

# --- Hugging Face ----------------------------------------------------------------


@dataclass
class HfSnapshot:
    repo_id: str
    commit: str
    card: dict[str, Any] = field(default_factory=dict)
    lfs_sha256: dict[str, str] = field(default_factory=dict)
    files: list[str] = field(default_factory=list)


def _require_hf() -> Any:
    try:
        import huggingface_hub
    except ImportError as exc:
        raise RuntimeError(
            "Hugging Face import needs the 'hf' extra: "
            'pip install "toolkit-ml-provenance[hf]"'
        ) from exc
    return huggingface_hub


def fetch_hf_model(
    repo_id: str,
    dest: Path,
    *,
    revision: str | None = None,
    allow_patterns: list[str] | None = None,
    token: str | None = None,
) -> HfSnapshot:
    """Download ``repo_id`` at a pinned commit into ``dest`` (must be empty).

    Every downloaded LFS file is re-hashed and compared with the SHA-256 the Hub
    declares for it; a mismatch raises ``ValueError``.
    """
    hf = _require_hf()
    if dest.exists() and any(dest.iterdir()):
        raise ValueError(f"download directory must be empty: {dest}")
    api = hf.HfApi(token=token)
    info = api.model_info(repo_id, revision=revision, files_metadata=True)
    commit = str(info.sha)
    lfs = {
        str(s.rfilename): str(s.lfs.sha256)
        for s in (info.siblings or [])
        if getattr(s, "lfs", None) is not None and getattr(s.lfs, "sha256", None)
    }
    dest.mkdir(parents=True, exist_ok=True)
    hf.snapshot_download(
        repo_id=repo_id,
        revision=commit,
        local_dir=str(dest),
        allow_patterns=allow_patterns,
        token=token,
    )
    # huggingface_hub keeps resume metadata here; it is not part of the model.
    shutil.rmtree(dest / ".cache", ignore_errors=True)

    files = sorted(
        p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file()
    )
    for rel in files:
        expected = lfs.get(rel)
        if expected and sha256_file(dest / rel) != expected:
            raise ValueError(f"downloaded {rel} does not match the Hub's SHA-256")
    card_data = getattr(info, "card_data", None)
    card = card_data.to_dict() if card_data is not None else {}
    return HfSnapshot(
        repo_id,
        commit,
        card,
        {k: v for k, v in lfs.items() if k in files},
        files,
    )


def apply_hf_snapshot(info: ModelInfo, snap: HfSnapshot) -> None:
    """Record Hub provenance on a :class:`ModelInfo` derived from the download."""
    info.purl = f"pkg:huggingface/{snap.repo_id}@{snap.commit}"
    info.source_url = f"https://huggingface.co/{snap.repo_id}"
    if not info.version:
        info.version = snap.commit
    info.properties["hf:repo"] = snap.repo_id
    info.properties["hf:commit"] = snap.commit
    info.properties["hf:lfs-files-verified"] = str(len(snap.lfs_sha256))
    apply_model_card(info, snap.card)


# --- MLflow ------------------------------------------------------------------------

# MLmodel flavor -> (package, version key in the flavor config)
_FLAVOR_PACKAGES = {
    "sklearn": ("scikit-learn", "sklearn_version"),
    "pytorch": ("torch", "pytorch_version"),
    "tensorflow": ("tensorflow", "tensorflow_version"),
    "keras": ("keras", "keras_version"),
    "xgboost": ("xgboost", "xgb_version"),
    "lightgbm": ("lightgbm", "lgb_version"),
    "transformers": ("transformers", "transformers_version"),
    "onnx": ("onnx", "onnx_version"),
    "catboost": ("catboost", "cb_version"),
}


@dataclass
class MlflowRun:
    run_dir: Path
    meta: dict[str, Any]
    params: dict[str, str]
    metrics: dict[str, str]
    tags: dict[str, str]
    model_dirs: list[Path]


def _load_yaml(text: str) -> dict[str, Any]:
    try:
        import yaml
    except ImportError:
        return _parse_simple_yaml(text)
    data = yaml.safe_load(text)
    return data if isinstance(data, dict) else {}


def _read_kv_dir(directory: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if directory.is_dir():
        for f in sorted(p for p in directory.rglob("*") if p.is_file()):
            out[f.relative_to(directory).as_posix()] = f.read_text(
                encoding="utf-8"
            ).strip()
    return out


def read_mlflow_run(run_dir: Path) -> MlflowRun:
    """Read an MLflow file-store run directory (the one holding ``meta.yaml``)."""
    meta_path = run_dir / "meta.yaml"
    if not meta_path.is_file():
        raise ValueError(f"not an MLflow run directory (no meta.yaml): {run_dir}")
    meta = _load_yaml(meta_path.read_text(encoding="utf-8"))
    metrics: dict[str, str] = {}
    for name, text in _read_kv_dir(run_dir / "metrics").items():
        # Each line is "<timestamp> <value> <step>"; keep the latest step.
        rows = [line.split() for line in text.splitlines() if line.strip()]
        rows = [r for r in rows if len(r) >= 2]
        if rows:
            latest = max(
                rows, key=lambda r: (int(r[2]) if len(r) > 2 else 0, int(r[0]))
            )
            metrics[name] = latest[1]
    return MlflowRun(
        run_dir=run_dir,
        meta=meta,
        params=_read_kv_dir(run_dir / "params"),
        metrics=metrics,
        tags=_read_kv_dir(run_dir / "tags"),
        model_dirs=_logged_model_dirs(run_dir, str(meta.get("run_id") or run_dir.name)),
    )


def _logged_model_dirs(run_dir: Path, run_id: str) -> list[Path]:
    """Directories holding an ``MLmodel`` file that this run logged.

    MLflow 2 stores them under the run's ``artifacts/``; MLflow 3 stores logged
    models beside the runs, in ``<experiment>/models/<model_id>/artifacts``, with
    ``source_run_id`` in the model's ``meta.yaml``.
    """
    dirs: list[Path] = []
    artifacts = run_dir / "artifacts"
    if artifacts.is_dir():
        dirs += sorted(p.parent for p in artifacts.rglob("MLmodel"))
    models = run_dir.parent / "models"
    if models.is_dir():
        for meta_path in sorted(models.glob("*/meta.yaml")):
            model_meta = _load_yaml(meta_path.read_text(encoding="utf-8"))
            art = meta_path.parent / "artifacts"
            if (
                str(model_meta.get("source_run_id")) == run_id
                and (art / "MLmodel").is_file()
            ):
                dirs.append(art)
    return dirs


def apply_mlflow_run(info: ModelInfo, run: MlflowRun, model_dir: Path | None) -> None:
    """Record an MLflow run's hyperparameters, metrics, tags and model flavors."""
    run_id = str(run.meta.get("run_id") or run.run_dir.name)
    info.properties["mlflow:run_id"] = run_id
    if run.meta.get("experiment_id") is not None:
        info.properties["mlflow:experiment_id"] = str(run.meta["experiment_id"])
    if run.meta.get("run_name"):
        info.properties["mlflow:run_name"] = str(run.meta["run_name"])
    commit = run.tags.get("mlflow.source.git.commit")
    if commit:
        info.properties["mlflow:source-git-commit"] = commit
    if run.tags.get("mlflow.source.name"):
        info.properties["mlflow:source-name"] = run.tags["mlflow.source.name"]
    for key, value in run.params.items():
        info.card_properties[f"mlflow:param:{key}"] = value
    for key, value in run.metrics.items():
        info.metrics.append({"type": key, "value": value, "slice": ""})
    if not info.version:
        info.version = run_id

    if model_dir is None:
        return
    mlmodel = model_dir / "MLmodel"
    if mlmodel.is_file():
        spec = _load_yaml(mlmodel.read_text(encoding="utf-8"))
        flavors = spec.get("flavors")
        if isinstance(flavors, dict):
            for flavor, conf in sorted(flavors.items()):
                info.card_properties.setdefault("mlflow:flavors", "")
                info.card_properties["mlflow:flavors"] = ",".join(
                    filter(None, [info.card_properties["mlflow:flavors"], flavor])
                )
                if flavor in _FLAVOR_PACKAGES and isinstance(conf, dict):
                    pkg, key = _FLAVOR_PACKAGES[flavor]
                    info.add_package(
                        PackageInfo(pkg, str(conf.get(key) or ""), "MLmodel")
                    )
                if flavor == "python_function" and isinstance(conf, dict):
                    if conf.get("python_version"):
                        info.properties["mlflow:python_version"] = str(
                            conf["python_version"]
                        )
        if spec.get("mlflow_version"):
            info.add_package(
                PackageInfo("mlflow", str(spec["mlflow_version"]), "MLmodel")
            )
        if spec.get("model_uuid"):
            info.properties["mlflow:model_uuid"] = str(spec["model_uuid"])
    reqs = model_dir / "requirements.txt"
    if reqs.is_file():
        for req in parse_requirements(
            reqs.read_text(encoding="utf-8"), "requirements.txt"
        ):
            info.add_package(req)
