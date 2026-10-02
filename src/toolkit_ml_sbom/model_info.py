"""What the ML-BOM says about a model, and how it is derived from a model directory.

Everything here is read from files that commonly ship with a model; nothing is
guessed:

* ``config.json`` (Hugging Face): ``model_type`` (architecture family),
  ``architectures[0]`` (model architecture), ``transformers_version``.
* ``README.md`` YAML front matter (Hugging Face model card): ``license``,
  ``base_model``, ``datasets``, ``pipeline_tag`` (task), ``library_name``,
  ``language``, ``tags`` and ``model-index`` results (metrics).
* ``requirements.txt``: Python packages, pinned versions when given.
* File extensions: serialization formats (``safetensors``, ``pickle`` ...).

The front matter is parsed with PyYAML when it is installed (it comes with the
``hf`` and ``mlflow`` extras). Without it, a small parser reads flat keys and
lists; nested sections such as ``model-index`` are then skipped.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .hashing import sha256_file

# Hugging Face license identifiers that map onto SPDX identifiers.
_SPDX_LICENSES = {
    "apache-2.0": "Apache-2.0",
    "mit": "MIT",
    "bsd": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "cc0-1.0": "CC0-1.0",
    "cc-by-4.0": "CC-BY-4.0",
    "cc-by-sa-4.0": "CC-BY-SA-4.0",
    "cc-by-nc-4.0": "CC-BY-NC-4.0",
    "cc-by-nc-sa-4.0": "CC-BY-NC-SA-4.0",
    "cc-by-nc-nd-4.0": "CC-BY-NC-ND-4.0",
    "gpl-2.0": "GPL-2.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "lgpl-3.0": "LGPL-3.0-only",
    "agpl-3.0": "AGPL-3.0-only",
    "mpl-2.0": "MPL-2.0",
    "unlicense": "Unlicense",
    "artistic-2.0": "Artistic-2.0",
    "openrail": "",
    "bigscience-openrail-m": "",
    "creativeml-openrail-m": "",
}

# Packages recorded as CycloneDX "framework" rather than "library".
_FRAMEWORKS = {
    "torch",
    "tensorflow",
    "jax",
    "flax",
    "keras",
    "transformers",
    "diffusers",
    "onnxruntime",
    "scikit-learn",
    "xgboost",
    "lightgbm",
    "catboost",
    "vllm",
    "mlflow",
}

# File extension -> serialization format.
_FORMATS = {
    ".safetensors": "safetensors",
    ".bin": "pytorch-pickle",
    ".pt": "pytorch-pickle",
    ".pth": "pytorch-pickle",
    ".ckpt": "pytorch-pickle",
    ".pkl": "pickle",
    ".pickle": "pickle",
    ".joblib": "joblib-pickle",
    ".onnx": "onnx",
    ".gguf": "gguf",
    ".h5": "hdf5",
    ".keras": "keras",
    ".tflite": "tflite",
    ".msgpack": "flax-msgpack",
    ".npz": "numpy",
    ".npy": "numpy",
}


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._/-]+", "-", text).strip("-") or "item"


@dataclass
class PackageInfo:
    name: str
    version: str = ""
    source: str = ""

    @property
    def component_type(self) -> str:
        return "framework" if _normalize(self.name) in _FRAMEWORKS else "library"

    @property
    def purl(self) -> str:
        base = f"pkg:pypi/{_normalize(self.name)}"
        return f"{base}@{self.version}" if self.version else base

    @property
    def bom_ref(self) -> str:
        return self.purl


@dataclass
class DatasetInfo:
    name: str
    url: str = ""
    sha256: str = ""
    files: list[dict[str, Any]] = field(default_factory=list)

    @property
    def bom_ref(self) -> str:
        return f"dataset:{_slug(self.name)}"


@dataclass
class ModelInfo:
    name: str
    version: str = ""
    description: str = ""
    license: str = ""
    purl: str = ""
    source_url: str = ""
    task: str = ""
    approach: str = ""
    architecture_family: str = ""
    model_architecture: str = ""
    base_models: list[str] = field(default_factory=list)
    datasets: list[DatasetInfo] = field(default_factory=list)
    packages: list[PackageInfo] = field(default_factory=list)
    metrics: list[dict[str, Any]] = field(default_factory=list)
    serialization_formats: list[str] = field(default_factory=list)
    properties: dict[str, str] = field(default_factory=dict)
    card_properties: dict[str, str] = field(default_factory=dict)
    # Extra properties for individual model files, keyed by manifest path.
    file_properties: dict[str, dict[str, str]] = field(default_factory=dict)

    @property
    def spdx_license_id(self) -> str | None:
        return _SPDX_LICENSES.get(self.license.lower()) or None

    def add_package(self, pkg: PackageInfo) -> None:
        for existing in self.packages:
            if _normalize(existing.name) == _normalize(pkg.name):
                if not existing.version and pkg.version:
                    existing.version, existing.source = pkg.version, pkg.source
                return
        self.packages.append(pkg)

    def add_dataset(self, ds: DatasetInfo) -> None:
        if all(d.bom_ref != ds.bom_ref for d in self.datasets):
            self.datasets.append(ds)


# --- front matter ------------------------------------------------------------


def _front_matter_text(readme: str) -> str | None:
    lines = readme.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            return "\n".join(lines[1:i])
    return None


def _scalar(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    return text


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    """Flat ``key: value`` and ``key:`` + ``- item`` lists; nested blocks skipped."""
    out: dict[str, Any] = {}
    key: str | None = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw[0] not in " \t-":
            key = None
            if ":" not in raw:
                continue
            k, _, v = raw.partition(":")
            k, v = k.strip(), v.strip()
            if v.startswith("[") and v.endswith("]"):
                out[k] = [_scalar(x) for x in v[1:-1].split(",") if x.strip()]
            elif v:
                out[k] = _scalar(v)
            else:
                key = k
                out[k] = []
        elif key is not None and raw.lstrip().startswith("- "):
            item = raw.lstrip()[2:]
            if ":" in item and not item.startswith(("'", '"')):
                out.pop(key, None)  # a list of mappings: nested, skip
                key = None
                continue
            value = out.get(key)
            if isinstance(value, list):
                value.append(_scalar(item))
        elif key is not None:
            out.pop(key, None)  # nested mapping: skip
            key = None
    return out


def parse_front_matter(readme: str) -> dict[str, Any]:
    """Parse a model card's YAML front matter (``---`` delimited)."""
    text = _front_matter_text(readme)
    if text is None:
        return {}
    try:
        import yaml
    except ImportError:
        return _parse_simple_yaml(text)
    data = yaml.safe_load(text)
    return data if isinstance(data, dict) else {}


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v is not None and str(v)]
    return [str(value)] if str(value) else []


def _metrics_from_model_index(model_index: Any) -> list[dict[str, Any]]:
    metrics: list[dict[str, Any]] = []
    if not isinstance(model_index, list):
        return metrics
    for entry in model_index:
        if not isinstance(entry, dict):
            continue
        for result in entry.get("results") or []:
            if not isinstance(result, dict):
                continue
            dataset = result.get("dataset") or {}
            slice_name = (
                str(dataset.get("name") or dataset.get("type") or "")
                if isinstance(dataset, dict)
                else ""
            )
            for m in result.get("metrics") or []:
                if isinstance(m, dict) and m.get("type") and "value" in m:
                    metrics.append(
                        {"type": m["type"], "value": m["value"], "slice": slice_name}
                    )
    return metrics


def apply_model_card(info: ModelInfo, card: dict[str, Any]) -> None:
    """Fill ``info`` from Hugging Face model-card metadata."""
    if card.get("license") and not info.license:
        info.license = str(card["license"])
    for base in _as_list(card.get("base_model")):
        if base not in info.base_models:
            info.base_models.append(base)
    for ds in _as_list(card.get("datasets")):
        info.add_dataset(
            DatasetInfo(name=ds, url=f"https://huggingface.co/datasets/{ds}")
        )
    if card.get("pipeline_tag") and not info.task:
        info.task = str(card["pipeline_tag"])
    if card.get("library_name"):
        info.add_package(PackageInfo(str(card["library_name"]), source="model card"))
    if card.get("language"):
        info.card_properties["hf:language"] = ",".join(_as_list(card["language"]))
    if card.get("tags"):
        info.card_properties["hf:tags"] = ",".join(_as_list(card["tags"]))
    info.metrics.extend(_metrics_from_model_index(card.get("model-index")))


# --- requirements --------------------------------------------------------------

_REQ = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(==|>=|~=)?\s*([^\s;,#]*)"
)


def parse_requirements(
    text: str, source: str = "requirements.txt"
) -> list[PackageInfo]:
    """Python packages from a requirements file; only ``==`` pins give a version."""
    packages: list[PackageInfo] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http:", "https:", "file:")):
            continue
        m = _REQ.match(line)
        if not m:
            continue
        name, op, version = m.group(1), m.group(2), m.group(3)
        packages.append(PackageInfo(name, version if op == "==" else "", source))
    return packages


# --- directory derivation ------------------------------------------------------------


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def derive_model_info(
    root: Path, entries: list[dict[str, Any]], *, name: str | None = None
) -> ModelInfo:
    """Derive a :class:`ModelInfo` from the files of a model directory."""
    info = ModelInfo(name=name or root.resolve().name)

    config = _read_json(root / "config.json")
    if config:
        if config.get("model_type"):
            info.architecture_family = str(config["model_type"])
        archs = config.get("architectures")
        if isinstance(archs, list) and archs:
            info.model_architecture = str(archs[0])
        if config.get("transformers_version"):
            info.add_package(
                PackageInfo(
                    "transformers", str(config["transformers_version"]), "config.json"
                )
            )
        if config.get("torch_dtype"):
            info.properties["hf:torch_dtype"] = str(config["torch_dtype"])

    readme = root / "README.md"
    if readme.is_file():
        try:
            apply_model_card(
                info, parse_front_matter(readme.read_text(encoding="utf-8"))
            )
        except (OSError, UnicodeDecodeError, ValueError):
            pass

    reqs = root / "requirements.txt"
    if reqs.is_file():
        for pkg in parse_requirements(reqs.read_text(encoding="utf-8")):
            info.add_package(pkg)

    formats = sorted(
        {
            _FORMATS[Path(str(e.get("path", ""))).suffix.lower()]
            for e in entries
            if Path(str(e.get("path", ""))).suffix.lower() in _FORMATS
        }
    )
    info.serialization_formats = formats
    return info


def local_dataset(spec: str) -> DatasetInfo:
    """A dataset from ``[name=]path-or-url``; local files and directories are hashed."""
    name, sep, target = spec.partition("=")
    if not sep:
        name, target = "", spec
    if target.startswith(("http://", "https://", "hf://")):
        return DatasetInfo(
            name=name or target.rstrip("/").rsplit("/", 1)[-1], url=target
        )
    path = Path(target)
    if path.is_file():
        return DatasetInfo(name=name or path.name, sha256=sha256_file(path))
    if path.is_dir():
        root = path.resolve()
        files = [
            {
                "path": f.relative_to(root).as_posix(),
                "sha256": sha256_file(f),
                "size": f.stat().st_size,
            }
            for f in sorted(root.rglob("*"))
            if f.is_file()
        ]
        return DatasetInfo(name=name or root.name, files=files)
    raise ValueError(f"dataset not found (expected a file, directory or URL): {target}")
