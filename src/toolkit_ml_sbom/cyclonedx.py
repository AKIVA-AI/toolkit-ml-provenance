"""CycloneDX 1.6 ML-BOM output.

The model is a ``machine-learning-model`` component with a ``modelCard`` and
its files nested as ``file`` components with SHA-256 hashes. Datasets are
``data`` components (with hashes when they are local files), base models are
recorded as pedigree ancestors, and framework and library packages are
``framework`` / ``library`` components. The ``dependencies`` graph links the
model to its base models, datasets and packages.

Reference: https://cyclonedx.org/docs/1.6/json/ and
https://cyclonedx.org/capabilities/mlbom/
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from .envelope import TOOL_NAME, tree_digest
from .manifest import Manifest
from .model_info import DatasetInfo, ModelInfo, PackageInfo

SPEC_VERSION = "1.6"
SCHEMA_URL = "http://cyclonedx.org/schema/bom-1.6.schema.json"
MODEL_REF = "model"


def _prop(name: str, value: object) -> dict[str, str]:
    return {"name": name, "value": str(value)}


def _license_choice(license_id: str, spdx_id: str | None) -> list[dict[str, Any]]:
    if spdx_id:
        return [{"license": {"id": spdx_id}}]
    return [{"license": {"name": license_id}}]


def _file_component(
    entry: dict[str, Any], ref_prefix: str, extra: dict[str, str] | None = None
) -> dict[str, Any]:
    path = str(entry.get("path", ""))
    comp: dict[str, Any] = {
        "type": "file",
        "bom-ref": f"{ref_prefix}:{path}",
        "name": path,
        "hashes": [{"alg": "SHA-256", "content": str(entry.get("sha256", ""))}],
        "properties": [_prop("aibom:size", int(entry.get("size", 0)))],
    }
    for key, value in sorted((extra or {}).items()):
        comp["properties"].append(_prop(key, value))
    return comp


def _package_component(pkg: PackageInfo) -> dict[str, Any]:
    comp: dict[str, Any] = {
        "type": pkg.component_type,
        "bom-ref": pkg.bom_ref,
        "name": pkg.name,
        "purl": pkg.purl,
    }
    if pkg.version:
        comp["version"] = pkg.version
    if pkg.source:
        comp["properties"] = [_prop("aibom:source", pkg.source)]
    return comp


def _dataset_component(ds: DatasetInfo) -> dict[str, Any]:
    comp: dict[str, Any] = {
        "type": "data",
        "bom-ref": ds.bom_ref,
        "name": ds.name,
        "data": [{"type": "dataset", "name": ds.name}],
    }
    if ds.url:
        comp["data"][0]["contents"] = {"url": ds.url}
        comp["externalReferences"] = [{"type": "distribution", "url": ds.url}]
    if ds.sha256:
        comp["hashes"] = [{"alg": "SHA-256", "content": ds.sha256}]
    if ds.files:
        comp["components"] = [_file_component(e, ds.bom_ref) for e in ds.files]
        comp["properties"] = [_prop("aibom:tree-sha256", tree_digest(ds.files))]
    return comp


def _base_model_component(name: str) -> dict[str, Any]:
    return {
        "type": "machine-learning-model",
        "bom-ref": f"base-model:{name}",
        "name": name,
        "purl": f"pkg:huggingface/{name}",
    }


def _model_card(info: ModelInfo) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if info.approach:
        params["approach"] = {"type": info.approach}
    if info.task:
        params["task"] = info.task
    if info.architecture_family:
        params["architectureFamily"] = info.architecture_family
    if info.model_architecture:
        params["modelArchitecture"] = info.model_architecture
    if info.datasets:
        params["datasets"] = [{"ref": ds.bom_ref} for ds in info.datasets]
    card: dict[str, Any] = {"bom-ref": "model-card"}
    if params:
        card["modelParameters"] = params
    if info.metrics:
        metrics = []
        for m in info.metrics:
            metric = {"type": str(m["type"]), "value": str(m["value"])}
            if m.get("slice"):
                metric["slice"] = str(m["slice"])
            metrics.append(metric)
        card["quantitativeAnalysis"] = {"performanceMetrics": metrics}
    if info.card_properties:
        card["properties"] = [
            _prop(k, v) for k, v in sorted(info.card_properties.items())
        ]
    return card


def manifest_to_cyclonedx(
    manifest: Manifest,
    *,
    tool_version: str = "0.0.0",
    model: ModelInfo | None = None,
) -> dict[str, Any]:
    """Build a CycloneDX 1.6 ML-BOM for the model described by ``manifest``.

    Args:
        manifest: The native manifest (file hashes of the model directory).
        tool_version: Version of this tool, recorded in ``metadata.tools``.
        model: What is known about the model (see :mod:`.model_info`). When
            omitted, the model is named ``model`` and only its files are listed.
    """
    info = model or ModelInfo(name="model")
    timestamp = (
        datetime.fromtimestamp(manifest.created_ts, tz=timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    model_props = [_prop("aibom:tree-sha256", tree_digest(manifest.entries))]
    for fmt in info.serialization_formats:
        model_props.append(_prop("aibom:serialization-format", fmt))
    for key, value in sorted(info.properties.items()):
        model_props.append(_prop(key, value))

    model_comp: dict[str, Any] = {
        "type": "machine-learning-model",
        "bom-ref": MODEL_REF,
        "name": info.name,
    }
    if info.version:
        model_comp["version"] = info.version
    if info.description:
        model_comp["description"] = info.description
    if info.license:
        model_comp["licenses"] = _license_choice(info.license, info.spdx_license_id)
    if info.purl:
        model_comp["purl"] = info.purl
    if info.source_url:
        model_comp["externalReferences"] = [
            {"type": "distribution", "url": info.source_url}
        ]
    if info.base_models:
        model_comp["pedigree"] = {
            "ancestors": [_base_model_component(b) for b in info.base_models]
        }
    model_comp["modelCard"] = _model_card(info)
    model_comp["components"] = [
        _file_component(e, "file", info.file_properties.get(str(e.get("path", ""))))
        for e in manifest.entries
    ]
    unsafe = sum(
        1
        for props in info.file_properties.values()
        if props.get("aibom:pickle-scan") in ("dangerous", "unknown", "error")
    )
    if info.file_properties:
        model_props.append(_prop("aibom:pickle-files-flagged", unsafe))
    model_comp["properties"] = model_props

    components: list[dict[str, Any]] = [model_comp]
    components += [_dataset_component(ds) for ds in info.datasets]
    components += [_package_component(p) for p in info.packages]

    dependency_refs = sorted(
        [f"base-model:{b}" for b in info.base_models]
        + [ds.bom_ref for ds in info.datasets]
        + [p.bom_ref for p in info.packages]
    )
    dependencies = [{"ref": MODEL_REF, "dependsOn": dependency_refs}]
    dependencies += [{"ref": ref, "dependsOn": []} for ref in dependency_refs]

    metadata: dict[str, Any] = {
        "timestamp": timestamp,
        "tools": {
            "components": [
                {"type": "application", "name": TOOL_NAME, "version": tool_version}
            ]
        },
        "properties": [],
    }
    if manifest.git_commit:
        metadata["properties"].append(
            _prop("provenance:git-commit", manifest.git_commit)
        )
    for key, value in sorted(manifest.meta.items()):
        metadata["properties"].append(_prop(f"custom:{key}", value))
    if not metadata["properties"]:
        del metadata["properties"]

    return {
        "$schema": SCHEMA_URL,
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": components,
        "dependencies": dependencies,
    }


def cyclonedx_to_json_string(cdx: dict[str, Any]) -> str:
    """Serialize a CycloneDX dict to a formatted JSON string (2-space indent)."""
    return json.dumps(cdx, indent=2, sort_keys=False)
