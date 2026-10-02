"""Validate documents against the official CycloneDX 1.6 JSON schema (vendored)."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

SCHEMAS = Path(__file__).parent / "schemas" / "cyclonedx"


def _load(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
    return data


@lru_cache(maxsize=1)
def validator() -> Draft7Validator:
    registry: Registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema, default_specification=DRAFT7))
        for schema in (_load("spdx.schema.json"), _load("jsf-0.82.schema.json"))
    )
    return Draft7Validator(
        _load("bom-1.6.schema.json"),
        registry=registry,
        format_checker=Draft7Validator.FORMAT_CHECKER,
    )


def validate_bom(bom: dict[str, Any]) -> None:
    validator().validate(bom)


def all_bom_refs(node: Any) -> list[str]:
    """Every ``bom-ref`` anywhere in the document."""
    refs: list[str] = []
    if isinstance(node, dict):
        if isinstance(node.get("bom-ref"), str):
            refs.append(node["bom-ref"])
        for value in node.values():
            refs.extend(all_bom_refs(value))
    elif isinstance(node, list):
        for value in node:
            refs.extend(all_bom_refs(value))
    return refs
