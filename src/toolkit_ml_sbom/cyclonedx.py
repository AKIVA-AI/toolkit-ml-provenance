"""CycloneDX SBOM format output.

Converts internal Manifest to CycloneDX 1.5 JSON format.
Reference: https://cyclonedx.org/docs/1.5/json/
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from .manifest import Manifest


def manifest_to_cyclonedx(
    manifest: Manifest, *, tool_version: str = "0.1.0"
) -> dict[str, Any]:
    """Convert a Manifest to CycloneDX 1.5 JSON format.

    Args:
        manifest: The internal manifest to convert.
        tool_version: Version of this tool to embed in metadata.

    Returns:
        CycloneDX 1.5 compliant JSON-serializable dictionary.
    """
    serial_number = f"urn:uuid:{uuid.uuid4()}"
    timestamp = datetime.fromtimestamp(manifest.created_ts, tz=timezone.utc).isoformat()

    components: list[dict[str, Any]] = []
    for entry in manifest.entries:
        path = str(entry.get("path", ""))
        sha256 = str(entry.get("sha256", ""))
        size = entry.get("size", 0)

        # Generate a deterministic BOM ref from the path
        bom_ref = hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]

        # Generate purl for data component
        purl = f"pkg:generic/{path.replace('/', '%2F')}?checksum=sha256:{sha256}"

        component: dict[str, Any] = {
            "type": "data",
            "bom-ref": bom_ref,
            "name": path,
            "version": "",
            "purl": purl,
            "hashes": [
                {
                    "alg": "SHA-256",
                    "content": sha256,
                }
            ],
            "properties": [
                {"name": "file:size", "value": str(size)},
            ],
        }
        components.append(component)

    metadata: dict[str, Any] = {
        "timestamp": timestamp,
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": "toolkit-ml-provenance-sbom",
                    "version": tool_version,
                }
            ]
        },
        "properties": [],
    }

    # Add git commit to metadata if present
    if manifest.git_commit:
        metadata["properties"].append(
            {"name": "provenance:git-commit", "value": manifest.git_commit}
        )

    # Add custom metadata
    for key, value in sorted(manifest.meta.items()):
        metadata["properties"].append({"name": f"custom:{key}", "value": value})

    cdx: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": metadata,
        "components": components,
    }

    return cdx


def cyclonedx_to_json_string(cdx: dict[str, Any]) -> str:
    """Serialize CycloneDX dict to formatted JSON string.

    Args:
        cdx: CycloneDX dictionary from manifest_to_cyclonedx.

    Returns:
        JSON string with 2-space indent.
    """
    return json.dumps(cdx, indent=2, sort_keys=False)
