#!/usr/bin/env python3
"""Export package license metadata from a CycloneDX JSON container SBOM.

The CSV is an audit index, not a legal conclusion. License strings collected
from distro package metadata may describe licenses of individual files within
a source package; they are listed as a set, not treated as SPDX OR choices.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any


# Syft identifies FFmpeg libraries bundled in the opencv-python-headless wheel
# as a separate binary component. The upstream wheel project states that its
# bundled FFmpeg is LGPLv2.1. Python runtime licensing is PSF-2.0.
MANUAL_LICENSES = {
    ("ffmpeg", "8.1.1"): ("LGPL-2.1", "opencv-python wheel licensing notice"),
    ("python", "3.12.16"): ("PSF-2.0", "Python Software Foundation License"),
    ("node", "22.23.5"): ("MIT", "Node.js upstream LICENSE"),
    ("github.com/evanw/esbuild", "v0.0.0-20251101233416-208f539945b1"): (
        "MIT", "esbuild upstream LICENSE"
    ),
    ("golang.org/x/sys", "v0.0.0-20220715151400-c0bba94af5f8"): (
        "BSD-3-Clause", "golang.org/x/sys upstream LICENSE"
    ),
}
INTERNAL_COMPONENTS = {
    "editflow-story-graph-explorer": (
        "first-party application package; not a third-party dependency"
    ),
}


def license_labels(component: dict[str, Any]) -> list[str]:
    labels: set[str] = set()
    for item in component.get("licenses") or []:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("expression"), str):
            labels.add(item["expression"])
        license_data = item.get("license")
        if isinstance(license_data, dict):
            label = license_data.get("id") or license_data.get("name") or license_data.get("url")
            if isinstance(label, str) and label.strip():
                labels.add(label.strip())
    return sorted(labels)


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: sbom_license_inventory.py SBOM.json OUTPUT.csv")
    source, destination = map(Path, sys.argv[1:])
    bom = json.loads(source.read_text(encoding="utf-8"))
    components = bom.get("components")
    if not isinstance(components, list):
        raise SystemExit("CycloneDX document has no components array")

    destination.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for component in components:
        if not isinstance(component, dict):
            continue
        component_type = component.get("type", "")
        # Syft emits many file-level components; they are provenance evidence,
        # not separately installable packages. Drop binary false positives
        # without a package URL (e.g. pip's bundled Windows launcher files).
        if component_type == "file":
            continue
        if component_type == "application" and not component.get("purl"):
            continue
        if component_type not in {"library", "application", "operating-system"}:
            continue

        name = component.get("name", "")
        version = component.get("version", "")
        labels = license_labels(component)
        internal_basis = INTERNAL_COMPONENTS.get(name.lower())
        manual = MANUAL_LICENSES.get((name.lower(), version))
        if internal_basis:
            license_text = ""
            basis = internal_basis
            status = "internal_project"
        elif manual:
            license_text, basis = manual
            status = "manual_override"
        elif labels:
            # Keep the metadata values distinct. They may represent multiple
            # file-level licenses in a Debian source package, not alternatives.
            license_text = "; ".join(labels)
            basis = "CycloneDX/Syft package metadata"
            status = "metadata_present"
        elif component_type == "operating-system":
            license_text = ""
            basis = "distribution aggregate; see individual OS package rows"
            status = "aggregate_distribution"
        else:
            license_text = ""
            basis = "missing from SBOM metadata"
            status = "review_required"

        rows.append({
            "name": name,
            "version": version,
            "type": component_type,
            "purl": component.get("purl", ""),
            "license_metadata": license_text,
            "license_basis": basis,
            "license_review_status": status,
        })

    rows.sort(key=lambda row: (row["type"], row["name"].lower(), row["version"]))
    fields = [
        "name", "version", "type", "purl", "license_metadata",
        "license_basis", "license_review_status",
    ]
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    counts: dict[str, int] = {}
    for row in rows:
        status = row["license_review_status"]
        counts[status] = counts.get(status, 0) + 1
    print(f"SBOM package components: {len(rows)}; license review statuses: {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
