#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 SBOM from the committed Cargo graph.

Usage:
    python scripts/sbom.py --output dist/active-infinity-2.0.7.cdx.json
    python scripts/sbom.py --check dist/active-infinity-2.0.7.cdx.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def metadata(root: Path) -> dict:
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.exit(result.stderr)
    return json.loads(result.stdout)


def purl(name: str, version: str) -> str:
    return f"pkg:cargo/{name}@{version}"


def build(root: Path) -> dict:
    data = metadata(root)
    root_package = next(
        (p for p in data["packages"] if p["id"] == data["resolve"]["root"]), None
    )
    if root_package is None:
        sys.exit("the cargo metadata graph has no root package")

    components = []
    for package in sorted(data["packages"], key=lambda p: (p["name"], p["version"])):
        if package["id"] == root_package["id"]:
            continue
        components.append(
            {
                "type": "library",
                "bom-ref": purl(package["name"], package["version"]),
                "name": package["name"],
                "version": package["version"],
                "purl": purl(package["name"], package["version"]),
                "scope": "required",
            }
        )

    by_id = {package["id"]: package for package in data["packages"]}
    dependencies = []
    for node in data["resolve"]["nodes"]:
        package = by_id.get(node["id"])
        if package is None:
            sys.exit(f"metadata graph references unknown package {node['id']}")
        depends_on = []
        for dep in node.get("dependencies", []):
            target = by_id.get(dep)
            if target is None:
                sys.exit(f"metadata graph has a dangling dependency {dep}")
            depends_on.append(purl(target["name"], target["version"]))
        dependencies.append(
            {
                "ref": purl(package["name"], package["version"]),
                "dependsOn": depends_on,
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "library",
                "bom-ref": purl(root_package["name"], root_package["version"]),
                "name": root_package["name"],
                "version": root_package["version"],
                "purl": purl(root_package["name"], root_package["version"]),
            }
        },
        "components": components,
        "dependencies": dependencies,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", help="write the SBOM here")
    parser.add_argument("--check", help="validate an existing SBOM file")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent

    if args.check:
        document = json.loads(Path(args.check).read_text(encoding="utf-8"))
        required = {"bomFormat", "specVersion", "version", "metadata", "components"}
        missing = required - document.keys()
        if missing:
            sys.exit(f"SBOM is missing {sorted(missing)}")
        if document["bomFormat"] != "CycloneDX" or document["specVersion"] != "1.5":
            sys.exit("not a CycloneDX 1.5 document")
        root_component = document["metadata"]["component"]
        if not root_component.get("purl", "").startswith("pkg:cargo/"):
            sys.exit("the root component has no cargo purl")
        if not document["components"]:
            sys.exit("the SBOM has no dependencies")
        print(
            f"SBOM ok: {root_component['name']} {root_component['version']}, "
            f"{len(document['components'])} components"
        )
        return 0

    document = build(root)
    rendered = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8", newline="\n")
        print(f"wrote {output} ({len(document['components'])} components)")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
