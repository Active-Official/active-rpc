#!/usr/bin/env python3
"""Presentation gate: README theme pairs, assets, manifest and logo integrity.

Fails when a README image target is missing or unlisted, a theme pair is
duplicated or has the wrong luminance relationship, an asset is blank or
oversized, the manifest drifts or duplicates a row, an SVG declares the wrong
size, or the Active mark is not the approved byte-identical source.
"""

from __future__ import annotations

import hashlib
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "docs/assets"
README = ROOT / "README.md"
MANIFEST = ASSETS / "ASSETS-MANIFEST.md"
APPROVED_MARK = "af10d633e0c19b6ef069ff29820c84b355006ce384050d140fcf52a20e9ca1d2"
MAX_BYTES = 600 * 1024

errors: list[str] = []


def fail(message: str) -> None:
    errors.append(message)


def pixels(path: Path) -> list[tuple[int, int, int]]:
    with Image.open(path) as image:
        rgb = image.convert("RGB").resize((64, 64))
        if hasattr(rgb, "get_flattened_data"):
            return list(rgb.get_flattened_data())
        return [tuple(pixel) for pixel in rgb.getdata()]


def mean_luminance(path: Path) -> float:
    values = pixels(path)
    return sum(sum(pixel) for pixel in values) / (len(values) * 3)


def variance(path: Path) -> float:
    values = [sum(pixel) / 3 for pixel in pixels(path)]
    mean = sum(values) / len(values)
    return sum((value - mean) ** 2 for value in values) / len(values)


def check_mark() -> None:
    mark = ASSETS / "active-mark.png"
    if not mark.exists():
        fail("missing docs/assets/active-mark.png")
        return
    if hashlib.sha256(mark.read_bytes()).hexdigest() != APPROVED_MARK:
        fail("active-mark.png is not the approved byte-identical source")


def parse_manifest() -> list[tuple[str, str]]:
    if not MANIFEST.exists():
        fail("missing docs/assets/ASSETS-MANIFEST.md")
        return []
    rows: list[tuple[str, str]] = []
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        match = re.match(r"\|\s*`([^`]+)`\s*\|\s*([^|]+)\|\s*([^|]+)\|", line)
        if match:
            rows.append((match.group(1), match.group(3).strip()))
    names = [name for name, _ in rows]
    for name in sorted({name for name in names if names.count(name) > 1}):
        fail(f"manifest duplicates {name}")
    return rows


def check_assets(rows: list[tuple[str, str]]) -> None:
    for name, dimensions in rows:
        path = ASSETS / name
        if not path.exists():
            fail(f"manifest lists missing asset {name}")
            continue
        if path.stat().st_size > MAX_BYTES:
            fail(f"{name} is {path.stat().st_size} bytes (budget {MAX_BYTES})")
        expected = re.search(r"(\d+)x(\d+)", dimensions)
        if not expected:
            continue
        want = (int(expected.group(1)), int(expected.group(2)))
        if name.endswith(".png"):
            with Image.open(path) as image:
                if image.size != want:
                    fail(f"{name} is {image.size}, manifest says {want}")
            if variance(path) < 20:
                fail(f"{name} is visually blank (variance {variance(path):.1f})")
        elif name.endswith(".svg"):
            try:
                root = ET.parse(path).getroot()
            except ET.ParseError as error:
                fail(f"{name} is not valid XML: {error}")
                continue
            width = root.attrib.get("width", "")
            height = root.attrib.get("height", "")
            match = re.match(r"(\d+)", width), re.match(r"(\d+)", height)
            if (
                not all(match)
                or (int(match[0].group(1)), int(match[1].group(1))) != want
            ):
                fail(f"{name} SVG size {width}x{height}, manifest says {dimensions}")


def check_pairs() -> None:
    for light in sorted(ASSETS.glob("*-light.png")):
        dark = Path(str(light).replace("-light.png", "-dark.png"))
        if not dark.exists():
            fail(f"{light.name} has no dark pair")
            continue
        if (
            hashlib.sha256(light.read_bytes()).digest()
            == hashlib.sha256(dark.read_bytes()).digest()
        ):
            fail(f"{light.name} and {dark.name} are byte-identical")
        light_luma = mean_luminance(light)
        dark_luma = mean_luminance(dark)
        if dark_luma >= light_luma - 100:
            fail(
                f"{light.name}/{dark.name} are not a real theme pair: "
                f"light={light_luma:.1f} dark={dark_luma:.1f}"
            )


def readme_targets(text: str) -> set[str]:
    targets: set[str] = set()
    for match in re.finditer(r"!\[[^\]]*\]\(([^)\s]+)", text):
        targets.add(match.group(1))
    for match in re.finditer(r'srcset="([^"\s]+)', text):
        targets.add(match.group(1))
    for match in re.finditer(r'<img[^>]+src="([^"\s]+)', text):
        targets.add(match.group(1))
    return {
        target.split("#", 1)[0].split("/")[-1]
        for target in targets
        if not target.startswith(("http://", "https://"))
    }


def check_readme(rows: list[tuple[str, str]]) -> None:
    if not README.exists():
        fail("missing README.md")
        return
    text = README.read_text(encoding="utf-8")
    listed = {name for name, _ in rows}
    targets = readme_targets(text)
    for target in sorted(targets):
        if not (ASSETS / target).exists():
            fail(f"README references missing asset {target}")
        if target not in listed:
            fail(f"README asset {target} is absent from the manifest")

    pictures = text.count("<picture>")
    if pictures < 4:
        fail(f"expected at least four theme-aware <picture> blocks, found {pictures}")
    for block in text.split("<picture>")[1:]:
        block = block.split("</picture>")[0]
        if "prefers-color-scheme: dark" not in block:
            fail("a <picture> block has no dark media query")
        if "prefers-color-scheme: light" not in block:
            fail("a <picture> block has no light media query")
        if "#gh-" in block:
            fail("a <picture> block mixes media queries with #gh fragment selectors")

    for heading in (
        "## The thirty-second version",
        "## What you get when you adopt it",
        "## Quick start",
        "## How it compares (benefit-led)",
        "## Hardened for production",
        "## Perfect partners",
        "## License",
    ):
        if heading not in text:
            fail(f"README is missing section {heading}")

    for asset in ASSETS.iterdir():
        if asset.suffix in (".png", ".svg") and asset.name not in listed:
            fail(f"{asset.name} exists but is absent from the manifest")


def main() -> int:
    check_mark()
    rows = parse_manifest()
    check_assets(rows)
    check_pairs()
    check_readme(rows)
    if errors:
        print("presentation gate failed:", file=sys.stderr)
        for error in errors:
            print("  -", error, file=sys.stderr)
        return 1
    print(
        f"presentation ok: {len(rows)} manifest assets, "
        f"{len(list(ASSETS.glob('*-light.png')))} theme pairs, approved mark"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
