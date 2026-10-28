//! README contract: the public page is a shipped artifact, not prose that drifts.
//!
//! The presentation gate (`scripts/check_presentation.py`) owns luminance, hash
//! and image integrity. This test keeps the structure, links, badges and theme
//! mechanism honest in a plain `cargo test` run.

use std::path::Path;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn readme_has_every_section_and_quick_start() {
    let readme = std::fs::read_to_string(root().join("README.md")).expect("README.md");
    for heading in [
        "## The thirty-second version",
        "## What you get when you adopt it",
        "## Quick start",
        "## Architecture at a glance",
        "## How it compares (benefit-led)",
        "## Hardened for production",
        "## Live Control Plane",
        "## Perfect partners",
        "## License",
    ] {
        assert!(readme.contains(heading), "README is missing {heading}");
    }
    assert!(readme.contains("crates/v/active-rpc"));
    assert!(readme.contains("cd control-plane"));
    assert!(readme.contains("MIT OR Apache-2.0"));
}

#[test]
fn every_readme_image_exists_and_is_theme_aware() {
    let readme = std::fs::read_to_string(root().join("README.md")).expect("README.md");
    let mut targets = Vec::new();
    for marker in [
        "](docs/assets/",
        "src=\"docs/assets/",
        "srcset=\"docs/assets/",
    ] {
        for chunk in readme.split(marker).skip(1) {
            let end = chunk.find([')', '"']).unwrap_or(0);
            targets.push(chunk[..end].split('#').next().unwrap_or("").to_string());
        }
    }
    assert!(
        targets.len() >= 4,
        "expected hero, compare, diagram and dashboard"
    );
    for target in targets {
        let path = root().join("docs/assets").join(&target);
        assert!(path.exists(), "README references missing {target}");
        assert!(
            path.metadata().map(|meta| meta.len()).unwrap_or(0) > 1_000,
            "{target} is suspiciously small"
        );
    }
    let pictures = readme.matches("<picture>").count();
    assert!(
        pictures >= 4,
        "expected hero, compare, diagram and dashboard pictures"
    );
    for block in readme.split("<picture>").skip(1) {
        let block = block.split("</picture>").next().unwrap_or("");
        assert!(
            block.contains("prefers-color-scheme: dark"),
            "missing dark media query"
        );
        assert!(
            block.contains("prefers-color-scheme: light"),
            "missing light media query"
        );
        assert!(
            !block.contains("#gh-"),
            "hybrid fragment selector in <picture>"
        );
    }
}

#[test]
fn assets_manifest_and_approved_mark_exist() {
    let manifest = std::fs::read_to_string(root().join("docs/assets/ASSETS-MANIFEST.md"))
        .expect("ASSETS-MANIFEST.md");
    for asset in [
        "active-mark.png",
        "active-mark.svg",
        "control-plane-light.png",
        "control-plane-dark.png",
    ] {
        assert!(manifest.contains(asset), "manifest omits {asset}");
        assert!(
            root().join("docs/assets").join(asset).exists(),
            "missing {asset}"
        );
    }
    use sha2::{Digest, Sha256};
    let mark = std::fs::read(root().join("docs/assets/active-mark.png")).expect("mark");
    let digest = Sha256::digest(&mark)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        digest, "af10d633e0c19b6ef069ff29820c84b355006ce384050d140fcf52a20e9ca1d2",
        "active-mark.png is not the approved source"
    );
}
