//! Public-surface policy for active-rpc.
//!
//! The authoritative gate is `scripts/api_surface.py`, which reads rustdoc JSON
//! and therefore sees the resolved public API (functions, trait items and
//! re-exports). CI runs it in the `api-surface` job. This file is the fast
//! tripwire that runs under `cargo test` without a nightly toolchain.
//!
//! Policy:
//! 1. no public accessor hands out raw secret material;
//! 2. `CapId::hex` is the single documented raw-authority accessor, for a
//!    deliberate transfer; every diagnostic surface uses the correlation id;
//! 3. capability errors format a correlation id, never the raw 128 bits.

use std::path::{Path, PathBuf};

use active_rpc::{CapId, CapToken, Error};

const FORBIDDEN: &[&str] = &[
    "secret_texts",
    "secret_bytes",
    "secret_values",
    "secret_payload",
    "cap_id_bytes",
    "cap_bits",
    "capability_bits",
    "raw_cap_id",
    "raw_capability",
];

fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory).expect("src directory") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

#[test]
fn no_public_secret_or_raw_capability_accessor_is_declared() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    for path in rust_sources(&root) {
        let text = std::fs::read_to_string(&path).expect("source");
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("pub fn ") {
                continue;
            }
            let name = line
                .trim_start_matches("pub fn ")
                .split(['(', '<'])
                .next()
                .unwrap_or("")
                .trim();
            if FORBIDDEN.contains(&name) {
                offenders.push(format!("{}: pub fn {name}", path.display()));
            }
            if name.contains("secret")
                && (line.contains("-> String")
                    || line.contains("-> &str")
                    || line.contains("-> Vec<u8>"))
            {
                offenders.push(format!(
                    "{}: pub fn {name} returns raw text/bytes",
                    path.display()
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "forbidden public accessors:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn capability_hex_is_the_single_documented_raw_accessor() {
    let cap = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cap.rs"))
        .expect("cap.rs");
    assert_eq!(
        cap.matches("pub fn hex(").count(),
        1,
        "CapId::hex must be the only raw-accessor declaration"
    );
    let start = cap.find("pub fn hex(").expect("hex");
    let context = &cap[start.saturating_sub(400)..start];
    assert!(
        context.contains("deliberate transfer"),
        "the raw accessor must carry its transfer-only warning"
    );
}

#[test]
fn capability_display_and_errors_use_the_correlation_id() {
    let id = CapId([0xab; 16]);
    assert_eq!(format!("{id}"), id.correlation_id());
    assert_ne!(format!("{id}"), id.hex());
    assert!(!format!("{id:?}").contains(&id.hex()));

    let bits = u128::from_be_bytes([0xab; 16]);
    let error = Error::UnknownCapability(CapToken(bits));
    for rendered in [format!("{error}"), format!("{error:?}")] {
        assert!(!rendered.contains("abab"));
        assert!(!rendered.contains(&bits.to_string()));
    }
}
