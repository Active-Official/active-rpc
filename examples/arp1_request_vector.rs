//! Print the canonical ARP1 request bytes for a fixed thin-client call.
//!
//! This is the byte-exact oracle for the polyglot thin clients: every client
//! encoder must reproduce this output for the same inputs.
//!
//! ```text
//! cargo run --example arp1_request_vector -- <payload-file> <cap-hex>
//! ```
//!
//! The inputs are deliberately the ones the maturity harness uses: request id
//! 42, method `echo`, no arguments, the AINF payload as the envelope payload,
//! and one capability descriptor carrying the `echo` method with the default
//! budget.

use active_rpc::cap::CapId;
use active_rpc::wire::CapDescriptor;
use active_rpc::{Budget, Envelope};

/// Largest payload file the example will read (matches the CLI's payload
/// ceiling): an unbounded `fs::read` let a huge file exhaust memory
/// (RPC-51c).
const MAX_PAYLOAD_BYTES: u64 = 64 << 20;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `std::env::args()` panics on a non-UTF-8 argument (exit 101); refuse
    // it instead (RPC-51c).
    let mut args = std::env::args_os().skip(1);
    let payload_path = args
        .next()
        .ok_or("usage: <payload-file> <cap-hex>")?
        .into_string()
        .map_err(|_| "an argument is not valid UTF-8")?;
    let cap_hex = args
        .next()
        .ok_or("usage: <payload-file> <cap-hex>")?
        .into_string()
        .map_err(|_| "an argument is not valid UTF-8")?;
    let payload = read_bounded(&payload_path)?;
    let cap = parse_cap(&cap_hex)?;

    let descriptor = CapDescriptor {
        id: cap,
        methods: ["echo".to_string()].into_iter().collect(),
        budget: Budget::default(),
        read_only: false,
        redact: false,
        path_scope: None,
    };
    let mut envelope = Envelope::request(42, "echo", Vec::new());
    envelope.payload = payload;
    envelope.caps = vec![descriptor];
    let bytes = envelope.encode()?;
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in &bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    println!("{hex}");
    Ok(())
}

/// Read the payload file under the ceiling, like the CLI's `--payload` read.
fn read_bounded(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use std::io::Read as _;
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_PAYLOAD_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PAYLOAD_BYTES {
        return Err(
            format!("{path} is larger than the {MAX_PAYLOAD_BYTES}-byte payload ceiling").into(),
        );
    }
    Ok(bytes)
}

fn parse_cap(hex: &str) -> Result<CapId, Box<dyn std::error::Error>> {
    if hex.len() != 32 {
        return Err("capability id must be 32 hex characters".into());
    }
    // The CLI's `parse_cap` checks `is_ascii()` before slicing; this one
    // did not, so a 32-byte cap holding a multi-byte character panicked on
    // a slice inside a code point (RPC-51c). The hex check also rejects the
    // `+` sign `from_str_radix` would otherwise accept (RPC-51b).
    if !hex.is_ascii() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("capability id must be 32 hex characters".into());
    }
    let mut id = [0u8; 16];
    for (index, slot) in id.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)?;
    }
    Ok(CapId(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cap_accepts_32_hex_digits() {
        assert!(parse_cap("00112233445566778899aabbccddeeff").is_ok());
    }

    #[test]
    fn parse_cap_refuses_a_plus_sign() {
        // `from_str_radix` accepts an optional `+`; the hex check rejects
        // it (RPC-51b).
        assert!(parse_cap("+0112233445566778899aabbccddeeff").is_err());
    }

    #[test]
    fn parse_cap_refuses_a_non_ascii_cap_without_panicking() {
        // 32 bytes, one of them multi-byte: the pre-fix slicing panicked
        // with "byte index 30 is not a char boundary" (RPC-51c).
        let cap = format!("{}é{}", "a".repeat(29), "a");
        assert_eq!(cap.len(), 32);
        assert!(parse_cap(&cap).is_err());
    }

    #[test]
    fn parse_cap_refuses_a_short_cap() {
        assert!(parse_cap("001122").is_err());
    }

    #[test]
    fn read_bounded_reads_a_small_file_whole() {
        let dir = std::env::temp_dir().join(format!("arp1-small-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("small.bin");
        std::fs::write(&path, [0x41u8; 16]).expect("small file");
        let bytes = read_bounded(path.to_str().unwrap()).expect("a small file reads");
        assert_eq!(bytes.len(), 16);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_bounded_refuses_a_file_over_the_ceiling() {
        let dir = std::env::temp_dir().join(format!("arp1-ceiling-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("big.bin");
        std::fs::write(&path, vec![0x41u8; MAX_PAYLOAD_BYTES as usize + 1]).expect("big file");
        let error = read_bounded(path.to_str().unwrap()).expect_err("over the ceiling");
        assert!(error.to_string().contains("larger than"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
