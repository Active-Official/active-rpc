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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let payload_path = args.next().ok_or("usage: <payload-file> <cap-hex>")?;
    let cap_hex = args.next().ok_or("usage: <payload-file> <cap-hex>")?;
    let payload = std::fs::read(&payload_path)?;
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

fn parse_cap(hex: &str) -> Result<CapId, Box<dyn std::error::Error>> {
    if hex.len() != 32 {
        return Err("capability id must be 32 hex characters".into());
    }
    let mut id = [0u8; 16];
    for (index, slot) in id.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)?;
    }
    Ok(CapId(id))
}
