//! C-1 invariant gate: diagnostics carry correlation ids, never raw capability
//! authority, and secret values never print their payload.

use active_rpc::value::Value;
use active_rpc::{CapId, CapToken, Error};

const CANARY: &str = "maturity-secret-canary-4d19";

#[test]
fn capability_diagnostics_use_correlation_ids_only() {
    let id = CapId([0xab; 16]);
    let raw = id.hex();
    assert_eq!(format!("{id}"), id.correlation_id());
    assert_ne!(format!("{id}"), raw);
    assert!(!format!("{id:?}").contains(&raw));
    assert!(!format!("{id}").contains(&raw));

    let token = CapToken(u128::from_be_bytes([0xab; 16]));
    assert_eq!(format!("{token}"), token.correlation_id());
    assert!(!format!("{token}").contains(&raw));
    assert!(!format!("{token:?}").contains(&raw));

    let error = Error::Revoked(token);
    assert!(!format!("{error}").contains(&raw));
    assert!(!format!("{error:?}").contains(&raw));
}

#[test]
fn secret_values_never_debug_their_payload() {
    let secret = Value::Secret;
    let debug = format!("{secret:?}");
    assert!(!debug.contains(CANARY));
    assert_eq!(debug, "Secret");
}
