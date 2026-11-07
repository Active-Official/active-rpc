//! R-16 round 8: the marker is the library's, the module tri-state is decided
//! once and documented, and a fingerprint parser is strict about hex.

use active_infinity::{encode, InfinityModule, Inode};
use active_rpc::cap::CapAttrs;
use active_rpc::identity::{IdentityPolicy, PeerIdentity};
use active_rpc::kernel::Provider;
use active_rpc::security::{module_carries_a_secret, SECRET_MARKER};
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, CapPersistence, CapabilityRecord};

struct Echo;

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }
    fn methods(&self) -> Vec<String> {
        vec!["echo".to_string()]
    }
    fn mutating(&self, _method: &str) -> bool {
        false
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("ok")))
    }
}

fn module(secret: bool) -> InfinityModule {
    let mut module = InfinityModule::new();
    let node = module.push(if secret {
        Inode::Secret(active_infinity::SecretBytes::new(b"canary"))
    } else {
        Inode::Str("plain".to_string())
    });
    module.set_root(Some(node));
    module
}

#[test]
fn the_secret_marker_is_the_librarys() {
    assert_eq!(
        SECRET_MARKER,
        active_infinity::interop::SECRET_MARKER,
        "a copy that drifted would make the map-key gates miss the library's marker"
    );
}

#[test]
fn a_corrupt_image_claims_a_secret_and_a_plain_image_does_not() {
    assert!(!module_carries_a_secret(b"not an image"));
    assert!(!module_carries_a_secret(
        &encode(&module(false)).expect("encode")
    ));
    assert!(module_carries_a_secret(
        &encode(&module(true)).expect("encode")
    ));

    let mut corrupt = encode(&module(false)).expect("encode");
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xFF;
    assert!(
        active_infinity::decode(&corrupt).is_err(),
        "the fixture is corrupt"
    );
    assert!(
        module_carries_a_secret(&corrupt),
        "an image that cannot be read cannot be proven secret-free"
    );
}

#[test]
fn a_signed_or_uppercase_fingerprint_is_refused() {
    let agent = Agent::with_secret([0x54; 32]);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x97; 32]);
    let provider = agent.register(Box::new(Echo));
    let owner = IdentityPolicy::default()
        .admit(Some(&PeerIdentity::from_certificate(b"hex-owner")), true)
        .expect("admit");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let cap = agent.mint_bound(&owner, provider, 0, attrs).expect("cap");
    let record = agent.export_capability(&cap).expect("export");
    let json = record.to_json();

    let marker = "\"record_id\":\"";
    let start = json.find(marker).expect("the record names its id") + marker.len();
    // Still 64 characters, and `from_str_radix` reads it as a signed number:
    // only the parser's own hex rule refuses it.
    let mut signed = String::with_capacity(json.len());
    signed.push_str(&json[..start]);
    signed.push('+');
    signed.push_str(&json[start + 1..]);
    let error = CapabilityRecord::from_json(&signed).expect_err("a signed id is not hex");
    let printed = format!("{error}");
    assert!(
        printed.contains("not hex"),
        "the parser applies the rule itself: {printed}"
    );

    let id = &json[start..start + 64];
    if let Some(offset) = id.find(|ch: char| ch.is_ascii_alphabetic()) {
        let index = start + offset;
        let mut upper = json.clone();
        let upper_digit = json[index..index + 1].to_uppercase();
        upper.replace_range(index..index + 1, &upper_digit);
        let error = CapabilityRecord::from_json(&upper).expect_err("an uppercase digit is not hex");
        assert!(format!("{error}").contains("not hex"), "{error}");
    }
}
