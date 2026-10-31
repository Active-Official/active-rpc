//! Introduction modules: a peer's surface described in Active Infinity itself.

use active_infinity::interop::to_redacted_json;
use active_infinity::{content_hash_hex, decode, validate};
use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, Budget};

struct Echo;

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn methods(&self) -> Vec<String> {
        vec!["echo".to_string(), "sum".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("ok")))
    }
}

struct Files;

impl Provider for Files {
    fn name(&self) -> &'static str {
        "files"
    }

    fn methods(&self) -> Vec<String> {
        vec!["read".to_string(), "stat".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("ok")))
    }
}

fn agent() -> Agent {
    let agent = Agent::with_secret([0x2f; 32]);
    agent.register(Box::new(Echo));
    agent.register(Box::new(Files));
    agent
}

fn json_of(bytes: &[u8]) -> String {
    to_redacted_json(&decode(bytes).expect("decode")).expect("redacted json")
}

#[test]
fn the_introduction_is_a_valid_canonical_module() {
    let agent = agent();
    let bytes = agent.intro().expect("intro");
    let meta = validate(&bytes).expect("valid AINF");
    assert!(meta.nodes >= 10);
    let json = json_of(&bytes);
    assert!(json.contains("\"echo\""), "{json}");
    assert!(json.contains("\"files\""), "{json}");
    assert!(json.contains("\"sum\""), "{json}");
    assert!(json.contains("\"default_budget\""), "{json}");
    assert!(json.contains("active-rpc/"));
}

#[test]
fn the_introduction_is_deterministic() {
    let agent = agent();
    let first = agent.intro().expect("intro");
    let second = agent.intro().expect("intro again");
    assert_eq!(first, second);
    assert_eq!(
        content_hash_hex(&first).expect("hash"),
        content_hash_hex(&second).expect("hash")
    );
}

#[test]
fn the_introduction_carries_no_capability_authority() {
    let agent = Agent::with_secret([0x30; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let cap_hex = cap.id().hex();
    let bytes = agent.intro().expect("intro");
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    assert!(
        !hex.contains(&cap_hex),
        "capability id leaked into the intro"
    );
    assert!(!json_of(&bytes).contains(&cap_hex));
}

#[test]
fn an_empty_agent_describes_an_empty_provider_table() {
    let agent = Agent::with_secret([0x31; 32]);
    let bytes = agent.intro().expect("intro");
    validate(&bytes).expect("valid");
    assert!(json_of(&bytes).contains("\"providers\":[]"));
}

#[test]
fn the_default_budget_is_advertised() {
    let agent = agent();
    let bytes = agent.intro().expect("intro");
    let json = json_of(&bytes);
    let budget = Budget::default();
    assert!(
        json.contains(&format!("\"max_calls\":{}", budget.max_calls)),
        "{json}"
    );
    assert!(
        json.contains(&format!("\"max_bytes\":{}", budget.max_bytes)),
        "{json}"
    );
    assert!(
        json.contains(&format!("\"max_wall_ms\":{}", budget.max_wall_ms)),
        "{json}"
    );
}
