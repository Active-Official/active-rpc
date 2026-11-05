//! A provider that reached its peer and then refused must be reported as a
//! withheld reply, not as a call that did not happen: the receipt records the
//! admission and an idempotent retry returns the same outcome instead of
//! executing a second time (round 42, M-1).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use active_rpc::budget::Budget;
use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::receipts::Decision;
use active_rpc::value::{Call as ProviderCall, Response};
use active_rpc::{Agent, Error};

/// A mutating provider that always fails with a withheld reply, as an adapter
/// does when the answer cannot be parsed after the request left.
struct Withheld(Arc<AtomicUsize>);

impl Provider for Withheld {
    fn name(&self) -> &'static str {
        "withheld"
    }

    fn methods(&self) -> Vec<String> {
        vec!["write".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        true
    }

    fn invoke(&mut self, _object: u64, _call: &ProviderCall) -> active_rpc::Result<Response> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(Error::Provider {
            code: "provider/reply-withheld".to_string(),
        })
    }
}

#[test]
fn a_withheld_reply_is_receipted_as_admitted_and_not_replayed() {
    let calls = Arc::new(AtomicUsize::new(0));
    let agent = Agent::with_secret([0x6d; 32]);
    agent.enable_receipts(true);
    let provider = agent.register(Box::new(Withheld(Arc::clone(&calls))));
    let cap = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["write"]).with_budget(Budget::calls(10)),
        )
        .expect("cap");
    let lane = agent
        .create_lane("withheld", Budget::default())
        .expect("lane");
    let key = "one-write";

    let first = agent
        .call_idempotent(lane, &cap, "write", Vec::new(), key)
        .expect("queued");
    agent.run();
    let error = first.value().expect_err("the reply was withheld");
    assert_eq!(
        error.provider_code(),
        Some("provider/reply-withheld"),
        "{error}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the provider ran once");

    let receipts = agent.receipts();
    assert_eq!(receipts.len(), 1, "one decision, one receipt");
    match &receipts[0].decision {
        Decision::Admitted => {}
        other => panic!("a withheld reply was receipted as {other:?}"),
    }

    // The idempotency key returns the same outcome: the peer must not run the
    // write a second time.
    let replayed = agent
        .call_idempotent(lane, &cap, "write", Vec::new(), key)
        .expect("the key is reusable");
    agent.run();
    let replay_error = replayed.value().expect_err("the same withheld reply");
    assert_eq!(
        replay_error.provider_code(),
        Some("provider/reply-withheld"),
        "{replay_error}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the idempotent retry re-executed the mutating provider"
    );
}
