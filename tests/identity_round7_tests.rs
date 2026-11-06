//! R-11 round 11: a certificate rotation carries the peer's own work, an
//! out-of-band answer follows the rotation, an anonymous peer cannot read the
//! agent's own promise, and a refused answer is visible on the tape.

use active_rpc::cap::CapAttrs;
use active_rpc::identity::{AdmittedIdentity, IdentityPolicy, PeerIdentity};
use active_rpc::value::{Arg, Call, Response};
use active_rpc::{Agent, Budget, Event, Provider};

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
    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        let value = call
            .args
            .iter()
            .find_map(|arg| match arg {
                Arg::Value(value) => Some(value.clone()),
                _ => None,
            })
            .unwrap_or(active_rpc::Value::Null);
        Ok(Response::Value(value))
    }
}

fn admitted(certificate: &[u8]) -> AdmittedIdentity {
    IdentityPolicy::default()
        .admit(Some(&PeerIdentity::from_certificate(certificate)), false)
        .expect("admitted")
}

/// The old and the successor certificate of one peer.
const OLD: &[u8] = b"alice-certificate-one";
const NEW: &[u8] = b"alice-certificate-two";

/// A rotation is the documented recovery for a renewed leaf certificate, so the
/// peer's cached idempotency claim must follow it: otherwise its retry of an
/// applied mutating call answers `rpc/identity` forever and it cannot learn
/// whether the write landed, while a fresh key would apply it twice
/// (R-11 round 11, #1).
#[test]
fn a_rotated_peer_retries_its_idempotency_key() {
    let agent = Agent::with_secret([0xb1; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    agent
        .introduce_to(&cap, &admitted(OLD))
        .expect("bind to the first certificate");
    let lane = agent
        .create_lane("rotation", Budget::default())
        .expect("lane");
    let args = vec![Arg::text("an applied write")];

    let first = agent
        .call_idempotent_as(
            Some(&PeerIdentity::from_certificate(OLD)),
            lane,
            &cap,
            "echo",
            args.clone(),
            "rotate-me",
        )
        .expect("first call");
    let id = first.id();
    agent.run();
    first.value().expect("the call settles");

    agent
        .reintroduce_to(&cap, &PeerIdentity::from_certificate(OLD), &admitted(NEW))
        .expect("the rotation succeeds");

    let retry = agent
        .call_idempotent_as(
            Some(&PeerIdentity::from_certificate(NEW)),
            lane,
            &cap,
            "echo",
            args,
            "rotate-me",
        )
        .expect("the successor certificate replays the same claim");
    assert_eq!(
        retry.id(),
        id,
        "the retry must name the promise the first call already answered"
    );
    retry.value().expect("the cached promise still reads");
}

/// A call queued by the peer before the rotation is still that peer's work after
/// it. A dispatch that compared the queued fingerprint with the new binding
/// would answer `rpc/identity` for a call the operator had already authorized
/// (R-11 round 11, #1).
#[test]
fn a_rotation_carries_a_queued_job() {
    let agent = Agent::with_secret([0xb2; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    agent.introduce_to(&cap, &admitted(OLD)).expect("bind");
    let lane = agent
        .create_lane("queued", Budget::default())
        .expect("lane");

    let queued = agent
        .call_as(
            Some(&PeerIdentity::from_certificate(OLD)),
            lane,
            &cap,
            "echo",
            vec![Arg::text("before the rotation")],
        )
        .expect("queued");
    agent
        .reintroduce_to(&cap, &PeerIdentity::from_certificate(OLD), &admitted(NEW))
        .expect("the rotation succeeds");
    agent.run();

    assert_eq!(
        queued.value().expect("the queued call still runs"),
        active_rpc::Value::text("before the rotation")
    );
}

/// An out-of-band answer belongs to the peer that queued the call, so the
/// rotation moves that owner too: before it the successor cannot answer, after
/// it the successor can and the old certificate cannot
/// (R-11 round 11, #1 and #5).
#[test]
fn an_out_of_band_answer_after_rotation() {
    let agent = Agent::with_secret([0xb3; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    agent.introduce_to(&cap, &admitted(OLD)).expect("bind");
    let lane = agent
        .create_lane("out-of-band", Budget::default())
        .expect("lane");
    let promise = agent
        .call_as(
            Some(&PeerIdentity::from_certificate(OLD)),
            lane,
            &cap,
            "echo",
            vec![Arg::text("question")],
        )
        .expect("queued");

    let error = agent
        .resolve_as(
            Some(&PeerIdentity::from_certificate(NEW)),
            &promise,
            active_rpc::Value::text("too early"),
        )
        .expect_err("the successor does not own the promise before the rotation");
    assert_eq!(error.code(), "rpc/identity", "{error}");

    agent
        .reintroduce_to(&cap, &PeerIdentity::from_certificate(OLD), &admitted(NEW))
        .expect("the rotation succeeds");

    let error = agent
        .resolve_as(
            Some(&PeerIdentity::from_certificate(OLD)),
            &promise,
            active_rpc::Value::text("the old certificate"),
        )
        .expect_err("the retired certificate no longer owns the promise");
    assert_eq!(error.code(), "rpc/identity", "{error}");

    agent
        .resolve_as(
            Some(&PeerIdentity::from_certificate(NEW)),
            &promise,
            active_rpc::Value::text("the answer"),
        )
        .expect("the successor answers its own call");
    assert_eq!(
        promise.peek().expect("settled"),
        active_rpc::Value::text("the answer")
    );
}

/// A refused answer is an operator-visible event, not a silent `Err`: the one
/// signal that says a peer tried to answer somebody else's call
/// (R-11 round 11, #5).
#[test]
fn a_refused_answer_is_counted_and_taped() {
    let agent = Agent::with_secret([0xb4; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    agent.introduce_to(&cap, &admitted(OLD)).expect("bind");
    let lane = agent
        .create_lane("counted", Budget::default())
        .expect("lane");
    let promise = agent
        .call_as(
            Some(&PeerIdentity::from_certificate(OLD)),
            lane,
            &cap,
            "echo",
            vec![Arg::text("question")],
        )
        .expect("queued");

    let before = agent.metrics();
    let error = agent
        .resolve_as(
            Some(&PeerIdentity::from_certificate(NEW)),
            &promise,
            active_rpc::Value::text("not mine"),
        )
        .expect_err("another certificate cannot answer");
    assert_eq!(error.code(), "rpc/identity", "{error}");

    let after = agent.metrics();
    assert_eq!(after.identity_refusals, before.identity_refusals + 1);
    assert_eq!(after.calls_refused, before.calls_refused + 1);
    let taped = agent
        .events()
        .into_iter()
        .filter(|event| matches!(event, Event::CallRefused { code, .. } if code == "rpc/identity"))
        .count();
    assert_eq!(taped, 1, "exactly one refusal event");
}

/// A peer that presented no identity is still a peer: the promise the agent
/// queued for itself carries neither a fingerprint nor a peer origin, and an
/// identity-less peer's call must not read it through an echoing provider
/// (R-11 round 11, #4; round 10, F1).
#[test]
fn an_identity_less_peer_cannot_pipeline_the_agents_own_promise() {
    let agent = Agent::with_secret([0xb5; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let lane = agent
        .create_lane("anonymous", Budget::default())
        .expect("lane");

    let own = agent
        .call(lane, &cap, "echo", vec![Arg::text("the agent's own value")])
        .expect("in-process call");
    let relay = agent
        .call_as(
            Some(&PeerIdentity::anonymous()),
            lane,
            &cap,
            "echo",
            vec![Arg::Promise(own.id())],
        )
        .expect("the argument list is built in-process");
    agent.run();
    own.value().expect("the agent's own call resolves");
    let error = relay
        .value()
        .expect_err("an identity-less peer cannot read the agent's promise");
    assert_eq!(error.code(), "rpc/identity", "{error}");

    // The control: the agent may pipeline its own promise, so the refusal above
    // is the origin and not a blanket refusal of promise arguments.
    let first = agent
        .call(lane, &cap, "echo", vec![Arg::text("first")])
        .expect("first");
    let second = agent
        .call(lane, &cap, "echo", vec![Arg::Promise(first.id())])
        .expect("second");
    agent.run();
    assert_eq!(
        first.value().expect("resolves"),
        active_rpc::Value::text("first")
    );
    assert_eq!(
        second.value().expect("the agent reads its own promise"),
        active_rpc::Value::text("first")
    );
}

/// An envelope never carries a promise argument, so the wire code comes first:
/// a peer cannot reach the ownership rule at all, and the conformance suite has
/// to agree with the spec on which code it sees (R-11 round 11, #7).
#[test]
fn an_envelope_naming_a_promise_is_a_wire_refusal() {
    use active_rpc::wire::Envelope;

    let agent = Agent::with_secret([0xb6; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let lane = agent
        .create_lane("envelope", Budget::default())
        .expect("lane");
    let envelope = Envelope::request(1, "echo", vec![Arg::Promise(active_rpc::PromiseId(0))]);
    let error = agent
        .call_from_envelope(
            Some(&PeerIdentity::from_certificate(OLD)),
            lane,
            &cap,
            &envelope,
        )
        .expect_err("an envelope cannot carry a promise argument");
    assert_eq!(error.code(), "rpc/wire", "{error}");
}

/// A rotation moves the work of the capabilities it rebinds, and only those: a
/// queued pipeline that spans a rotated capability and an unrotated sibling is
/// refused at dispatch, with the rotation's own code and no partial side effect.
/// The operator rotates every capability in a pipeline before the next dispatch
/// (R-11 round 12, F1; `docs/deployment/identity.md` rule 3).
#[test]
fn a_rotation_refuses_a_pipeline_that_spans_two_capabilities() {
    let agent = Agent::with_secret([0xb7; 32]);
    let provider = agent.register(Box::new(Echo));
    let first = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("first cap");
    let second = agent
        .mint(provider, 1, CapAttrs::new(&["echo"]))
        .expect("second cap");
    agent.introduce_to(&first, &admitted(OLD)).expect("bind A");
    agent.introduce_to(&second, &admitted(OLD)).expect("bind B");
    let lane = agent
        .create_lane("pipeline", Budget::default())
        .expect("lane");

    let produced = agent
        .call_as(
            Some(&PeerIdentity::from_certificate(OLD)),
            lane,
            &first,
            "echo",
            vec![Arg::text("value")],
        )
        .expect("producer queued");
    let dependent = agent
        .call_as(
            Some(&PeerIdentity::from_certificate(OLD)),
            lane,
            &second,
            "echo",
            vec![Arg::Promise(produced.id())],
        )
        .expect("dependent queued");

    // Rotate only the producing capability, then dispatch.
    agent
        .reintroduce_to(&first, &PeerIdentity::from_certificate(OLD), &admitted(NEW))
        .expect("rotate A");
    agent.run();
    let error = dependent
        .value()
        .expect_err("the dependency's owner moved and the sibling did not");
    assert_eq!(error.code(), "rpc/identity", "{error}");

    // The documented procedure: rotate both before the next dispatch.
    let agent = Agent::with_secret([0xb8; 32]);
    let provider = agent.register(Box::new(Echo));
    let first = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("first cap");
    let second = agent
        .mint(provider, 1, CapAttrs::new(&["echo"]))
        .expect("second cap");
    agent.introduce_to(&first, &admitted(OLD)).expect("bind A");
    agent.introduce_to(&second, &admitted(OLD)).expect("bind B");
    let lane = agent
        .create_lane("pipeline-2", Budget::default())
        .expect("lane");
    let produced = agent
        .call_as(
            Some(&PeerIdentity::from_certificate(OLD)),
            lane,
            &first,
            "echo",
            vec![Arg::text("value")],
        )
        .expect("producer queued");
    let dependent = agent
        .call_as(
            Some(&PeerIdentity::from_certificate(OLD)),
            lane,
            &second,
            "echo",
            vec![Arg::Promise(produced.id())],
        )
        .expect("dependent queued");
    agent
        .reintroduce_to(&first, &PeerIdentity::from_certificate(OLD), &admitted(NEW))
        .expect("rotate A");
    agent
        .reintroduce_to(
            &second,
            &PeerIdentity::from_certificate(OLD),
            &admitted(NEW),
        )
        .expect("rotate B");
    agent.run();
    assert_eq!(
        dependent.value().expect("the whole pipeline runs"),
        active_rpc::Value::text("value")
    );
}

/// An idempotency claim is scoped to the lane that holds it, and a rotation
/// cannot move a lane: a retry on the same lane replays the promise, a retry on
/// a new one is a new call. The deployment doc says so, and this pins it so the
/// code and the doc cannot drift (R-11 round 12, F3).
#[test]
fn a_rotation_does_not_carry_a_claim_across_lanes() {
    let agent = Agent::with_secret([0xb9; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    agent.introduce_to(&cap, &admitted(OLD)).expect("bind");
    let lane = agent.create_lane("claim", Budget::default()).expect("lane");
    let args = vec![Arg::text("an applied write")];
    let first = agent
        .call_idempotent_as(
            Some(&PeerIdentity::from_certificate(OLD)),
            lane,
            &cap,
            "echo",
            args.clone(),
            "lane-scoped",
        )
        .expect("first call");
    agent.run();
    first.value().expect("settles");
    agent
        .reintroduce_to(&cap, &PeerIdentity::from_certificate(OLD), &admitted(NEW))
        .expect("rotate");

    let replay = agent
        .call_idempotent_as(
            Some(&PeerIdentity::from_certificate(NEW)),
            lane,
            &cap,
            "echo",
            args.clone(),
            "lane-scoped",
        )
        .expect("the same lane replays the claim");
    assert_eq!(replay.id(), first.id(), "the claim follows the certificate");

    let other = agent
        .create_lane("claim-2", Budget::default())
        .expect("second lane");
    let fresh = agent
        .call_idempotent_as(
            Some(&PeerIdentity::from_certificate(NEW)),
            other,
            &cap,
            "echo",
            args,
            "lane-scoped",
        )
        .expect("a new lane is a new key scope");
    agent.run();
    assert_ne!(
        fresh.id(),
        first.id(),
        "a key is scoped to (capability, lane, method, key): a new lane is a new call"
    );
}

/// A rotation says on the tape what it carried, so an auditor can tell a
/// rotation that moved a peer's answers from one that moved none
/// (R-11 round 12, F5).
#[test]
fn a_rotation_reports_the_work_it_carries() {
    let agent = Agent::with_secret([0xba; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    agent.introduce_to(&cap, &admitted(OLD)).expect("bind");
    let lane = agent
        .create_lane("carried", Budget::default())
        .expect("lane");
    // One idempotent call leaves a queued job, a pending promise and a claim,
    // all stamped with the old certificate.
    let promise = agent
        .call_idempotent_as(
            Some(&PeerIdentity::from_certificate(OLD)),
            lane,
            &cap,
            "echo",
            vec![Arg::text("carried")],
            "carried-key",
        )
        .expect("queued");
    let _ = promise;
    agent
        .reintroduce_to(&cap, &PeerIdentity::from_certificate(OLD), &admitted(NEW))
        .expect("rotate");
    let carried = agent.events().into_iter().find_map(|event| match event {
        Event::RotationCarried {
            jobs,
            promises,
            claims,
            ..
        } => Some((jobs, promises, claims)),
        _ => None,
    });
    assert_eq!(
        carried,
        Some((1, 1, 1)),
        "the tape reports one job, one promise and one claim"
    );
}

/// An out-of-band answer past the grant is refused, counted and taped like the
/// same refusal on a call: a peer must not be able to probe the reply ceiling
/// without a trace (R-11 round 12, F2).
#[test]
fn an_over_budget_answer_is_counted_and_taped() {
    let agent = Agent::with_secret([0xbb; 32]);
    let provider = agent.register(Box::new(Echo));
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.budget.max_bytes = 256;
    let cap = agent.mint(provider, 0, attrs).expect("cap");
    agent.introduce_to(&cap, &admitted(OLD)).expect("bind");
    let lane = agent
        .create_lane("answer", Budget::default())
        .expect("lane");
    let promise = agent
        .call_as(
            Some(&PeerIdentity::from_certificate(OLD)),
            lane,
            &cap,
            "echo",
            vec![Arg::text("q")],
        )
        .expect("queued");

    let before = agent.metrics();
    let wide = active_rpc::Value::list((0..64).map(active_rpc::Value::Int));
    let error = agent
        .resolve_as(Some(&PeerIdentity::from_certificate(OLD)), &promise, wide)
        .expect_err("an answer past the grant is refused");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    let after = agent.metrics();
    assert_eq!(
        after.calls_refused,
        before.calls_refused + 1,
        "the refusal is counted"
    );
    assert_eq!(
        after.budget_exhaustions,
        before.budget_exhaustions + 1,
        "the budget dimension is counted"
    );
    let taped = agent
        .events()
        .into_iter()
        .filter(|event| {
            matches!(event, Event::CallRefused { code, .. } if code == "rpc/budget-exceeded")
        })
        .count();
    assert_eq!(taped, 1, "exactly one refusal event");
}
