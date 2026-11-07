//! R-17 round 2: the authority edges around introductions, topics and channels.
//!
//! Each test names the finding it pins. They are written against the shipped
//! kernel: the wall clock is the real one, the channels are real channels, and
//! the provider in the re-entrancy test is a real provider.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use active_rpc::cap::CapAttrs;
use active_rpc::channel::{Channel, ChannelStats, Direction};
use active_rpc::identity::{AdmittedIdentity, IdentityPolicy, PeerIdentity};
use active_rpc::kernel::Provider;
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, Budget, ProviderId};

struct Echo;

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }
    fn methods(&self) -> Vec<String> {
        vec!["ping".to_string()]
    }
    fn mutating(&self, _method: &str) -> bool {
        false
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("pong")))
    }
}

fn agent() -> (Agent, ProviderId) {
    let agent = Agent::with_secret([0x41; 32]);
    let provider = agent.register(Box::new(Echo));
    (agent, provider)
}

/// 2.1 - a wall clock has to be read before a deadline is compared.
#[test]
fn an_expired_capability_cannot_publish_send_attenuate_or_be_introduced() {
    let (agent, provider) = agent();
    agent.use_wall_clock(true);
    let channel = agent
        .create_channel("clock", Direction::Both)
        .expect("channel");
    let lane = agent.create_lane("clock", Budget::default()).expect("lane");
    agent.subscribe(lane, channel).expect("subscribe");
    let peer = IdentityPolicy::default()
        .admit(Some(&PeerIdentity::from_certificate(b"peer-a")), false)
        .expect("admitted");

    let expiring = |agent: &Agent| {
        let mut attrs = CapAttrs::new(&["ping"]).allow_publish();
        attrs.ttl_ms = Some(1);
        agent.mint(provider, 0, attrs).expect("mint")
    };

    // Publish.
    let cap = expiring(&agent);
    std::thread::sleep(std::time::Duration::from_millis(15));
    assert_eq!(
        agent
            .publish(lane, channel, &cap, "topic", Value::text("late"))
            .expect_err("an expired capability must not publish")
            .code(),
        "rpc/revoked"
    );

    // Attenuate.
    let cap = expiring(&agent);
    std::thread::sleep(std::time::Duration::from_millis(15));
    assert_eq!(
        agent
            .attenuate(&cap, CapAttrs::new(&["ping"]))
            .expect_err("an expired capability must not attenuate")
            .code(),
        "rpc/revoked"
    );

    // Introduce.
    let cap = expiring(&agent);
    std::thread::sleep(std::time::Duration::from_millis(15));
    assert_eq!(
        agent
            .introduce_to(&cap, &peer)
            .expect_err("an expired capability must not be introduced")
            .code(),
        "rpc/revoked"
    );

    // Transfer over a channel.
    let cap = expiring(&agent);
    std::thread::sleep(std::time::Duration::from_millis(15));
    assert_eq!(
        agent
            .send(
                lane,
                channel,
                Value::text("caps"),
                std::slice::from_ref(&cap)
            )
            .expect_err("an expired capability must not be transferred")
            .code(),
        "rpc/revoked"
    );
}

/// 2.2 - the channel view carries no queue, so a non-subscriber cannot read it.
#[test]
fn a_channel_view_carries_no_messages() {
    let (agent, provider) = agent();
    let channel = agent
        .create_channel("mailbox", Direction::Both)
        .expect("channel");
    let reader = agent
        .create_lane("reader", Budget::default())
        .expect("lane");
    let writer = agent
        .create_lane("writer", Budget::default())
        .expect("lane");
    agent.subscribe(reader, channel).expect("subscribe");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["ping"]))
        .expect("mint");
    agent
        .send(writer, channel, Value::text("secret-payload"), &[cap])
        .expect("send");

    let stats: ChannelStats = agent.channel(channel).expect("channel");
    assert_eq!(stats.queued, 1);
    assert!(stats.queued_bytes > 0);
    // The payload and the transferred id are gone from the view: only counts
    // and names remain.
    let rendered = format!("{stats:?}");
    assert!(!rendered.contains("secret-payload"), "{rendered}");
}

/// 2.4 - an imported handle is not ownership.
#[test]
fn an_imported_handle_cannot_introduce_authority() {
    let (agent, provider) = agent();
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["ping"]))
        .expect("mint");
    let borrowed = agent.import(cap.id());
    let peer = IdentityPolicy::default()
        .admit(Some(&PeerIdentity::from_certificate(b"peer-b")), false)
        .expect("admitted");
    assert_eq!(
        agent
            .introduce_to(&borrowed, &peer)
            .expect_err("a borrowed id is not authority")
            .code(),
        "rpc/identity"
    );
    // The owner still holds an unbound capability.
    assert!(agent.introduce_to(&cap, &peer).is_ok());
}

/// 2.6 - separators, bidi and zero-width characters are refused everywhere a
/// name or a topic is accepted.
#[test]
fn invisible_and_reordering_characters_are_refused() {
    let (agent, provider) = agent();
    let hostile = [
        "topic\u{2028}second",
        "topic\u{2029}second",
        "topic\u{202E}reversed",
        "topic\u{200B}zero",
        "topic\u{FEFF}bom",
    ];
    for topic in hostile {
        assert_eq!(
            agent
                .mint(
                    provider,
                    0,
                    CapAttrs::new(&["ping"]).restrict_topics(&[topic])
                )
                .expect_err("a hostile topic must not be granted")
                .code(),
            "rpc/invalid-argument",
            "{topic:?}"
        );
    }
    assert_eq!(
        agent
            .create_channel("name\u{2028}x", Direction::Both)
            .expect_err("a hostile channel name must be refused")
            .code(),
        "rpc/invalid-argument"
    );
    let mut channel = Channel::new(active_rpc::ChannelId(7), "direct", Direction::Both);
    assert_eq!(
        channel
            .send_topic(
                active_rpc::LaneId(1),
                Some("bad\u{202E}topic"),
                Value::text("x"),
                Vec::new()
            )
            .expect_err("the type boundary enforces the rule too")
            .code(),
        "rpc/invalid-argument"
    );
    // The introduction refuses the same characters in a provider name.
    assert_eq!(
        active_rpc::intro::build(
            "peer",
            &[("pro\u{202E}vider".to_string(), vec!["m".to_string()])],
            &Budget::default()
        )
        .expect_err("a hostile provider name must be refused")
        .code(),
        "rpc/invalid-argument"
    );
}

/// 2.7 - the same surface encodes to the same bytes, including two instances of
/// one adapter, whose method lists break the tie (R-17 round 4).
#[test]
fn an_introduction_is_order_independent_and_lists_each_instance() {
    let forward = vec![
        ("b".to_string(), vec!["x".to_string()]),
        ("a".to_string(), vec!["y".to_string(), "x".to_string()]),
    ];
    let mut reverse = forward.clone();
    reverse.reverse();
    let first = active_rpc::intro::build("peer", &forward, &Budget::default()).expect("first");
    let second = active_rpc::intro::build("peer", &reverse, &Budget::default()).expect("second");
    assert_eq!(first, second, "an introduction is canonical");

    let instances = vec![
        ("dup".to_string(), vec!["a".to_string()]),
        ("dup".to_string(), vec!["b".to_string()]),
    ];
    let mut swapped = instances.clone();
    swapped.reverse();
    let bytes = active_rpc::intro::build("peer", &instances, &Budget::default())
        .expect("two instances of one adapter are a documented configuration");
    assert_eq!(
        bytes,
        active_rpc::intro::build("peer", &swapped, &Budget::default()).expect("the other order"),
        "the method list orders two instances deterministically"
    );
}

/// 2.8 - a ceiling that does not fit the module integer is refused.
#[test]
fn a_budget_that_does_not_fit_the_module_is_refused() {
    let budget = Budget {
        max_bytes: u64::MAX,
        ..Budget::default()
    };
    assert_eq!(
        active_rpc::intro::build("peer", &[], &budget)
            .expect_err("a negative ceiling would advertise an impossible budget")
            .code(),
        "rpc/invalid-argument"
    );
}

/// 2.9 - provider code runs with no kernel borrow held, so it may call back in.
struct Reentrant {
    agent: Rc<RefCell<Option<Agent>>>,
    lanes: Rc<Cell<usize>>,
}

impl Provider for Reentrant {
    fn name(&self) -> &'static str {
        "reentrant"
    }
    fn methods(&self) -> Vec<String> {
        if let Some(agent) = self.agent.borrow().as_ref() {
            if agent.create_lane("from-methods", Budget::default()).is_ok() {
                self.lanes.set(self.lanes.get() + 1);
            }
        }
        vec!["ping".to_string()]
    }
    fn mutating(&self, _method: &str) -> bool {
        false
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("pong")))
    }
}

#[test]
fn a_provider_may_call_the_agent_from_methods() {
    let agent = Agent::with_secret([0x42; 32]);
    // The surface is described at registration, with no kernel borrow held, so
    // a provider may consult the agent there (R-17 round 3, M-2).
    let slot = Rc::new(RefCell::new(Some(agent.clone())));
    let lanes = Rc::new(Cell::new(0));
    let provider = agent.register(Box::new(Reentrant {
        agent: Rc::clone(&slot),
        lanes: Rc::clone(&lanes),
    }));
    assert_eq!(lanes.get(), 1, "the provider ran with no borrow held");
    let bytes = agent.intro().expect("intro with a re-entrant provider");
    assert!(!bytes.is_empty());
    assert_eq!(lanes.get(), 1, "intro reads the captured surface");
    // The provider is still registered.
    assert!(agent.mint(provider, 0, CapAttrs::new(&["ping"])).is_ok());
}

/// 2.10 / 13 - a message is a bounded transfer, and a closed channel is not
/// "busy".
#[test]
fn a_message_carries_a_bounded_number_of_capabilities() {
    let (agent, provider) = agent();
    let lane = agent.create_lane("caps", Budget::default()).expect("lane");
    let channel = agent
        .create_channel("caps", Direction::Both)
        .expect("channel");
    let caps: Vec<_> = (0..=active_rpc::kernel::MAX_CAPS_PER_MESSAGE)
        .map(|_| {
            agent
                .mint(provider, 0, CapAttrs::new(&["ping"]))
                .expect("mint")
        })
        .collect();
    assert_eq!(
        agent
            .send(lane, channel, Value::text("x"), &caps)
            .expect_err("a transfer that large is a flood")
            .code(),
        "rpc/budget-exceeded"
    );

    // A full channel that is then closed answers "closed", not "retry".
    let small = agent
        .create_channel("small", Direction::Both)
        .expect("channel");
    let narrow = agent
        .create_lane(
            "narrow",
            Budget {
                max_value_size: u64::MAX,
                ..Budget::default()
            },
        )
        .expect("lane");
    for index in 0..active_rpc::channel::MAX_QUEUED_PER_CHANNEL {
        agent
            .send(narrow, small, Value::text(format!("m{index}")), &[])
            .expect("fill");
    }
    agent.close_channel(small).expect("close");
    assert_eq!(
        agent
            .send(narrow, small, Value::text("late"), &[])
            .expect_err("a closed channel refuses")
            .code(),
        "rpc/invalid-argument"
    );
}

/// The identity type is public so a test can build one; this keeps the import
/// used when the peer is admitted from a policy.
#[allow(dead_code)]
fn admitted(certificate: &[u8]) -> AdmittedIdentity {
    IdentityPolicy::strict()
        .admit(Some(&PeerIdentity::from_certificate(certificate)), false)
        .expect("admitted")
}
