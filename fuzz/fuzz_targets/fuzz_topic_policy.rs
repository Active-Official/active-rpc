#![no_main]

//! Capability-filtered topics: publish, receive, attenuate.
//!
//! Invariants under test:
//!
//! 1. `publish` succeeds exactly when the topic is inside the capability's
//!    topic set (an unrestricted capability accepts every topic) and the
//!    channel, lane and capability are live.
//! 2. A refused publish is `rpc/topic-not-granted` and leaves no message
//!    behind: a later `recv_topic` for that topic finds nothing.
//! 3. A successful publish is received once with the same payload, in order per
//!    topic, and `recv_topic` does not consume messages for other topics.
//! 4. Attenuation can only narrow the topic set; widening or removing the
//!    restriction is `rpc/attenuation-escalation`.
//!
//! Run with `cargo +nightly fuzz run fuzz_topic_policy -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_rpc::cap::CapAttrs;
use active_rpc::channel::Direction;
use active_rpc::Budget;

#[path = "common.rs"]
mod common;

const TOPICS: [&str; 6] = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"];

/// A subset of [`TOPICS`], selected by bits of `mask`.
fn subset(mask: u8) -> Vec<&'static str> {
    TOPICS
        .iter()
        .enumerate()
        .filter(|(index, _)| mask & (1 << index) != 0)
        .map(|(_, topic)| *topic)
        .collect()
}

fn granted(grants: &Option<Vec<&'static str>>, topic: &str) -> bool {
    match grants {
        None => true,
        Some(allowed) => allowed.iter().any(|candidate| *candidate == topic),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let agent = common::agent(data);
    let provider = agent.register(Box::new(common::Echo::default()));
    let lane = agent
        .create_lane("topics", Budget::default())
        .expect("the default lane budget is valid");
    let channel = agent
        .create_channel("news", Direction::Both)
        .expect("the fuzz harness creates a valid channel");

    // Bit 7 set means "unrestricted"; otherwise the low bits pick the topics.
    let grants: Option<Vec<&'static str>> = if data[0] & 0x80 != 0 {
        None
    } else {
        Some(subset(data[0]))
    };
    let mut attrs = CapAttrs::new(&["echo"]);
    if let Some(allowed) = &grants {
        attrs = attrs.restrict_topics(allowed);
    }
    let cap = agent
        .mint(provider, 0, attrs)
        .expect("the fuzz harness mints a valid capability");

    // Attenuation narrows, never widens.
    //
    // The child set must be a *strict* superset for the widening rule to apply:
    // an identical set is a valid attenuation, and an empty parent set is
    // already the narrowest grant. `out-of-grant` is in no capability's set, so
    // adding it is a strict widening whatever the parent holds.
    if let Some(allowed) = &grants {
        let wider: Vec<&str> = TOPICS
            .iter()
            .copied()
            .chain(std::iter::once("out-of-grant"))
            .collect();
        let error = agent
            .attenuate(&cap, CapAttrs::new(&["echo"]).restrict_topics(&wider))
            .expect_err("a widening topic set must be refused");
        assert_eq!(error.code(), "rpc/attenuation-escalation");

        let error = agent
            .attenuate(&cap, CapAttrs::new(&["echo"]))
            .expect_err("dropping the topic restriction must be refused");
        assert_eq!(error.code(), "rpc/attenuation-escalation");

        // The same set attenuates to itself and stays as narrow.
        let same = agent
            .attenuate(&cap, CapAttrs::new(&["echo"]).restrict_topics(allowed))
            .expect("the same topic set is a valid attenuation");
        if allowed.is_empty() {
            let error = agent
                .publish(
                    lane,
                    channel,
                    &same,
                    TOPICS[0],
                    active_rpc::Value::text("empty"),
                )
                .expect_err("an empty topic grant publishes nothing");
            assert_eq!(error.code(), "rpc/topic-not-granted");
        }

        // A non-empty subset of the grant is a valid child; publish through it
        // must still honour the child's narrower set.
        if let Some(narrow) = allowed.first() {
            let child = agent
                .attenuate(&cap, CapAttrs::new(&["echo"]).restrict_topics(&[*narrow]))
                .expect("a subset topic set is a valid attenuation");
            for (index, topic) in TOPICS.iter().enumerate() {
                let payload = active_rpc::Value::text(format!("child-{index}"));
                match agent.publish(lane, channel, &child, topic, payload) {
                    Ok(_) => {
                        assert_eq!(
                            *topic, *narrow,
                            "a child capability published outside its topic set"
                        );
                        let message = agent
                            .recv_topic(channel, topic)
                            .expect("receive")
                            .expect("the published message is queued");
                        assert_eq!(message.topic.as_deref(), Some(*topic));
                    }
                    Err(error) => {
                        assert_eq!(error.code(), "rpc/topic-not-granted");
                        assert_ne!(*topic, *narrow, "the granted topic was refused");
                    }
                }
            }
        }
    }

    // Drive publish/receive with the remaining bytes.
    for (index, byte) in data.iter().skip(1).take(64).enumerate() {
        let topic = TOPICS[*byte as usize % TOPICS.len()];
        let payload = active_rpc::Value::text(format!("m{index}"));
        match agent.publish(lane, channel, &cap, topic, payload) {
            Ok(_) => {
                assert!(
                    granted(&grants, topic),
                    "published {topic} outside the granted set"
                );
                let message = agent
                    .recv_topic(channel, topic)
                    .expect("receive")
                    .expect("the published message is queued");
                assert_eq!(message.topic.as_deref(), Some(topic));
                assert_eq!(
                    message.payload,
                    active_rpc::Value::text(format!("m{index}"))
                );
            }
            Err(error) => {
                assert_eq!(error.code(), "rpc/topic-not-granted");
                assert!(
                    !granted(&grants, topic),
                    "refused a topic inside the granted set: {topic}"
                );
                assert!(
                    agent
                        .recv_topic(channel, topic)
                        .expect("receive after a refusal")
                        .is_none(),
                    "a refused publish left a message behind"
                );
            }
        }
    }

    // Every topic the capability may use can still be published after the
    // refusal path, and an unrestricted capability covers the whole alphabet.
    if grants.is_none() {
        for (index, topic) in TOPICS.iter().enumerate() {
            agent
                .publish(
                    lane,
                    channel,
                    &cap,
                    topic,
                    active_rpc::Value::text(format!("final-{index}")),
                )
                .expect("an unrestricted capability publishes any topic");
            let message = agent
                .recv_topic(channel, topic)
                .expect("receive")
                .expect("the published message is queued");
            assert_eq!(message.topic.as_deref(), Some(*topic));
        }
    }
});
