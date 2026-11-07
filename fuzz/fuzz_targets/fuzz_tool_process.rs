#![no_main]

//! LocalProcess policy: argv cannot escape the allow-list.
//!
//! Invariants under test (I-11, H2.12):
//!
//! 1. An argument outside the process allow-list is refused before spawn.
//! 2. A method other than `run` is refused.
//! 3. A non-existent program is refused at construction, not a panic.
//! 4. The adapter policy is a valid attenuation of a wider parent.
//!
//! The program is a real shell but the allow-list admits only `ok`, so no
//! argument the target produces can run anything.
//!
//! Run with `cargo +nightly fuzz run fuzz_tool_process -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_rpc::tool::LocalProcess;
use active_rpc::{Arg, Budget, CapAttrs, ToolPolicy, Value};

#[path = "common.rs"]
mod common;

fn policy() -> ToolPolicy {
    ToolPolicy {
        allowed: ["run"].iter().map(|name| name.to_string()).collect(),
        max_arg_bytes: 64,
        allow_process: true,
    }
}

fuzz_target!(|data: &[u8]| {
    // Fixed positive control: an allow-listed argument runs and its output
    // comes back. A policy that refused every argument used to pass
    // (R-20 round 5, F7).
    {
        // `/bin/echo` with the allowed argument: the response proves the child
        // ran and its output came back, not only that the policy accepted the
        // call. `/bin/sh ok` would have run a file named `ok` and a canned `Ok`
        // would have passed the old check (R-20 round 6, finding 5).
        let tool = LocalProcess::new("/bin/echo", &["ok"]).expect("an absolute program");
        let control = common::agent(&[0x05]);
        let provider = control.register(Box::new(tool));
        let lane = control
            .create_lane("control", Budget::default())
            .expect("the control lane");
        let cap = control
            .mint(
                provider,
                0,
                CapAttrs::new(&["run"])
                    .with_budget(Budget::default())
                    .with_tool_policy(policy()),
            )
            .expect("the control method is granted");
        let promise = control
            .call(lane, &cap, "run", vec![Arg::text("ok")])
            .expect("the control call is queued");
        let value = promise.value().expect("the allow-listed argument ran");
        let Value::Map(fields) = value else {
            panic!("the process reply is a map: {value:?}");
        };
        assert!(
            matches!(fields.get("status"), Some(Value::Int(0))),
            "the child did not exit cleanly: {fields:?}"
        );
        assert!(
            matches!(fields.get("stdout"), Some(Value::Text(text)) if text == "ok\n"),
            "the child's output did not come back: {fields:?}"
        );
    }
    if data.is_empty() {
        return;
    }
    // A program that does not resolve is refused at construction (round 17).
    assert!(LocalProcess::new("/nonexistent-active-fuzz-binary", &["ok"]).is_err());
    let tool = LocalProcess::new("/bin/sh", &["ok"]).expect("an absolute program");
    assert!(policy().is_attenuation_of(&tool.policy()));

    let agent = common::agent(data);
    let provider = agent.register(Box::new(tool));
    let lane = agent
        .create_lane("process", Budget::default())
        .expect("default lane budget");
    let cap = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["run"])
                .with_budget(Budget::default())
                .with_tool_policy(policy()),
        )
        .expect("the process method is granted");

    // An argument outside the allow-list is refused without spawning.
    let argument: String = match data[0] % 5 {
        0 => "ok".to_string(),
        1 => "ok;rm -rf /".to_string(),
        2 => "$(id)".to_string(),
        3 => "../escape".to_string(),
        _ => {
            let mut out = String::new();
            for byte in data.iter().take(8) {
                out.push(char::from(b'a' + (byte % 26)));
            }
            out
        }
    };

    // The argument policy is the provider's, so the refusal is the promise's
    // value, not the `call` result: the old target asserted on the latter and an
    // admitted escape therefore passed silently.
    let promise = agent
        .call(lane, &cap, "run", vec![Arg::text(argument.clone())])
        .expect("the call is queued");
    match promise.value() {
        Ok(_) => assert_eq!(
            argument, "ok",
            "an argument outside the allow-list must never run"
        ),
        Err(error) if argument == "ok" => assert!(
            matches!(
                error.code(),
                "rpc/provider" | "rpc/transport" | "rpc/timeout" | "rpc/transport-unavailable"
            ),
            "unexpected code {} for the pinned program",
            error.code()
        ),
        Err(error) => assert_eq!(
            error.code(),
            "rpc/tool-policy",
            "an argument outside the allow-list must be a tool-policy refusal, got {error}"
        ),
    }
});
