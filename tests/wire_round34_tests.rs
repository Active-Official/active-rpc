//! R-01 wire, round 34: the encoder's value budget is cumulative across the
//! whole frame, exactly as the decoder's is.

use active_rpc::value::{Arg, Value};
use active_rpc::wire::{Envelope, WireLimits};

/// Two arguments that each fit the value ceiling are still over it together;
/// the decoder counts the whole frame (round 34, #4).
#[test]
fn the_value_ceiling_is_cumulative_across_arguments() {
    let limits = WireLimits::default();
    let half = limits.max_values / 2 + 1;
    let arg = Value::list((0..half).map(|_| Value::Null));
    let envelope = Envelope::request(1, "p", vec![Arg::Value(arg.clone()), Arg::Value(arg)]);
    let error = envelope
        .encode()
        .expect_err("the two arguments together pass the ceiling");
    assert_eq!(error.code(), "rpc/wire", "{error}");

    // One argument of the same shape is under the ceiling and round-trips.
    let single = Value::list((0..half).map(|_| Value::Null));
    let bytes = Envelope::request(1, "p", vec![Arg::Value(single)])
        .encode()
        .expect("one argument fits");
    Envelope::decode(&bytes).expect("the decoder agrees");
}
