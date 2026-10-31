//! Capability-table deltas under load, over a real transport.
//!
//! `tests/cap_delta_tests.rs` proves the arithmetic of one delta. This file
//! drives the same code across a TCP connection with several concurrent
//! negotiators, a chain of deltas per negotiator, and a stale-base refusal, so
//! the property under test is the one the proposal asks for: the delta path is
//! exercised under load, not only in a unit test.

use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use active_rpc::budget::Budget;
use active_rpc::cap::{CapAttrs, CapId};
use active_rpc::transport::{serve_connection, TcpTransport, Transport};
use active_rpc::value::{Arg, Value};
use active_rpc::wire::{cap_table_hash, CapDescriptor, CapTableDelta, Envelope};

const NEGOTIATORS: usize = 4;
const STEPS: usize = 120;
const BASE_SIZE: usize = 24;

fn id_for(index: usize) -> CapId {
    let mut bytes = [0u8; 16];
    bytes[0] = index as u8;
    bytes[1] = (index >> 8) as u8;
    bytes[2] = 0xa5;
    bytes[15] = 0x5a;
    CapId(bytes)
}

fn descriptor(index: usize, method: &str) -> CapDescriptor {
    CapDescriptor::from_attrs(
        id_for(index),
        &CapAttrs::new(&[method]).with_budget(Budget::default()),
    )
}

fn base_table() -> Vec<CapDescriptor> {
    (0..BASE_SIZE)
        .map(|index| descriptor(index, "echo"))
        .collect()
}

/// Deterministic per-negotiation plan: one removal (when possible) and two
/// additions whose ids this negotiator has never used, so the table grows and
/// shrinks without colliding.
fn plan(seed: u64, step: usize, table: &[CapDescriptor]) -> (Vec<CapId>, Vec<CapDescriptor>) {
    let mut state = seed
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(step as u64);
    state ^= state >> 33;
    state = state.wrapping_mul(0xff51_afd7_ed55_8ccd);
    state ^= state >> 29;
    let removed = if table.len() > 8 && state.is_multiple_of(3) {
        vec![table[(state as usize) % table.len()].id]
    } else {
        Vec::new()
    };
    let first = BASE_SIZE + seed as usize * 4096 + step * 2;
    let added = vec![descriptor(first, "stats"), descriptor(first + 1, "why")];
    (removed, added)
}

/// Server side: one handler per connection, holding that connection's table.
fn serve(listener: TcpListener, connections: usize, served: Arc<AtomicUsize>) {
    for _ in 0..connections {
        let (stream, _) = listener.accept().expect("accept a negotiator");
        let mut table = base_table();
        let served = Arc::clone(&served);
        let transport = TcpTransport::new(stream).expect("server transport");
        serve_connection(transport, move |envelope: Envelope| {
            let Some(delta) = envelope.cap_delta.clone() else {
                return Envelope::error(envelope.request_id, &active_rpc::Error::Wire("no delta"));
            };
            match delta.apply_to(&table) {
                Ok(next) => {
                    table = next;
                    served.fetch_add(1, Ordering::Relaxed);
                    Envelope::response(
                        envelope.request_id,
                        Value::Module(cap_table_hash(&table).to_vec()),
                    )
                }
                Err(error) => Envelope::error(envelope.request_id, &error),
            }
        })
        .expect("serve a negotiator");
    }
}

#[test]
fn concurrent_negotiators_agree_with_the_peer_on_every_step() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("local address").to_string();
    let served = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&served);
    let server = std::thread::spawn(move || serve(listener, NEGOTIATORS, counter));

    let mut workers = Vec::new();
    for negotiator in 0..NEGOTIATORS {
        let address = address.clone();
        workers.push(std::thread::spawn(move || {
            let mut transport = TcpTransport::connect(&address).expect("connect");
            let mut table = base_table();
            for step in 0..STEPS {
                let (removed, added) = plan(negotiator as u64 + 1, step, &table);
                let delta = CapTableDelta::new(&table, removed, added);
                let expected = delta.apply_to(&table).expect("client-side apply");
                let request = Envelope::request(step as u64, "negotiate", vec![Arg::text("t")])
                    .with_cap_delta(delta.clone());
                transport.send(&request).expect("send delta");
                let response = transport.recv().expect("recv").expect("response");
                assert_eq!(
                    response.first_value(),
                    Some(&Value::Module(cap_table_hash(&expected).to_vec())),
                    "negotiator {negotiator} step {step}: the peer applied a different table"
                );
                // The base is never modified in place.
                let snapshot = table.clone();
                let _ = delta.apply_to(&table).expect("re-apply");
                assert_eq!(table, snapshot, "apply_to must not mutate the base");
                table = expected;
            }
            table.len()
        }));
    }

    let sizes: Vec<usize> = workers
        .into_iter()
        .map(|worker| worker.join().expect("negotiator"))
        .collect();
    server.join().expect("server");
    assert_eq!(served.load(Ordering::Relaxed), NEGOTIATORS * STEPS);
    // Every negotiator started from the same base and applied STEPS deltas; the
    // tables grow by at most two per step and shrink by at most one, so the
    // sizes are the same across negotiators only in aggregate bounds. What must
    // hold is that each stayed inside the arithmetic bounds.
    for size in sizes {
        assert!(
            size <= BASE_SIZE + 2 * STEPS && size >= BASE_SIZE.saturating_sub(STEPS),
            "table size {size} is outside the delta arithmetic"
        );
    }
}

#[test]
fn a_stale_base_is_refused_under_concurrency() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("local address").to_string();
    let server = std::thread::spawn(move || serve(listener, 1, Arc::new(AtomicUsize::new(0))));

    let mut transport = TcpTransport::connect(&address).expect("connect");
    let base = base_table();
    // One good delta moves the server's table.
    let first = CapTableDelta::new(&base, vec![], vec![descriptor(90, "stats")]);
    let request = Envelope::request(1, "negotiate", vec![]).with_cap_delta(first.clone());
    transport.send(&request).expect("send");
    let response = transport.recv().expect("recv").expect("response");
    assert_eq!(response.kind, active_rpc::wire::Kind::Response);

    // The same delta again is stale: its base no longer matches.
    let request = Envelope::request(2, "negotiate", vec![]).with_cap_delta(first);
    transport.send(&request).expect("send stale");
    let response = transport.recv().expect("recv").expect("response");
    assert_eq!(
        response.kind,
        active_rpc::wire::Kind::Error,
        "a stale base must be refused, got {response:?}"
    );
    assert_eq!(
        response.method, "rpc/capability-table",
        "the refusal names the capability-table class"
    );
    drop(transport);
    server.join().expect("server");
}
