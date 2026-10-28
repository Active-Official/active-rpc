//! The control plane's claims are tested against the real engines.
//!
//! Every test drives [`PlaneCore`], which owns a real `active-rpc::Agent` and
//! calls the shipped `active-infinity` codec. No fixture stubs the counters.

use active_control_plane::plane::{scenario_def, PlaneCore, SCENARIOS};

fn scenario(core: &mut PlaneCore, id: &str) -> serde_json::Value {
    let result = core.run_scenario(id).expect("scenario");
    serde_json::to_value(result).expect("serialize")
}

#[test]
fn round_trip_observes_real_codec_work() {
    let mut core = PlaneCore::new();
    let before = core.snapshot();
    let result = scenario(&mut core, "round-trip");
    let after = core.snapshot();
    // snapshot() itself refreshes the status module, so the counter deltas
    // include the status build as well as the scenario's round-trip.
    assert!(after.infinity.counters.encodes > before.infinity.counters.encodes);
    assert!(after.infinity.counters.validates > before.infinity.counters.validates);
    assert!(after.infinity.counters.hashes > before.infinity.counters.hashes);
    assert!(after.infinity.counters.decodes > before.infinity.counters.decodes);
    assert_eq!(result["data"]["stable"], true);
    assert!(result["data"]["bytes"].as_u64().unwrap_or(0) > 0);
    assert!(after.infinity.timings.encode_us > 0.0);
    assert!(after.infinity.timings.validate_us > 0.0);
    // The round-trip records a real canonical sample and a hash spotlight.
    assert!(after.activity.hash_prefix.is_some());
    assert!(after.metrics.canonical_samples >= 1);
    assert!(after.metrics.canonical_ok_rate > 0.0);
}

#[test]
fn pipelining_uses_fewer_round_trips_and_is_repeatable() {
    let mut core = PlaneCore::new();
    let first = scenario(&mut core, "pipeline");
    let second = scenario(&mut core, "pipeline");
    for result in [first, second] {
        let sequential = result["data"]["sequential_round_trips"]
            .as_u64()
            .expect("seq");
        let pipelined = result["data"]["pipelined_round_trips"]
            .as_u64()
            .expect("pipe");
        assert_eq!(sequential, 6);
        assert_eq!(pipelined, 1);
        assert!(pipelined < sequential);
    }
    let snapshot = core.snapshot();
    assert_eq!(snapshot.activity.mode, "RpcBatch");
    assert_eq!(snapshot.activity.promise_chain.len(), 6);
    assert!(snapshot.activity.stages.len() >= 2);
}

#[test]
fn a_widening_attempt_is_refused_by_the_kernel() {
    let mut core = PlaneCore::new();
    let result = scenario(&mut core, "attenuation");
    assert_eq!(result["ok"], true);
    assert_eq!(result["data"]["code"], "rpc/attenuation-escalation");
}

#[test]
fn a_real_budget_is_exhausted() {
    let mut core = PlaneCore::new();
    let before = core.snapshot().metrics.budget_exhaustions;
    let result = scenario(&mut core, "budget");
    let after = core.snapshot().metrics.budget_exhaustions;
    assert_eq!(result["ok"], true);
    assert_eq!(result["data"]["code"], "rpc/budget-exceeded");
    assert_eq!(after, before + 1);
}

#[test]
fn a_real_tool_policy_refuses_work() {
    let mut core = PlaneCore::new();
    let result = scenario(&mut core, "tool-policy");
    assert_eq!(result["ok"], true);
    assert_eq!(result["data"]["code"], "rpc/tool-policy");
}

#[test]
fn streaming_reassembles_the_canonical_image() {
    let mut core = PlaneCore::new();
    let result = scenario(&mut core, "streaming");
    assert_eq!(result["ok"], true);
    assert_eq!(result["data"]["stable"], true);
    assert!(result["data"]["frames"].as_u64().unwrap_or(0) > 0);
    let snapshot = core.snapshot();
    assert!(snapshot.metrics.stream_frames_per_s >= 0.0);
    assert!(snapshot.infinity.counters.streaming_frames > 0);
}

#[test]
fn lanes_are_served_in_one_provider_batch() {
    let mut core = PlaneCore::new();
    let result = scenario(&mut core, "lanes");
    assert_eq!(result["ok"], true);
    assert_eq!(result["data"]["round_trips"], 1);
    assert_eq!(result["data"]["lanes"], 4);
    let engines = core.snapshot().engines;
    assert_eq!(engines.lanes.len(), 4);
    assert_eq!(engines.channels.len(), 2);
    assert!(engines.lanes.iter().any(|lane| lane.completed > 0));
}

#[test]
fn channel_share_transfers_a_capability_id_by_reference() {
    let mut core = PlaneCore::new();
    let result = scenario(&mut core, "channel-share");
    assert_eq!(result["ok"], true);
    assert_eq!(result["data"]["shared"], true);
    assert_eq!(result["data"]["caps"], 1);
}

#[test]
fn revoke_before_dispatch_never_reaches_the_provider() {
    let mut core = PlaneCore::new();
    let result = scenario(&mut core, "revoke");
    assert_eq!(result["ok"], true);
    assert_eq!(result["data"]["code"], "rpc/revoked");
}

#[test]
fn the_snapshot_never_contains_the_secret_canary() {
    let mut core = PlaneCore::new();
    scenario(&mut core, "redaction");
    let snapshot = serde_json::to_string(&core.snapshot()).expect("json");
    assert!(!snapshot.contains(active_control_plane::plane::SECRET_CANARY));
    assert!(core.snapshot().health.redaction_ok);
    // Events are redacted too, including their structured fields.
    let log = serde_json::to_string(&core.events_after(0)).expect("events");
    assert!(!log.contains(active_control_plane::plane::SECRET_CANARY));
}

#[test]
fn metrics_change_by_the_real_call_count() {
    let mut core = PlaneCore::new();
    let before = core.snapshot().metrics.calls_queued;
    scenario(&mut core, "pipeline");
    let after = core.snapshot().metrics.calls_queued;
    // Six sequential + six pipelined calls.
    assert_eq!(after, before + 12);
}

#[test]
fn benchmark_exports_the_samples_it_measured() {
    let mut core = PlaneCore::new();
    let report = core.run_benchmark(20).expect("benchmark");
    assert_eq!(report.encode.n, 20);
    assert_eq!(report.validate.n, 20);
    assert!(report.encode.p50_us > 0.0);
    assert!(report.validate.p50_us > 0.0);
    assert_eq!(report.samples["encode"].len(), 20);
    assert!(report.csv.starts_with("workload,iteration,microseconds\n"));
    let second = core.run_benchmark(20).expect("benchmark");
    assert_eq!(second.encode.n, report.encode.n);
    assert_eq!(second.validate.n, report.validate.n);
}

#[test]
fn status_module_is_valid_ainf_with_a_matching_hash() {
    use base64::Engine;
    let mut core = PlaneCore::new();
    let value = core.status_module_json().expect("status module");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value["bytes_base64"].as_str().expect("base64"))
        .expect("valid base64");
    let meta = active_infinity::validate(&bytes).expect("valid AINF");
    let expected = active_infinity::content_hash(&bytes).expect("hash");
    assert_eq!(
        value["hash"],
        expected
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    assert!(meta.nodes > 0);
    assert!(!value["redacted_json"]
        .as_str()
        .unwrap_or("")
        .contains(active_control_plane::plane::SECRET_CANARY));
}

#[test]
fn every_ladder_step_runs_real_code_and_passes() {
    let mut core = PlaneCore::new();
    for def in SCENARIOS {
        let result = core.run_scenario(def.id).expect("scenario");
        assert!(result.ok, "{} failed: {}", def.id, result.detail);
        assert_eq!(result.code, def.code);
        assert_eq!(result.level, def.level);
        assert!(result.duration_us > 0, "{} reported no duration", def.id);
    }
    let snapshot = core.snapshot();
    assert_eq!(snapshot.scenario_results.len(), SCENARIOS.len());
    // Every scenario appended a structured SCENARIO event with its id.
    for def in SCENARIOS {
        assert!(
            snapshot
                .events
                .iter()
                .any(|event| event.category == "scenario"
                    && event.scenario_id.as_deref() == Some(def.id)),
            "missing scenario event for {}",
            def.id
        );
    }
}

#[test]
fn the_ladder_covers_every_level_from_zero_to_six() {
    let levels: std::collections::BTreeSet<u8> = SCENARIOS.iter().map(|def| def.level).collect();
    assert_eq!(levels, (0u8..=6).collect());
    for def in SCENARIOS {
        assert_eq!(scenario_def(def.id).map(|item| item.code), Some(def.code));
    }
    assert!(scenario_def("nope").is_none());
}

#[test]
fn run_level_returns_the_steps_at_or_below_the_cut() {
    let mut core = PlaneCore::new();
    let smoke = core.run_level(0, false);
    assert_eq!(smoke.len(), 3);
    let up_to_one = core.run_level(1, true);
    assert_eq!(up_to_one.len(), 8);
    assert!(up_to_one.iter().all(|result| result.ok));
    let snapshot = core.snapshot();
    assert_eq!(snapshot.scenario_results.len(), 8);
    assert_eq!(
        snapshot
            .last_scenario
            .as_ref()
            .map(|result| result.code.as_str()),
        Some("L1.5")
    );
    assert!(core.run_level(7, false).is_empty());
    assert!(core.run_level(7, true).is_empty());
}

#[test]
fn idle_rates_are_zero_and_gauges_record_real_samples() {
    let mut core = PlaneCore::new();
    let first = core.snapshot();
    assert_eq!(first.metrics.calls_per_second, 0.0);
    assert_eq!(first.metrics.settled_per_s, 0.0);
    assert_eq!(first.metrics.tool_calls_per_s, 0.0);
    assert_eq!(first.metrics.tool_refusals_per_s, 0.0);
    assert_eq!(first.metrics.stream_frames_per_s, 0.0);
    assert_eq!(first.metrics.queue_depth, 0);
    assert_eq!(first.gauge_samples.len(), 20);
    for samples in first.gauge_samples.values() {
        assert_eq!(samples.len(), 1);
    }
    let second = core.snapshot();
    for samples in second.gauge_samples.values() {
        assert_eq!(samples.len(), 2);
    }
    assert!(second.gauge_samples["encode_us"][1].value > 0.0);
}

#[test]
fn events_carry_structured_fields_and_a_working_cursor() {
    let mut core = PlaneCore::new();
    core.run_scenario("pipeline").expect("scenario");
    let all = core.events_after(0);
    assert!(all.len() >= 3);
    let scenario_event = all
        .iter()
        .find(|event| event.scenario_id.as_deref() == Some("pipeline"))
        .expect("scenario event");
    assert_eq!(scenario_event.category, "scenario");
    assert_eq!(scenario_event.kind, "scenario");
    assert!(scenario_event.duration_us.unwrap_or(0.0) > 0.0);
    assert!(all.iter().all(|event| event.id > 0));
    let cursor = all[all.len() / 2].id;
    let later = core.events_after(cursor);
    assert!(later.iter().all(|event| event.id > cursor));
    assert!(later.len() < all.len());
}

#[test]
fn engines_replace_the_old_topology_with_real_registries() {
    let mut core = PlaneCore::new();
    let snapshot = core.snapshot();
    assert_eq!(snapshot.engines.lanes.len(), 4);
    assert_eq!(snapshot.engines.channels.len(), 2);
    assert_eq!(snapshot.engines.capabilities.len(), 10);
    assert!(snapshot
        .engines
        .capabilities
        .iter()
        .all(|cap| cap.id.len() == 16 && cap.id.chars().all(|ch| ch.is_ascii_hexdigit())));
    let json = serde_json::to_value(&snapshot).expect("json");
    assert!(json.get("topology").is_none());
    assert!(json.get("engines").is_some());
    assert!(json.get("activity").is_some());
}

#[test]
fn health_and_scenario_allow_list_are_stable() {
    let mut core = PlaneCore::new();
    let snapshot = core.snapshot();
    let first = snapshot.scenario_ids;
    let second = core.snapshot().scenario_ids;
    assert_eq!(first, second);
    assert_eq!(first.len(), SCENARIOS.len());
    assert_eq!(snapshot.health.kernel, "up");
    assert_eq!(snapshot.health.mode, "demo");
    assert_eq!(snapshot.activity.mode, "Idle");
    assert!(snapshot.activity.summary.contains("listening"));
}

#[test]
fn every_refusal_facet_is_recorded() {
    let mut core = PlaneCore::new();
    core.run_scenario("tool-policy").expect("tool policy");
    core.run_scenario("budget").expect("budget");
    core.run_scenario("revoke").expect("revoke");
    let snapshot = core.snapshot();
    let events = snapshot.events;
    // Both the generic call refusal and the specific policy/budget event are
    // true observations and stay visible.
    assert!(events
        .iter()
        .any(|event| event.kind == "call_refused"
            && event.code.as_deref() == Some("rpc/tool-policy")));
    assert!(events.iter().any(|event| event.kind == "tool_refused"));
    assert!(events.iter().any(|event| event.kind == "call_refused"
        && event.code.as_deref() == Some("rpc/budget-exceeded")));
    assert!(events.iter().any(|event| event.kind == "budget"));
    assert!(events
        .iter()
        .any(|event| event.kind == "call_refused" && event.code.as_deref() == Some("rpc/revoked")));
    assert!(snapshot.metrics.tool_refusals >= 1);
    assert!(snapshot.metrics.budget_exhaustions >= 1);
}

#[test]
fn http_and_process_tools_survive_repeated_runs() {
    let mut core = PlaneCore::new();
    for round in 0..10 {
        let result = core.run_scenario("http-tool").expect("http scenario");
        assert!(result.ok, "http round {round}: {}", result.detail);
        let result = core
            .run_scenario("local-process")
            .expect("process scenario");
        assert!(result.ok, "process round {round}: {}", result.detail);
    }
    let snapshot = core.snapshot();
    assert_eq!(snapshot.health.kernel, "up");
    assert!(snapshot.engines.capabilities.len() >= 10);
}

#[test]
fn read_only_mode_is_labeled_without_changing_observations() {
    let mut core = PlaneCore::new();
    core.set_mode("read-only");
    let snapshot = core.snapshot();
    assert_eq!(snapshot.health.mode, "read-only");
    assert!(snapshot.infinity.counters.encodes > 0);
}
