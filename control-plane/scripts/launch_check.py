#!/usr/bin/env python3
"""Start the shipped control plane twice and assert the documented shape.

Run from `control-plane/` after `cargo build`:

    python scripts/launch_check.py

The harness starts a fresh process on two ports, asserts the field set, runs
the pipelining scenario, and requires the exact deterministic counter deltas
(12 queued calls, 7 provider round-trips) on both launches.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = (
    ROOT
    / "target"
    / "debug"
    / (
        "active-control-plane.exe"
        if sys.platform == "win32"
        else "active-control-plane"
    )
)
PORTS = (8891, 8892)


def get(base: str, path: str) -> dict:
    with urllib.request.urlopen(base + path, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def post(base: str, path: str) -> dict:
    request = urllib.request.Request(
        base + path,
        data=b"{}",
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def wait_ready(base: str) -> None:
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            health = get(base, "/health")
            if health.get("ok"):
                return
        except (urllib.error.URLError, ConnectionError):
            pass
        time.sleep(0.2)
    raise RuntimeError(f"{base} did not become ready")


def assert_shape(snapshot: dict, label: str) -> None:
    required = {
        "ts_ms",
        "uptime_ms",
        "health",
        "metrics",
        "infinity",
        "engines",
        "events",
        "scenarios",
        "activity",
        "gauge_samples",
        "last_error_code",
    }
    missing = required - set(snapshot)
    assert not missing, f"{label}: snapshot missing {sorted(missing)}"
    metrics = snapshot["metrics"]
    for field in (
        "calls_queued",
        "calls_refused",
        "round_trips",
        "promise_records",
        "active_lanes",
        "active_channels",
        "caps_live",
        "canonical_ok_rate",
        "p99_call_us",
    ):
        assert field in metrics, f"{label}: metrics missing {field}"
    assert len(snapshot["engines"]["lanes"]) == 4, f"{label}: lanes"
    assert len(snapshot["engines"]["channels"]) == 2, f"{label}: channels"
    assert len(snapshot["engines"]["capabilities"]) == 10, f"{label}: capabilities"
    assert len(snapshot["scenarios"]) == 22, f"{label}: ladder size"
    assert len(snapshot["gauge_samples"]) == 20, f"{label}: gauge samples"
    assert snapshot["health"]["kernel"] == "up", f"{label}: kernel"
    assert snapshot["health"]["redaction_ok"] is True, f"{label}: redaction"


def one_launch(port: int, label: str) -> list[str]:
    base = f"http://127.0.0.1:{port}"
    log = [f"== {label} on {base} =="]
    process = subprocess.Popen(
        [str(BINARY), "--port", str(port)],
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        wait_ready(base)
        before = get(base, "/metrics")
        assert_shape(before, label)
        log.append(
            "before: calls_queued={calls_queued} round_trips={round_trips} lanes={lanes} "
            "channels={channels} caps={caps} gauges={gauges}".format(
                calls_queued=before["metrics"]["calls_queued"],
                round_trips=before["metrics"]["round_trips"],
                lanes=len(before["engines"]["lanes"]),
                channels=len(before["engines"]["channels"]),
                caps=len(before["engines"]["capabilities"]),
                gauges=len(before["gauge_samples"]),
            )
        )
        result = post(base, "/demo/scenario/pipeline")
        after = get(base, "/metrics")
        assert result["result"]["ok"] is True, f"{label}: pipeline failed"
        assert result["result"]["code"] == "L1.1", f"{label}: pipeline code"
        delta_calls = (
            after["metrics"]["calls_queued"] - before["metrics"]["calls_queued"]
        )
        delta_round_trips = (
            after["metrics"]["round_trips"] - before["metrics"]["round_trips"]
        )
        assert delta_calls == 12, f"{label}: expected 12 calls, got {delta_calls}"
        assert delta_round_trips == 7, (
            f"{label}: expected 7 round-trips, got {delta_round_trips}"
        )
        activity = get(base, "/activity")
        assert activity["mode"] == "RpcBatch", f"{label}: activity mode"
        assert len(activity["promise_chain"]) == 6, f"{label}: promise chain"
        assert len(activity["stages"]) >= 2, f"{label}: stages"
        page = urllib.request.urlopen(base + "/", timeout=10).read().decode("utf-8")
        for marker in ("Live activity", "Live gauges", "Scenario ladder"):
            assert marker in page, f"{label}: dashboard missing {marker}"
        assert "Topology" not in page, f"{label}: topology still present"
        log.extend(
            [
                f"after: calls_queued={after['metrics']['calls_queued']} "
                f"round_trips={after['metrics']['round_trips']}",
                f"delta: calls_queued=+{delta_calls} round_trips=+{delta_round_trips}",
                f"activity: {activity['mode']} stages={len(activity['stages'])} "
                f"chain={activity['promise_chain']}",
                f"pipeline: {result['result']['detail']}",
                f"dashboard bytes: {len(page)}",
            ]
        )

        # A negative path must be observable too, and every facet must remain.
        refused_before = after["metrics"]["calls_refused"]
        tool_before = after["metrics"]["tool_refusals"]
        refused = post(base, "/demo/scenario/tool-policy")
        refused_after = get(base, "/metrics")
        assert refused["result"]["ok"] is True, f"{label}: tool-policy failed"
        assert refused_after["metrics"]["calls_refused"] == refused_before + 1, (
            f"{label}: calls_refused delta"
        )
        assert refused_after["metrics"]["tool_refusals"] == tool_before + 1, (
            f"{label}: tool_refusals delta"
        )
        assert any(
            event["kind"] == "tool_refused" for event in refused_after["events"]
        ), f"{label}: tool_refused event missing"
        assert any(
            event["kind"] == "call_refused" and event.get("code") == "rpc/tool-policy"
            for event in refused_after["events"]
        ), f"{label}: generic refusing call event missing"
        log.append(
            "negative path: calls_refused +1, tool_refusals +1, both facets visible"
        )
        return log
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main() -> int:
    if not BINARY.exists():
        subprocess.run(["cargo", "build", "--locked"], cwd=str(ROOT), check=True)
    lines = []
    for index, port in enumerate(PORTS, start=1):
        lines.extend(one_launch(port, f"launch {index}"))
    lines.append("RESULT: both launches reproduced the documented shape and deltas")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
