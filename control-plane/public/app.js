(() => {
	const $ = (id) => document.getElementById(id);
	const state = {
		snapshot: null,
		status: null,
		ws: null,
		retry: 0,
		filter: "all",
		search: "",
		brush: null,
		selectedScenario: "round-trip",
		selectedLevel: 0,
		running: false,
	};

	const LEVEL_NAMES = {
		0: "Smoke",
		1: "Core correctness",
		2: "Tools & policy",
		3: "Concurrency",
		4: "Budgets & refuse",
		5: "Benchmark",
		6: "Intense",
	};

	const GAUGES = [
		{
			key: "encode_us",
			label: "Encode",
			unit: "µs",
			digits: 1,
			max: 250,
			source: "status-module encode()",
			def: "Wall time of one canonical AINF encode of the status module, measured with Instant around the shipped encode().",
		},
		{
			key: "decode_us",
			label: "Decode",
			unit: "µs",
			digits: 1,
			max: 150,
			source: "status-module decode()",
			def: "Wall time of one decode() of the status module image, measured with Instant.",
		},
		{
			key: "hash_us",
			label: "Hash",
			unit: "µs",
			digits: 1,
			max: 250,
			source: "status-module content_hash()",
			def: "Wall time of one Blake3 content_hash() over the status image.",
		},
		{
			key: "validate_us",
			label: "Validate",
			unit: "µs",
			digits: 1,
			max: 150,
			source: "status-module validate()",
			def: "Wall time of one validate() over the status image.",
		},
		{
			key: "calls_per_second",
			label: "Calls / s",
			unit: "/s",
			digits: 2,
			max: 100,
			source: "calls_queued delta / wall",
			def: "Delta of Agent::metrics().calls_queued divided by the elapsed wall time since the previous sample.",
		},
		{
			key: "wire_in_per_s",
			label: "Wire in",
			unit: "B/s",
			digits: 0,
			max: 1000000,
			compact: true,
			source: "sum of inbound frame bytes / wall",
			def: "Delta of the plane's inbound byte counter (encoded images, stream frames and tool paths) divided by wall time.",
		},
		{
			key: "wire_out_per_s",
			label: "Wire out",
			unit: "B/s",
			digits: 0,
			max: 1000000,
			compact: true,
			source: "sum of outbound frame bytes / wall",
			def: "Delta of the plane's outbound byte counter divided by wall time.",
		},
		{
			key: "settled_per_s",
			label: "Settled / s",
			unit: "/s",
			digits: 2,
			max: 100,
			source: "resolved + rejected delta / wall",
			def: "Promise resolutions plus rejections per wall second, from the kernel metrics delta.",
		},
		{
			key: "promise_records",
			label: "Promise records",
			unit: "",
			digits: 0,
			max: 50,
			source: "Agent::promise_count()",
			def: "Promise records retained by the kernel right now. Settled records stay pinned while a live handle can still read them.",
		},
		{
			key: "active_lanes",
			label: "Active lanes",
			unit: "",
			digits: 0,
			max: 8,
			source: "open lane registry",
			def: "Lanes in the kernel registry that are not closed.",
		},
		{
			key: "active_channels",
			label: "Active channels",
			unit: "",
			digits: 0,
			max: 8,
			source: "channel registry",
			def: "Channels in the kernel registry.",
		},
		{
			key: "caps_live",
			label: "Capabilities",
			unit: "",
			digits: 0,
			max: 16,
			source: "CapHandles held by the plane",
			def: "Capability handles the control plane currently holds. Correlation ids are shown; raw authority never is.",
		},
		{
			key: "tool_calls_per_s",
			label: "Tool calls",
			unit: "/s",
			digits: 2,
			max: 20,
			source: "tool success counter delta / wall",
			def: "Tool provider calls that completed successfully per wall second.",
		},
		{
			key: "tool_refusals_per_s",
			label: "Tool refuses",
			unit: "/s",
			digits: 2,
			max: 10,
			source: "tool policy refusals delta / wall",
			def: "Tool policy refusals per wall second, from the kernel metrics delta.",
		},
		{
			key: "budget_pressure",
			label: "Budget",
			unit: "%",
			digits: 1,
			max: 100,
			source: "calls / granted call budgets",
			def: "Queued calls divided by the sum of granted call budgets across the plane's capabilities.",
		},
		{
			key: "stream_frames_per_s",
			label: "Stream frames",
			unit: "/s",
			digits: 2,
			max: 200,
			source: "streaming frame counter delta / wall",
			def: "Streaming frames consumed per wall second by the real stream decoder path.",
		},
		{
			key: "canonical_ok_rate",
			label: "Canonical",
			unit: "%",
			digits: 1,
			max: 100,
			source: "re-encode equality / attempts",
			def: "Share of finishes whose re-encode matched the canonical image. Zero samples shows 0.0%.",
		},
		{
			key: "p99_call_us",
			label: "p99 call",
			unit: "µs",
			digits: 1,
			max: 2000,
			source: "rolling settle durations",
			def: "99th percentile of the last 512 real promise settlement durations measured by the plane.",
		},
		{
			key: "queue_depth",
			label: "Calls queued",
			unit: "total",
			digits: 0,
			max: 1000,
			source: "Agent::metrics().calls_queued",
			def: "Calls accepted into the kernel queue, cumulative since start. This is a counter, not a current depth.",
		},
		{
			key: "pipeline_depth",
			label: "Pipeline depth",
			unit: "",
			digits: 0,
			max: 50,
			source: "queued − settled",
			def: "Calls queued minus promises resolved or rejected: an in-flight estimate from kernel counters.",
		},
	];

	const GAUGE_BY_KEY = Object.fromEntries(
		GAUGES.map((gauge) => [gauge.key, gauge]),
	);
	const ARC_LENGTH = 157.08;

	function theme() {
		const url = new URLSearchParams(location.search).get("theme");
		const saved = localStorage.getItem("acp-theme");
		const dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
		document.documentElement.dataset.theme =
			url || saved || (dark ? "dark" : "light");
	}
	theme();
	$("theme-toggle").addEventListener("click", () => {
		const next =
			document.documentElement.dataset.theme === "dark" ? "light" : "dark";
		document.documentElement.dataset.theme = next;
		localStorage.setItem("acp-theme", next);
	});

	const fmt = (value, digits = 0) =>
		Number(value || 0).toLocaleString(undefined, {
			maximumFractionDigits: digits,
			minimumFractionDigits: digits,
		});

	function compact(value) {
		const number = Number(value || 0);
		if (number >= 1_000_000) return `${(number / 1_000_000).toFixed(1)}M`;
		if (number >= 1_000) return `${(number / 1_000).toFixed(1)}k`;
		return fmt(number, 0);
	}

	function escapeHtml(text) {
		return String(text ?? "").replace(
			/[&<>"']/g,
			(char) =>
				({
					"&": "&amp;",
					"<": "&lt;",
					">": "&gt;",
					'"': "&quot;",
					"'": "&#39;",
				})[char],
		);
	}

	function setStatus(text, cls) {
		$("status-text").textContent = text;
		$("status").className = `status ${cls || ""}`;
	}

	function setText(id, value) {
		const node = $(id);
		if (node) node.textContent = value;
	}

	function gaugeValue(snapshot, key) {
		switch (key) {
			case "encode_us":
				return snapshot.infinity.timings.encode_us;
			case "decode_us":
				return snapshot.infinity.timings.decode_us;
			case "hash_us":
				return snapshot.infinity.timings.hash_us;
			case "validate_us":
				return snapshot.infinity.timings.validate_us;
			case "calls_per_second":
				return snapshot.metrics.calls_per_second;
			case "wire_in_per_s":
				return snapshot.metrics.wire_in_per_s;
			case "wire_out_per_s":
				return snapshot.metrics.wire_out_per_s;
			case "settled_per_s":
				return snapshot.metrics.settled_per_s;
			case "promise_records":
				return snapshot.metrics.promise_records;
			case "active_lanes":
				return snapshot.metrics.active_lanes;
			case "active_channels":
				return snapshot.metrics.active_channels;
			case "caps_live":
				return snapshot.metrics.caps_live;
			case "tool_calls_per_s":
				return snapshot.metrics.tool_calls_per_s;
			case "tool_refusals_per_s":
				return snapshot.metrics.tool_refusals_per_s;
			case "budget_pressure":
				return snapshot.metrics.budget_pressure;
			case "stream_frames_per_s":
				return snapshot.metrics.stream_frames_per_s;
			case "canonical_ok_rate":
				return snapshot.metrics.canonical_ok_rate;
			case "p99_call_us":
				return snapshot.metrics.p99_call_us;
			case "queue_depth":
				return snapshot.metrics.queue_depth;
			case "pipeline_depth":
				return snapshot.metrics.pipeline_depth;
			default:
				return 0;
		}
	}

	function buildGauges() {
		$("gauge-grid").innerHTML = GAUGES.map(
			(gauge) => `
      <div class="gauge" data-gauge="${gauge.key}" role="button" tabindex="0" aria-label="${gauge.label} gauge, click for samples">
        <svg viewBox="0 0 120 70" aria-hidden="true">
          <path class="gauge-track" d="M10 62a50 50 0 0 1 100 0"/>
          <path class="arc" id="arc-${gauge.key}" d="M10 62a50 50 0 0 1 100 0"/>
        </svg>
        <strong id="gv-${gauge.key}">0</strong>
        <span>${gauge.label}</span>
        <small>${gauge.unit ? gauge.unit + " · " : ""}${escapeHtml(gauge.source)}</small>
      </div>`,
		).join("");
		$("gauge-grid")
			.querySelectorAll(".gauge")
			.forEach((element) => {
				const open = () => openGauge(element.dataset.gauge);
				element.addEventListener("click", open);
				element.addEventListener("keydown", (event) => {
					if (event.key === "Enter" || event.key === " ") {
						event.preventDefault();
						open();
					}
				});
			});
	}

	function renderGauges(snapshot) {
		for (const gauge of GAUGES) {
			const value = gaugeValue(snapshot, gauge.key);
			const strong = $(`gv-${gauge.key}`);
			strong.textContent = gauge.compact
				? compact(value)
				: fmt(value, gauge.digits);
			const fraction = Math.max(0, Math.min(1, Number(value) / gauge.max));
			const arc = $(`arc-${gauge.key}`);
			arc.style.strokeDasharray = `${fraction * ARC_LENGTH} 999`;
			arc.style.opacity = fraction > 0.01 ? "1" : "0";
			arc.parentElement.parentElement.classList.toggle(
				"warm",
				gauge.key === "budget_pressure" && value > 75,
			);
		}
	}

	function renderKpis(snapshot) {
		const metrics = snapshot.metrics;
		setText("kpi-cps", fmt(metrics.calls_per_second, 2));
		setText("kpi-calls", fmt(metrics.calls_queued));
		setText("kpi-promises", fmt(metrics.promise_records));
		setText("kpi-roundtrips", fmt(metrics.round_trips));
		setText("kpi-refused", fmt(metrics.calls_refused + metrics.tool_refusals));
		setText("kpi-pressure", `${fmt(metrics.budget_pressure, 1)}%`);
		setText(
			"kpi-bytes",
			compact(metrics.wire_in_per_s + metrics.wire_out_per_s),
		);
		setText("kpi-error", snapshot.last_error_code || "none");
		$("kpi-error").classList.toggle(
			"muted",
			!snapshot.last_error_code || snapshot.last_error_code === "none",
		);
		setText("footer-hash", `AINF ${snapshot.infinity.hash.slice(0, 16)}…`);
		setText("mode-chip", snapshot.health.mode);
	}

	function renderActivity(snapshot) {
		const activity = snapshot.activity;
		$("activity-mode").textContent = activity.mode;
		$("activity-mode").className =
			`mode-badge mode-${activity.mode.toLowerCase()}`;
		$("activity-age").textContent =
			activity.last_event_age_ms < 1500
				? "event just now"
				: `last event ${fmt(activity.last_event_age_ms / 1000, 1)}s ago`;
		$("activity-summary").textContent = activity.summary;
		const stages = activity.stages || [];
		$("activity-stages").innerHTML = stages.length
			? stages
					.map(
						(stage, index) =>
							`${index ? '<i class="stage-arrow" aria-hidden="true">→</i>' : ""}
               <span class="stage ${stage.ok ? "ok" : "bad"}">
                 <b>${escapeHtml(stage.name)}</b>
                 <small>${escapeHtml(stage.detail)}${stage.duration_us ? ` · ${fmt(stage.duration_us, 1)} µs` : ""}</small>
               </span>`,
					)
					.join("")
			: '<span class="hint">No stages yet. Run a scenario or attach real traffic.</span>';
		const hashSpot = $("hash-spot");
		if (activity.hash_prefix) {
			hashSpot.hidden = false;
			setText("activity-hash", activity.hash_prefix);
		} else {
			hashSpot.hidden = true;
		}
		setText(
			"activity-bytes",
			activity.bytes ? `${fmt(activity.bytes)} AINF bytes` : "image —",
		);
		if (activity.progress) {
			const [done, total] = activity.progress;
			const fraction = total ? Math.min(100, (done / total) * 100) : 0;
			$("activity-progress").innerHTML =
				`progress ${fmt(done)} / ${fmt(total)} <span class="inline-bar"><i style="width:${fraction}%"></i></span>`;
		} else {
			setText("activity-progress", "progress —");
		}
		const chain = activity.promise_chain || [];
		if (!chain.length) {
			$("promise-chain").innerHTML =
				'<span class="hint">no pipelined batch yet</span>';
		} else {
			const shown = chain.slice(-16);
			$("promise-chain").innerHTML =
				shown
					.map((id) => `<span class="promise">#${id}</span>`)
					.join('<i class="stage-arrow" aria-hidden="true">→</i>') +
				(chain.length > shown.length
					? `<span class="hint">+${chain.length - shown.length} earlier</span>`
					: "");
		}
		const lanes = activity.lanes || [];
		const max = Math.max(
			1,
			...lanes.map((lane) => lane.completed + lane.pending + lane.queue),
		);
		$("lane-bars").innerHTML = lanes
			.map(
				(lane) => `
        <div class="lane-row ${lane.closed ? "closed" : ""}">
          <span class="lane-name">${escapeHtml(lane.name)}</span>
          <span class="lane-track"><i style="width:${Math.min(100, ((lane.pending + lane.queue) / max) * 100)}%"></i></span>
          <span class="lane-num">${lane.pending} pending · ${lane.queue} queued · ${fmt(lane.completed)} done</span>
        </div>`,
			)
			.join("");
		$("copy-hash").onclick = () => copyText(activity.hash_prefix || "");
	}

	function renderEngines(snapshot) {
		const engines = snapshot.engines;
		setText(
			"engine-counts",
			`${engines.lanes.length} lanes · ${engines.channels.length} channels · ${engines.capabilities.length} caps`,
		);
		$("engine-grid").innerHTML = `
      <div class="engine-col">
        <span class="section-label">Lanes</span>
        ${engines.lanes
					.map(
						(lane) =>
							`<div class="engine-row"><b>${escapeHtml(lane.name)}</b><small>${lane.pending} pending · ${lane.completed} done</small></div>`,
					)
					.join("")}
      </div>
      <div class="engine-col">
        <span class="section-label">Channels</span>
        ${engines.channels
					.map(
						(channel) =>
							`<div class="engine-row"><b>${escapeHtml(channel.name)}</b><small>${channel.sent} sent · ${channel.received} recv · ${channel.subscribers} sub</small></div>`,
					)
					.join("")}
      </div>`;
		$("cap-list").innerHTML = engines.capabilities
			.map(
				(cap) => `
      <button class="cap-row" data-cap="${escapeHtml(cap.label)}" type="button">
        <b>${escapeHtml(cap.label)}</b>
        <small>${cap.methods.length} methods${cap.read_only ? " · read-only" : ""}${cap.attenuated ? " · attenuated" : ""}</small>
      </button>`,
			)
			.join("");
		$("cap-list")
			.querySelectorAll(".cap-row")
			.forEach((button) =>
				button.addEventListener("click", () => openCap(button.dataset.cap)),
			);
	}

	const LANE_DEFS = [
		{
			id: "calls",
			label: "CALLS",
			match: (event) => event.category === "calls",
		},
		{
			id: "batch",
			label: "BATCH",
			match: (event) => event.category === "batch",
		},
		{
			id: "tool",
			label: "TOOL",
			match: (event) =>
				event.category === "tool" || event.kind === "tool_refused",
		},
		{
			id: "stream",
			label: "STREAM",
			match: (event) => event.category === "stream",
		},
		{
			id: "budget",
			label: "BUDGET",
			match: (event) =>
				event.kind === "budget" || (event.code || "").includes("budget"),
		},
		{
			id: "scenario",
			label: "SCENARIO",
			match: (event) =>
				event.category === "scenario" || event.category === "benchmark",
		},
	];

	function eventClass(event) {
		if (!event.code) return "";
		if (
			event.code.includes("budget") ||
			event.code.includes("policy") ||
			event.code.includes("refused") ||
			event.code.includes("revoked")
		)
			return "refused";
		return "error";
	}

	function timelineBounds(events) {
		if (state.brush) return { min: state.brush.min, max: state.brush.max };
		const now = Date.now();
		if (!events.length) return { min: now - 60_000, max: now };
		const times = events.map((event) => event.ts_ms);
		const first = Math.min(...times);
		const last = Math.max(...times);
		const padding = Math.max(250, (last - first) * 0.02);
		return { min: first - padding, max: last + padding };
	}

	function renderTimeline(snapshot) {
		const events = snapshot.events || [];
		const bounds = timelineBounds(events);
		const span = Math.max(1, bounds.max - bounds.min);
		$("timeline").innerHTML = LANE_DEFS.map((lane) => {
			const ticks = events
				.filter(lane.match)
				.map((event) => {
					const x = ((event.ts_ms - bounds.min) / span) * 100;
					if (x < 0 || x > 100) return "";
					return `<i class="tick ${eventClass(event)}" style="left:${x}%" data-event="${event.id}" role="button" tabindex="0" aria-label="${escapeHtml(`${event.kind}: ${event.detail}`)}" title="${escapeHtml(`${event.kind} · ${event.detail}`)}"></i>`;
				})
				.join("");
			const band = state.brush
				? `<span class="brush-band" style="left:0;width:100%"></span>`
				: "";
			return `<div class="tick-row"><span>${lane.label}</span><div class="tick-track" data-track="${lane.id}">${band}${ticks}</div></div>`;
		}).join("");
		$("timeline")
			.querySelectorAll(".tick")
			.forEach((tick) => {
				const open = () => openEvent(Number(tick.dataset.event));
				tick.addEventListener("click", open);
				tick.addEventListener("keydown", (event) => {
					if (event.key === "Enter" || event.key === " ") {
						event.preventDefault();
						open();
					}
				});
			});
		$("timeline")
			.querySelectorAll(".tick-track")
			.forEach((track) => attachBrush(track, bounds, span));
		$("timeline-hint").textContent = state.brush
			? `Brush: ${new Date(state.brush.min).toLocaleTimeString([], { hour12: false })} → ${new Date(state.brush.max).toLocaleTimeString([], { hour12: false })} · Clear to reset`
			: "Drag across the tracks to brush a time window; the event log follows.";
	}

	function attachBrush(track, bounds, span) {
		let start = null;
		track.addEventListener("mousedown", (event) => {
			const rect = track.getBoundingClientRect();
			start = Math.max(
				0,
				Math.min(1, (event.clientX - rect.left) / rect.width),
			);
			event.preventDefault();
		});
		const finish = (event) => {
			if (start === null) return;
			const rect = track.getBoundingClientRect();
			const end = Math.max(
				0,
				Math.min(1, (event.clientX - rect.left) / rect.width),
			);
			const low = Math.min(start, end);
			const high = Math.max(start, end);
			start = null;
			if (high - low < 0.01) return;
			state.brush = {
				min: bounds.min + low * span,
				max: bounds.min + high * span,
			};
			render(state.snapshot);
		};
		track.addEventListener("mouseup", finish);
		document.addEventListener("mouseup", finish, { once: true });
	}

	function matchesFilter(event) {
		if (state.filter === "all") return true;
		if (state.filter === "budget")
			return event.kind === "budget" || (event.code || "").includes("budget");
		if (state.filter === "refusals")
			return (
				event.category === "refusals" ||
				event.kind === "tool_refused" ||
				Boolean(event.code)
			);
		return event.category === state.filter;
	}

	function visibleEvents(snapshot) {
		const needle = state.search.trim().toLowerCase();
		return (snapshot.events || [])
			.filter((event) => {
				if (state.brush) {
					if (event.ts_ms < state.brush.min || event.ts_ms > state.brush.max)
						return false;
				}
				if (!matchesFilter(event)) return false;
				if (!needle) return true;
				return [
					event.kind,
					event.detail,
					event.code,
					event.lane,
					event.method,
					event.scenario_id,
					event.capability,
				]
					.filter(Boolean)
					.some((value) => String(value).toLowerCase().includes(needle));
			})
			.slice(-200)
			.reverse();
	}

	function renderEvents(snapshot) {
		const events = visibleEvents(snapshot);
		const total = (snapshot.events || []).length;
		setText("event-count", `${events.length} of ${total} events`);
		const cursor = total ? snapshot.events[total - 1].id : 0;
		setText("log-cursor", `cursor ${cursor}`);
		$("event-log").innerHTML = events.length
			? events
					.map((event) => {
						const time = new Date(event.ts_ms).toLocaleTimeString([], {
							hour12: false,
						});
						const meta = [
							event.code,
							event.duration_us != null
								? `${fmt(event.duration_us, 1)} µs`
								: null,
							event.bytes != null ? `${fmt(event.bytes)} B` : null,
							event.lane,
							event.method,
						]
							.filter(Boolean)
							.join(" · ");
						return `<li class="${eventClass(event)}" data-event="${event.id}">
              <time>${time}</time>
              <span class="cat cat-${event.category}">${event.category}</span>
              <b>${escapeHtml(event.kind)}</b>
              <span class="detail">${escapeHtml(event.detail)}</span>
              <span class="meta">${escapeHtml(meta)}</span>
            </li>`;
					})
					.join("")
			: '<li class="empty">No events match this filter.</li>';
		$("event-log")
			.querySelectorAll("li[data-event]")
			.forEach((row) =>
				row.addEventListener("click", () =>
					openEvent(Number(row.dataset.event)),
				),
			);
	}

	function renderLadder(snapshot) {
		if (!snapshot) return;
		const results = Object.fromEntries(
			(snapshot.scenario_results || []).map((result) => [result.id, result]),
		);
		const groups = new Map();
		for (const def of snapshot.scenarios || []) {
			if (!groups.has(def.level)) groups.set(def.level, []);
			groups.get(def.level).push(def);
		}
		$("ladder").innerHTML = [...groups.entries()]
			.sort((a, b) => a[0] - b[0])
			.map(([level, defs]) => {
				const rows = defs
					.map((def) => {
						const result = results[def.id];
						const cls = result ? (result.ok ? "ok" : "bad") : "pending";
						const stateText = result
							? result.ok
								? "pass"
								: "fail"
							: "not run";
						return `<button class="ladder-step ${cls} ${state.selectedScenario === def.id ? "selected" : ""}" data-scenario="${def.id}" type="button">
              <span class="code">${def.code}</span>
              <b>${escapeHtml(def.title)}</b>
              <small>${escapeHtml(def.description)}</small>
              <span class="state">${stateText}${result ? ` · ${fmt(result.duration_us / 1000, 1)} ms` : ""}</span>
            </button>`;
					})
					.join("");
				return `<div class="level-group ${state.selectedLevel === level ? "selected" : ""}" data-level="${level}">
          <div class="level-head">
            <span class="level-badge">L${level}</span>
            <b>${LEVEL_NAMES[level]}</b>
            <span class="hint">${defs.length} step${defs.length === 1 ? "" : "s"}</span>
            <button class="mini-button" data-run-level="${level}" type="button">Run level</button>
            <button class="mini-button" data-run-up-to="${level}" type="button">Run ≤ L${level}</button>
          </div>
          <div class="level-steps">${rows}</div>
        </div>`;
			})
			.join("");
		$("ladder")
			.querySelectorAll("[data-scenario]")
			.forEach((button) =>
				button.addEventListener("click", () => {
					state.selectedScenario = button.dataset.scenario;
					state.selectedLevel = Number(
						(snapshot.scenarios || []).find(
							(def) => def.id === button.dataset.scenario,
						)?.level || 0,
					);
					runScenario(button.dataset.scenario);
				}),
			);
		$("ladder")
			.querySelectorAll("[data-run-level]")
			.forEach((button) =>
				button.addEventListener("click", () =>
					runLevel(Number(button.dataset.runLevel), false),
				),
			);
		$("ladder")
			.querySelectorAll("[data-run-up-to]")
			.forEach((button) =>
				button.addEventListener("click", () =>
					runLevel(Number(button.dataset.runUpTo), true),
				),
			);
		$("ladder")
			.querySelectorAll("button")
			.forEach((button) => (button.disabled = state.running));
		const last = snapshot.last_scenario;
		const summary = $("ladder-summary");
		if (last) {
			summary.className = `scenario-result ${last.ok ? "ok" : "bad"} ${state.running ? "running" : ""}`;
			summary.textContent = `${last.code} ${last.title} · ${last.ok ? "pass" : "fail"} · ${fmt(last.duration_us)} µs\n${last.detail}`;
		} else if (state.running) {
			summary.className = "scenario-result running";
			summary.textContent = "Running…";
		}
	}

	function renderBenchmark(snapshot) {
		const report = snapshot.benchmark;
		if (!report) return;
		const rows = [
			["Encode", report.encode],
			["Validate", report.validate],
			["Call (sequential)", report.call_sequential],
			["Call (pipelined, per call)", report.call_pipelined],
		];
		$("bench-body").innerHTML = rows
			.map(
				([name, stats]) =>
					`<tr><td>${name}</td><td>${stats.n}</td><td>${fmt(stats.p50_us, 1)}</td><td>${fmt(stats.p99_us, 1)}</td><td>${fmt(stats.mean_us, 1)}</td></tr>`,
			)
			.join("");
		$("bench-note").textContent =
			`Measured ${new Date(report.ts_ms).toLocaleTimeString([], { hour12: false })} · raw samples exported as CSV.`;
		$("csv-link").href = "/benchmark/export.csv";
	}

	function applyMode(snapshot) {
		const readOnly = snapshot.health.mode === "read-only";
		document.body.classList.toggle("read-only", readOnly);
		if (readOnly) {
			$("ladder")
				.querySelectorAll("button")
				.forEach((button) => (button.disabled = true));
			setText(
				"ladder-summary",
				"Read-only attach: scenarios and benchmarks are disabled. Metrics, events and logs stay live.",
			);
			$("run-benchmark").disabled = true;
		}
	}

	function render(snapshot) {
		if (!snapshot) return;
		state.snapshot = snapshot;
		renderKpis(snapshot);
		renderActivity(snapshot);
		renderEngines(snapshot);
		renderGauges(snapshot);
		renderTimeline(snapshot);
		renderEvents(snapshot);
		renderLadder(snapshot);
		renderBenchmark(snapshot);
		applyMode(snapshot);
	}

	function buildFilters() {
		const filters = [
			"all",
			"calls",
			"batch",
			"refusals",
			"budget",
			"caps",
			"scenario",
			"benchmark",
			"tool",
			"stream",
			"system",
		];
		$("filter-chips").innerHTML = filters
			.map(
				(filter) =>
					`<button class="chip-filter ${filter === state.filter ? "active" : ""}" data-filter="${filter}" type="button">${filter.toUpperCase()}</button>`,
			)
			.join("");
		$("filter-chips")
			.querySelectorAll("[data-filter]")
			.forEach((button) =>
				button.addEventListener("click", () => {
					state.filter = button.dataset.filter;
					buildFilters();
					renderEvents(state.snapshot);
				}),
			);
	}

	function openGauge(key) {
		const gauge = GAUGE_BY_KEY[key];
		if (!gauge) return;
		const snapshot = state.snapshot;
		const samples = (snapshot?.gauge_samples?.[key] || []).slice(-10);
		const values = samples.map((sample) => sample.value);
		const latest = snapshot ? gaugeValue(snapshot, key) : 0;
		$("detail-title").textContent = `${gauge.label} ${gauge.unit}`;
		$("detail-body").innerHTML = `
      <p class="big-value">${gauge.compact ? compact(latest) : fmt(latest, gauge.digits)} <small>${gauge.unit}</small></p>
      <p><b>Source.</b> ${escapeHtml(gauge.def)}</p>
      <p><b>Caption.</b> <code>${escapeHtml(gauge.source)}</code></p>
      ${sparkline(values)}
      <p class="hint">Last ${samples.length} sample${samples.length === 1 ? "" : "s"} · ${samples.map((sample) => new Date(sample.ts_ms).toLocaleTimeString([], { hour12: false })).join(", ") || "none yet"}</p>`;
		showDrawer();
	}

	function sparkline(values) {
		if (!values.length) return '<p class="hint">No samples recorded yet.</p>';
		const max = Math.max(1, ...values);
		const min = Math.min(...values);
		const width = 280;
		const height = 54;
		const points = values
			.map((value, index) => {
				const x =
					values.length === 1
						? width / 2
						: (index / (values.length - 1)) * width;
				const y =
					height - ((value - min) / (max - min || 1)) * (height - 8) - 4;
				return `${x.toFixed(1)},${y.toFixed(1)}`;
			})
			.join(" ");
		return `<svg class="spark" viewBox="0 0 ${width} ${height}" role="img" aria-label="sample sparkline"><polyline points="${points}"/></svg>`;
	}

	function openCap(label) {
		const cap = state.snapshot?.engines?.capabilities?.find(
			(item) => item.label === label,
		);
		if (!cap) return;
		$("detail-title").textContent = cap.label;
		$("detail-body").innerHTML = `
      <p><b>Methods.</b> ${cap.methods.map(escapeHtml).join(", ") || "none"}</p>
      <p><b>Call budget.</b> ${fmt(cap.max_calls)}</p>
      <p><b>Flags.</b> ${cap.read_only ? "read-only" : "read-write"}${cap.attenuated ? " · attenuated" : ""}</p>
      <p><b>Correlation id.</b> <code>${escapeHtml(cap.id)}</code></p>
      <p class="hint">This is a CapToken-style correlation id. Raw authority bits never leave the kernel.</p>`;
		showDrawer();
	}

	function openEvent(id) {
		const event = state.snapshot?.events?.find((item) => item.id === id);
		if (!event) return;
		$("detail-title").textContent = `${event.kind} · #${event.id}`;
		$("detail-body").innerHTML = `
      <p>${escapeHtml(event.detail)}</p>
      <dl class="detail-grid">
        <dt>Time</dt><dd>${new Date(event.ts_ms).toLocaleString()}</dd>
        <dt>Category</dt><dd>${event.category}</dd>
        <dt>Code</dt><dd><code>${escapeHtml(event.code || "none")}</code></dd>
        <dt>Duration</dt><dd>${event.duration_us != null ? `${fmt(event.duration_us, 1)} µs` : "—"}</dd>
        <dt>Bytes</dt><dd>${event.bytes != null ? fmt(event.bytes) : "—"}</dd>
        <dt>Lane</dt><dd>${escapeHtml(event.lane || "—")}</dd>
        <dt>Method</dt><dd>${escapeHtml(event.method || "—")}</dd>
        <dt>Scenario</dt><dd>${escapeHtml(event.scenario_id || "—")}</dd>
        <dt>Capability</dt><dd><code>${escapeHtml(event.capability || "—")}</code></dd>
      </dl>`;
		showDrawer();
	}

	function showDrawer() {
		$("detail-drawer").hidden = false;
	}
	$("detail-close").addEventListener(
		"click",
		() => ($("detail-drawer").hidden = true),
	);

	async function copyText(text) {
		try {
			await navigator.clipboard.writeText(text);
		} catch {
			const area = document.createElement("textarea");
			area.value = text;
			document.body.appendChild(area);
			area.select();
			document.execCommand("copy");
			area.remove();
		}
	}

	function downloadJsonl() {
		const events = state.snapshot?.events || [];
		const body = events.map((event) => JSON.stringify(event)).join("\n");
		const blob = new Blob([body ? body + "\n" : ""], {
			type: "application/x-ndjson",
		});
		const link = document.createElement("a");
		link.href = URL.createObjectURL(blob);
		link.download = "control-plane-events.jsonl";
		link.click();
		URL.revokeObjectURL(link.href);
	}

	async function runScenario(id) {
		if (state.running || state.snapshot?.health?.mode === "read-only") return;
		state.running = true;
		renderLadder(state.snapshot);
		const summary = $("ladder-summary");
		summary.className = "scenario-result running";
		summary.textContent = `Running ${id}…`;
		try {
			const response = await fetch(`/demo/scenario/${id}`, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: "{}",
			});
			const text = await response.text();
			if (!response.ok) throw new Error(text || response.status);
			JSON.parse(text);
			await refresh();
			await loadStatus();
		} catch (error) {
			summary.className = "scenario-result bad";
			summary.textContent = `Scenario failed: ${error}`;
		} finally {
			state.running = false;
			renderLadder(state.snapshot);
		}
	}

	async function runLevel(level, upTo) {
		if (state.running || state.snapshot?.health?.mode === "read-only") return;
		state.running = true;
		renderLadder(state.snapshot);
		$("ladder-summary").className = "scenario-result running";
		$("ladder-summary").textContent =
			`Running ${upTo ? `levels ≤ L${level}` : `level L${level}`}…`;
		try {
			const response = await fetch(`/demo/level/${level}?up_to=${upTo}`, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: "{}",
			});
			if (!response.ok) throw new Error(await response.text());
			await refresh();
			await loadStatus();
		} catch (error) {
			$("ladder-summary").className = "scenario-result bad";
			$("ladder-summary").textContent = `Level run failed: ${error}`;
		} finally {
			state.running = false;
			renderLadder(state.snapshot);
		}
	}

	$("run-benchmark").addEventListener("click", async () => {
		if (state.snapshot?.health?.mode === "read-only") return;
		const button = $("run-benchmark");
		button.disabled = true;
		button.textContent = "Running…";
		try {
			const iterations = Number($("iterations").value || 200);
			const response = await fetch("/benchmark/run", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ iterations }),
			});
			if (!response.ok) throw new Error(await response.text());
			await refresh();
			await loadStatus();
		} catch (error) {
			$("bench-note").textContent = `Benchmark failed: ${error}`;
		} finally {
			button.disabled = false;
			button.textContent = "Run";
		}
	});

	$("focus-scenario").addEventListener("click", () => {
		const start = state.snapshot?.activity?.started_ms;
		if (!start) return;
		state.brush = { min: start - 500, max: Date.now() + 250 };
		render(state.snapshot);
	});
	$("clear-brush").addEventListener("click", () => {
		state.brush = null;
		render(state.snapshot);
	});
	$("download-jsonl").addEventListener("click", downloadJsonl);
	$("copy-tail").addEventListener("click", async () => {
		const tail = visibleEvents(state.snapshot || { events: [] }).slice(0, 40);
		await copyText(tail.map((event) => JSON.stringify(event)).join("\n"));
		$("copy-tail").textContent = "Copied";
		setTimeout(() => ($("copy-tail").textContent = "Copy tail"), 1500);
	});
	$("event-search").addEventListener("input", (event) => {
		state.search = event.target.value;
		renderEvents(state.snapshot);
	});

	const mcpConfig = {
		mcpServers: {
			"active-control-plane": {
				command: "cargo",
				args: [
					"run",
					"--quiet",
					"--manifest-path",
					"active-rpc/control-plane/Cargo.toml",
					"--",
					"--mcp",
					"--attach",
					`http://${location.host}`,
				],
				cwd: ".",
			},
		},
	};
	$("mcp-config").textContent = JSON.stringify(mcpConfig, null, 2);
	$("copy-mcp").addEventListener("click", async () => {
		await copyText(JSON.stringify(mcpConfig, null, 2));
		$("copy-mcp").textContent = "Copied";
		setTimeout(() => ($("copy-mcp").textContent = "Copy MCP config"), 1500);
	});

	async function loadStatus() {
		try {
			const response = await fetch("/status-module", { cache: "no-store" });
			if (!response.ok) return;
			const data = await response.json();
			state.status = data;
			setText("status-hash", data.hash.slice(0, 24) + "…");
			setText(
				"status-bytes",
				`${data.image_bytes} AINF bytes · redaction ${data.redaction_ok ? "ok" : "FAILED"}`,
			);
			const bytes = Uint8Array.from(atob(data.bytes_base64), (char) =>
				char.charCodeAt(0),
			);
			const blob = new Blob([bytes], { type: "application/octet-stream" });
			$("download-status").href = URL.createObjectURL(blob);
		} catch (error) {
			console.error("status module", error);
		}
	}

	function connect() {
		const protocol = location.protocol === "https:" ? "wss" : "ws";
		const ws = new WebSocket(`${protocol}://${location.host}/ws`);
		state.ws = ws;
		ws.addEventListener("open", () => {
			state.retry = 0;
			setStatus("live", "live");
		});
		ws.addEventListener("message", (event) => {
			try {
				render(JSON.parse(event.data));
			} catch (error) {
				console.error("snapshot parse", error);
			}
		});
		ws.addEventListener("close", () => {
			setStatus("reconnecting", "error");
			const delay = Math.min(10_000, 500 * 2 ** state.retry++);
			setTimeout(connect, delay);
		});
		ws.addEventListener("error", () => ws.close());
	}

	async function refresh() {
		try {
			const response = await fetch("/metrics", { cache: "no-store" });
			if (!response.ok) throw new Error(response.status);
			render(await response.json());
		} catch (error) {
			setStatus("offline", "error");
		}
	}

	function toggleHelp(force) {
		const help = $("help");
		help.hidden = force !== undefined ? !force : !help.hidden;
	}
	$("help-toggle").addEventListener("click", () => toggleHelp());
	$("help-close").addEventListener("click", () => toggleHelp(false));

	document.addEventListener("keydown", (event) => {
		if (event.target.matches("input, textarea")) return;
		switch (event.key) {
			case "r":
				runScenario(state.selectedScenario);
				break;
			case "[":
				state.selectedLevel = Math.max(0, state.selectedLevel - 1);
				renderLadder(state.snapshot);
				break;
			case "]":
				state.selectedLevel = Math.min(6, state.selectedLevel + 1);
				renderLadder(state.snapshot);
				break;
			case "e":
				downloadJsonl();
				break;
			case "f":
				$("focus-scenario").click();
				break;
			case "?":
				toggleHelp();
				break;
			default:
		}
	});

	buildGauges();
	buildFilters();
	refresh();
	loadStatus();
	connect();
	setInterval(() => {
		if (!state.ws || state.ws.readyState !== 1) refresh();
	}, 3000);
	setInterval(loadStatus, 10_000);
})();
