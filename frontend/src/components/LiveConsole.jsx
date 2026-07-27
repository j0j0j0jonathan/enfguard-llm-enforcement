import { useEffect, useMemo, useState } from "react";
import { getTrace, listTraces } from "../api.js";
import { POLICY_META } from "../policyMeta.js";
import { verdictKind, verdictLabel } from "../traceUtils.js";
import { EnforcementModeControl, SwitchMini, ToggleControl } from "./ui.jsx";
import { TraceDetail } from "./TraceDetail.jsx";

const LIVE_POLL_MS = 2000;

function LiveConsole({
  policyState,
  switches,
  enforcementMode,
  onChangeMode,
  onTogglePolicy,
  onUpdateSwitch,
  onReload,
  setStatus,
  onOpenPolicies,
  onOpenSwitches,
}) {
  const [traceList, setTraceList] = useState([]);
  const [activeTid, setActiveTid] = useState(null);
  const [activeTrace, setActiveTrace] = useState(null);
  const [live, setLive] = useState(true);
  const [redact, setRedact] = useState(false);
  const [follow, setFollow] = useState(true); // follow newest turn automatically
  const [error, setError] = useState("");
  const [busyPolicy, setBusyPolicy] = useState("");
  // Operator filters: narrow the live stream to one verdict kind, and the
  // policy rail by id/title substring. Neither touches the backend, both are
  // pure view state so they never interfere with following the newest turn.
  const [verdictFilter, setVerdictFilter] = useState("all"); // all | block | warn | allow
  const [policyQuery, setPolicyQuery] = useState("");
  // Compact density shrinks the rail and stream rows so more turns fit on
  // screen during a long run. Pure view state, persisted for the session.
  const [density, setDensity] = useState("comfortable"); // comfortable | compact
  // Newest tid the operator has "caught up" to. Frozen while follow is off so
  // we can count how many turns arrived since they stopped following.
  const [seenTopTid, setSeenTopTid] = useState(null);

  // Poll the trace list. When following, keep the newest turn selected so the
  // console shows the run as it happens.
  useEffect(() => {
    let cancelled = false;
    async function tick() {
      try {
        const result = await listTraces(40);
        if (cancelled) return;
        const list = Array.isArray(result.traces) ? result.traces : [];
        setTraceList(list);
        setError("");
        if (follow && list.length) {
          setActiveTid((current) => (current === list[0].tid ? current : list[0].tid));
        }
      } catch (err) {
        if (!cancelled) setError(err.message || "failed to load traces");
      }
    }
    tick();
    if (!live) return () => { cancelled = true; };
    const handle = window.setInterval(tick, LIVE_POLL_MS);
    return () => { cancelled = true; window.clearInterval(handle); };
  }, [live, follow]);

  // Load the selected turn's detail. Re-fetches when the list updates so a
  // followed newest turn refreshes its verdict in place.
  useEffect(() => {
    if (activeTid == null) { setActiveTrace(null); return undefined; }
    let cancelled = false;
    (async () => {
      try {
        const result = await getTrace(activeTid);
        if (!cancelled) setActiveTrace(result);
      } catch (err) {
        if (!cancelled) setError(err.message || "failed to load trace");
      }
    })();
    return () => { cancelled = true; };
  }, [activeTid, traceList]);

  function selectTrace(tid) {
    setFollow(false);
    setActiveTid(tid);
  }

  const firedInActive = useMemo(() => {
    const names = new Set();
    for (const phase of activeTrace?.phases || []) {
      for (const fp of phase.fired_predicates || []) {
        if (fp && fp.predicate) names.add(String(fp.predicate));
      }
    }
    return names;
  }, [activeTrace]);

  const policyIds = useMemo(() => {
    const fromActive = Array.isArray(policyState.active) ? policyState.active : [];
    const fromPolicies = Array.isArray(policyState.policies)
      ? policyState.policies.map((p) => p.id)
      : [];
    return [...new Set([...fromPolicies, ...fromActive].filter(Boolean))].sort();
  }, [policyState.active, policyState.policies]);

  const activeSet = useMemo(
    () => new Set(Array.isArray(policyState.active) ? policyState.active : []),
    [policyState.active],
  );
  const onCount = policyIds.filter((id) => activeSet.has(id)).length;

  const railSwitches = useMemo(
    () => (Array.isArray(switches) ? switches.filter((s) => s.id !== "enforcement_mode") : []),
    [switches],
  );

  // Verdict tally across the recent turns, for the stream-head counters and to
  // disable a filter chip that would match nothing.
  const verdictCounts = useMemo(() => {
    const acc = { block: 0, warn: 0, allow: 0 };
    for (const entry of traceList) {
      const kind = verdictKind(entry.action);
      acc[kind] = (acc[kind] || 0) + 1;
    }
    return acc;
  }, [traceList]);

  const visibleTraces = useMemo(
    () =>
      verdictFilter === "all"
        ? traceList
        : traceList.filter((entry) => verdictKind(entry.action) === verdictFilter),
    [traceList, verdictFilter],
  );

  const visiblePolicyIds = useMemo(() => {
    const query = policyQuery.trim().toLowerCase();
    if (!query) return policyIds;
    return policyIds.filter(
      (id) =>
        id.toLowerCase().includes(query) ||
        String(POLICY_META[id]?.title || "").toLowerCase().includes(query),
    );
  }, [policyIds, policyQuery]);

  // Keep the "caught up" marker pinned to the newest turn while following, then
  // freeze it when the operator stops, so new arrivals can be counted.
  useEffect(() => {
    if (follow && traceList.length) setSeenTopTid(traceList[0].tid);
  }, [follow, traceList]);

  const newCount = useMemo(() => {
    if (follow || seenTopTid == null) return 0;
    return traceList.filter((entry) => Number(entry.tid) > Number(seenTopTid)).length;
  }, [follow, seenTopTid, traceList]);

  function jumpToLatest() {
    if (traceList.length) {
      setActiveTid(traceList[0].tid);
      setSeenTopTid(traceList[0].tid);
    }
    setFollow(true);
  }

  // Keyboard navigation for the live stream. Arrow up/down moves the selection
  // through the visible turns (and stops follow so it does not snap back), and
  // "p" pauses or resumes the live poll. Guarded so it never fires while the
  // operator is typing in the policy filter or any other input.
  useEffect(() => {
    function onKey(event) {
      const target = event.target;
      const tag = target && target.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
      if (target && target.isContentEditable) return;
      if (event.metaKey || event.ctrlKey || event.altKey) return;
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        if (!visibleTraces.length) return;
        event.preventDefault();
        setFollow(false);
        setActiveTid((current) => {
          const idx = visibleTraces.findIndex((entry) => entry.tid === current);
          if (idx === -1) return visibleTraces[0].tid;
          const nextIdx =
            event.key === "ArrowDown"
              ? Math.min(visibleTraces.length - 1, idx + 1)
              : Math.max(0, idx - 1);
          return visibleTraces[nextIdx].tid;
        });
      } else if (event.key === "p" || event.key === "P") {
        event.preventDefault();
        setLive((value) => !value);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [visibleTraces]);

  async function flipPolicy(id, enabled) {
    setBusyPolicy(id);
    try {
      await onTogglePolicy(id, enabled);
    } catch (err) {
      setStatus?.({ kind: "error", text: err.message });
    } finally {
      setBusyPolicy("");
    }
  }

  async function flipSwitch(id, value) {
    try {
      const result = await onUpdateSwitch(id, value);
      setStatus?.({ kind: "ok", text: `${id} = ${result.value}` });
    } catch (err) {
      setStatus?.({ kind: "error", text: err.message });
    }
  }

  return (
    <section className={`console density-${density}`}>
      <div className="console-bar">
        <button
          type="button"
          className={live ? "live-btn on" : "live-btn"}
          onClick={() => setLive((v) => !v)}
          title={live ? "Streaming live. Click to pause." : "Paused. Click to stream live."}
        >
          <span className="live-dot" />
          {live ? "LIVE" : "PAUSED"}
        </button>
        <button
          type="button"
          className={follow ? "chip-btn on" : "chip-btn"}
          onClick={() => setFollow((v) => !v)}
          title="Keep the newest turn selected as the run proceeds"
        >
          Follow newest
        </button>
        <span className="console-sep" />
        <span className="console-label">Enforcement</span>
        <EnforcementModeControl value={enforcementMode} onChange={onChangeMode} />
        <span className="console-spacer" />
        <button
          type="button"
          className={`chip-btn${redact ? " on" : ""}`}
          onClick={() => setRedact((v) => !v)}
          title="Redact content fields in the verdict detail"
        >
          {redact ? "Redacted" : "Content shown"}
        </button>
        <button
          type="button"
          className={`chip-btn${density === "compact" ? " on" : ""}`}
          onClick={() => setDensity((value) => (value === "compact" ? "comfortable" : "compact"))}
          title="Toggle compact density for the rail and stream"
          aria-pressed={density === "compact"}
        >
          {density === "compact" ? "Compact" : "Comfortable"}
        </button>
        <button type="button" className="chip-btn" onClick={onReload} title="Reload policies from YAML">
          Reload YAML
        </button>
      </div>

      <div className="console-grid">
        <aside className="console-rail">
          <div className="rail-section">
            <div className="rail-head">
              <span>Policies</span>
              <span className="rail-count">{onCount}/{policyIds.length} on</span>
            </div>
            {policyIds.length > 6 ? (
              <input
                className="rail-filter"
                type="search"
                value={policyQuery}
                onChange={(event) => setPolicyQuery(event.target.value)}
                placeholder="Filter policies"
                aria-label="Filter policies by name"
              />
            ) : null}
            <div className="rail-policies">
              {visiblePolicyIds.map((id) => {
                const enabled = activeSet.has(id);
                const meta = POLICY_META[id];
                const fired = [...firedInActive].some(
                  (n) => n === id || n.includes(id) || id.includes(n),
                );
                return (
                  <div className={`rail-policy${fired ? " fired" : ""}`} key={id}>
                    <ToggleControl
                      checked={enabled}
                      onChange={(next) => flipPolicy(id, next)}
                      title={enabled ? "Disable policy" : "Enable policy"}
                      disabled={Boolean(busyPolicy)}
                    />
                    <div className="rail-policy-label">
                      <code>{id}</code>
                      {meta?.title ? <span className="muted">{meta.title}</span> : null}
                    </div>
                    {fired ? <span className="fired-badge" title="fired in the selected turn">fired</span> : null}
                  </div>
                );
              })}
              {!policyIds.length ? <p className="muted small">No policies loaded.</p> : null}
              {policyIds.length && !visiblePolicyIds.length ? (
                <p className="muted small">No policies match “{policyQuery}”.</p>
              ) : null}
            </div>
            <button type="button" className="rail-link" onClick={onOpenPolicies}>
              Open full policy editor →
            </button>
          </div>

          <div className="rail-section">
            <div className="rail-head">
              <span>Switches</span>
              <span className="rail-count">{railSwitches.length}</span>
            </div>
            <div className="rail-switches">
              {railSwitches.map((entry) => (
                <SwitchMini key={entry.id} entry={entry} onChange={flipSwitch} />
              ))}
              {!railSwitches.length ? <p className="muted small">No switches declared in YAML.</p> : null}
            </div>
            {railSwitches.length ? (
              <button type="button" className="rail-link" onClick={onOpenSwitches}>
                Open all switches →
              </button>
            ) : null}
          </div>
        </aside>

        <div className="console-stream">
          <div className="stream-head">
            <span>Live trace</span>
            <div className="stream-filters" role="group" aria-label="Filter live trace by verdict">
              {[
                ["all", "all", traceList.length],
                ["block", "block", verdictCounts.block],
                ["warn", "warn", verdictCounts.warn],
                ["allow", "allow", verdictCounts.allow],
              ].map(([key, label, count]) => (
                <button
                  key={key}
                  type="button"
                  className={`verdict-filter v-${key}${verdictFilter === key ? " on" : ""}`}
                  onClick={() => setVerdictFilter(key)}
                  disabled={key !== "all" && !count}
                  aria-pressed={verdictFilter === key}
                  title={`Show ${label} turns`}
                >
                  {label} <span className="vf-count">{count}</span>
                </button>
              ))}
            </div>
          </div>
          {!follow && newCount > 0 ? (
            <button
              type="button"
              className="stream-jump"
              onClick={jumpToLatest}
              title="Jump to the newest turn and resume following"
            >
              ↓ {newCount} new turn{newCount === 1 ? "" : "s"}
            </button>
          ) : null}
          {error ? <div className="banner error">{error}</div> : null}
          <div className="stream-list">
            {visibleTraces.map((entry) => {
              const fired = Array.isArray(entry.fired_predicates) ? entry.fired_predicates : [];
              const kind = verdictKind(entry.action);
              const firedText = fired.length
                ? fired.slice(0, 3).join(", ") + (fired.length > 3 ? ` +${fired.length - 3}` : "")
                : "";
              // For block/warn turns the firing policies are the reason, so we
              // label them; allow turns keep the muted predicate list.
              let reason = "no policy fired";
              if (firedText && (kind === "block" || kind === "warn")) {
                reason = `${kind === "block" ? "blocked by" : "warned by"}: ${firedText}`;
              } else if (firedText) {
                reason = firedText;
              }
              return (
                <button
                  key={`${entry.tid}:${entry.ts}`}
                  type="button"
                  className={`stream-row${activeTid === entry.tid ? " active" : ""} v-${kind}`}
                  onClick={() => selectTrace(entry.tid)}
                >
                  <span className={`verdict-pill ${kind}`}>{verdictLabel(entry.action)}</span>
                  <span className="stream-tid">T{entry.tid}</span>
                  <span className={kind === "allow" ? "stream-fired muted" : `stream-fired reason-${kind}`}>
                    {reason}
                  </span>
                  <span className="stream-ms muted">{entry.wall_ms || 0}ms</span>
                </button>
              );
            })}
            {!traceList.length ? (
              <p className="muted small stream-empty">
                Waiting for the first turn. Run an agent or send a request through the proxy and verdicts appear here live.
              </p>
            ) : null}
            {traceList.length && !visibleTraces.length ? (
              <p className="muted small stream-empty">
                No {verdictFilter} turns in the recent window.{" "}
                <button type="button" className="link-button" onClick={() => setVerdictFilter("all")}>
                  Show all
                </button>
              </p>
            ) : null}
          </div>
        </div>

        <div className="console-detail">
          {activeTrace ? (
            <TraceDetail trace={activeTrace} redact={redact} />
          ) : (
            <div className="detail-empty muted">
              {traceList.length ? "Select a turn to inspect its verdict and the events that fired." : "No turn selected yet."}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

export { LiveConsole };
