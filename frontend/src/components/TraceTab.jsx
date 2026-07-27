import { useCallback, useEffect, useState } from "react";
import { getTrace, listTraces } from "../api.js";
import { verdictKind, verdictLabel } from "../traceUtils.js";
import { TraceDetail } from "./TraceDetail.jsx";

function TraceTab() {
  const [traceList, setTraceList] = useState([]);
  const [activeTid, setActiveTid] = useState(null);
  const [activeTrace, setActiveTrace] = useState(null);
  const [error, setError] = useState("");
  const [redact, setRedact] = useState(true);
  const [loadingList, setLoadingList] = useState(false);

  const refreshList = useCallback(async () => {
    setLoadingList(true);
    try {
      const result = await listTraces();
      setTraceList(Array.isArray(result.traces) ? result.traces : []);
      setError("");
    } catch (err) {
      setError(err.message || "failed to load traces");
    } finally {
      setLoadingList(false);
    }
  }, []);

  const loadTrace = useCallback(async (tid) => {
    try {
      setError("");
      const result = await getTrace(tid);
      setActiveTid(tid);
      setActiveTrace(result);
      window.parent?.postMessage({ kind: "trace_loaded", tid }, "*");
    } catch (err) {
      setError(err.message || "failed to load trace");
    }
  }, []);

  useEffect(() => {
    refreshList();
  }, [refreshList]);

  // Drop a stale selection: if the currently open turn is no longer in the
  // list (e.g. it belonged to a previous proxy run), clear the detail pane so
  // we never show a trace that the refreshed list no longer contains.
  useEffect(() => {
    if (activeTid != null && !traceList.some((entry) => entry.tid === activeTid)) {
      setActiveTid(null);
      setActiveTrace(null);
    }
  }, [traceList, activeTid]);

  async function loadByInput(event) {
    event?.preventDefault();
    const data = new FormData(event.currentTarget);
    const raw = data.get("tid");
    const tid = parseInt(raw, 10);
    if (Number.isFinite(tid)) {
      await loadTrace(tid);
    }
  }

  return (
    <section className="panel-grid">
      <form className="toolbar" onSubmit={loadByInput}>
        <div>
          <h2>Trace</h2>
          <p>
            Per-turn traces also appear inline in the chat. This tab is for
            admin lookup across the {traceList.length || "0"} most recent turn
            {traceList.length === 1 ? "" : "s"}.
          </p>
        </div>
        <div className="toolbar-actions">
          <input name="tid" placeholder="tid" inputMode="numeric" />
          <button className="button secondary" type="submit" title="Load by tid">
            Load
          </button>
          <button
            className="button secondary"
            type="button"
            onClick={refreshList}
            title="Refresh trace list"
            disabled={loadingList}
          >
            Refresh
          </button>
          <button
            className={`button secondary${redact ? " active" : ""}`}
            type="button"
            onClick={() => setRedact((v) => !v)}
            title="Redact content fields"
          >
            {redact ? "Redacted" : "Shown"}
          </button>
        </div>
      </form>
      {error ? <div className="banner error">{error}</div> : null}
      <div className="trace-layout">
        <div className="trace-list">
          {traceList.map((entry) => (
            <button
              key={`${entry.tid}:${entry.ts}`}
              type="button"
              className={`trace-summary${activeTid === entry.tid ? " active" : ""}`}
              onClick={() => loadTrace(entry.tid)}
            >
              <span className={`verdict-pill ${verdictKind(entry.action)}`}>{verdictLabel(entry.action)}</span>
              <strong>T{entry.tid}</strong>
              <span className="muted">
                {entry.fired_predicates && entry.fired_predicates.length
                  ? entry.fired_predicates.join(", ")
                  : "no predicates fired"}
              </span>
              <span className="muted">{entry.wall_ms || 0}ms</span>
            </button>
          ))}
          {!traceList.length && !loadingList ? (
            <p className="muted">No traces yet. Issue a request through the chat tab to populate this list.</p>
          ) : null}
        </div>
        <div className="runtime-box">
          {activeTrace ? <TraceDetail trace={activeTrace} redact={redact} /> : (
            <p className="muted">Select a turn to inspect.</p>
          )}
        </div>
      </div>
    </section>
  );
}

export { TraceTab };
