import { useMemo, useState } from "react";
import { formatEvent, phaseTimingLabel, verdictKind, verdictLabel } from "../traceUtils.js";
import { overrideJudgeResult } from "../api.js";

function TraceDetail({ trace, redact }) {
  const phases = Array.isArray(trace.phases) ? trace.phases : [];
  const rows = Array.isArray(trace.predicate_rows) ? trace.predicate_rows : [];
  const batches = trace.batches || {};
  const sessionRecords = Array.isArray(trace.session_records) ? trace.session_records : [];

  return (
    <div className="trace-detail">
      <div className="box-title">
        <strong>Trace T{trace.tid}</strong>
      </div>
      <div className="trace-phase-grid">
        {phases.map((phase) => (
          <PhaseSummary
            key={phase.phase}
            tid={trace.tid}
            phase={phase}
            rows={rows}
            batches={batches}
            redact={redact}
          />
        ))}
      </div>
      {!phases.length ? (
        <p className="muted">No verdict rows for this turn yet — predicates may not have fired.</p>
      ) : null}
      <EventsBlock sessionRecords={sessionRecords} />
    </div>
  );
}

function EventsBlock({ sessionRecords }) {
  const groups = useMemo(() => {
    const acc = { inbound: [], verdict: [], outbound: [] };
    for (const record of sessionRecords) {
      for (const event of record.inbound || []) acc.inbound.push(event);
      for (const event of record.verdict_events || []) acc.verdict.push(event);
      for (const event of record.outbound || []) acc.outbound.push(event);
    }
    return acc;
  }, [sessionRecords]);

  const total = groups.inbound.length + groups.verdict.length + groups.outbound.length;
  if (!total) return null;

  return (
    <details className="phase-block" open>
      <summary>
        <span className="verdict-pill allow">EVENTS</span>
        <strong>events that fired</strong>
        <span className="muted">{total} total</span>
        <span></span>
      </summary>
      <div className="events-groups">
        {[
          ["inbound (sent to EnfGuard)", groups.inbound],
          ["verdict (proxy to EnfGuard)", groups.verdict],
          ["outbound (sent to EnfGuard)", groups.outbound],
        ].map(([label, events]) =>
          events.length ? (
            <div key={label}>
              <div className="events-label">{label}</div>
              <pre className="events-pre">
                {events.map((event, index) => (
                  <span key={index}>{formatEvent(event)}{"\n"}</span>
                ))}
              </pre>
            </div>
          ) : null,
        )}
      </div>
    </details>
  );
}

function PhaseSummary({ tid, phase, rows, batches, redact }) {
  const phaseRows = rows.filter((row) => row.phase === phase.phase);
  return (
    <details className="phase-block" open>
      <summary>
        <span className={`verdict-pill ${verdictKind(phase.action)}`}>{verdictLabel(phase.action)}</span>
        <strong>{phase.phase}</strong>
        <span className="muted">
          {phase.fired_predicates.length
            ? `${phase.fired_predicates.length} fired`
            : "no policy fired"}
        </span>
        <span className="muted">{phaseTimingLabel(phase)}</span>
      </summary>
      {phase.fired_predicates.length ? (
        <ul className="fired-list">
          {phase.fired_predicates.map((entry, index) => (
            <li key={`${entry.predicate}-${index}`}>
              <strong>{entry.predicate}</strong>
              <span>score {entry.raw_score?.toFixed?.(2) ?? entry.raw_score}</span>
              <span className="muted">{entry.reason}</span>
            </li>
          ))}
        </ul>
      ) : null}
      {phaseRows.length ? (
        <table className="trace-table">
          <thead>
            <tr>
              <th>predicate</th>
              <th>raw</th>
              <th>fired</th>
              <th>cache</th>
              <th>latency</th>
              <th>batch</th>
              <th>reason</th>
            </tr>
          </thead>
          <tbody>
            {phaseRows.map((row, index) => (
              <PredicateRow
                key={`${row.predicate}-${index}`}
                tid={tid}
                row={row}
                redact={redact}
                batches={batches}
              />
            ))}
          </tbody>
        </table>
      ) : null}
    </details>
  );
}

function PredicateRow({ tid, row, redact, batches }) {
  const fired = Number(row.score || 0) >= 0.5;
  const cached = Boolean(row.judge_cache_hit);
  const batchId = row.batch_id || "";
  const batch = batchId ? batches[batchId] : null;
  const [overrideState, setOverrideState] = useState({ status: "", error: "" });
  const overrideScore = fired ? 0 : 1;

  async function flagJudge() {
    const label = fired ? "false positive" : "false negative";
    const reason = window.prompt(`Why should this judge result be marked as a ${label}?`);
    if (reason === null) return;
    setOverrideState({ status: "Saving override...", error: "" });
    try {
      await overrideJudgeResult({
        tid,
        predicate: row.predicate,
        phase: row.phase,
        content_preview: row.content_preview,
        raw_score: overrideScore,
        reason: reason.trim() || label,
      });
      setOverrideState({ status: "Override saved for next matching request.", error: "" });
    } catch (error) {
      setOverrideState({ status: "", error: error.message || "override failed" });
    }
  }

  return (
    <>
      <tr>
        <td>
          <details>
            <summary>{row.predicate}</summary>
            <div className="trace-row-detail">
              <PromptBlock label="judge_prompt" text={row.judge_prompt} redact={redact} />
              <PromptBlock label="judge_raw_reply" text={row.judge_raw_reply} redact={redact} />
              <PromptBlock label="content_preview" text={row.content_preview} redact={redact} />
              {row.reasons && row.reasons.length ? (
                <PromptBlock label="reasons" text={row.reasons.join("\n")} redact={redact} />
              ) : null}
              <div className="judge-override">
                <button className="button ghost compact-button" type="button" onClick={flagJudge}>
                  Flag judge
                </button>
                <span className={overrideState.error ? "error-text" : "muted"}>
                  {overrideState.error || overrideState.status || "Writes an exact cache override and logs feedback."}
                </span>
              </div>
            </div>
          </details>
        </td>
        <td>{Number(row.raw_score || 0).toFixed(2)}</td>
        <td>{fired ? "yes" : "no"}</td>
        <td>{cached ? "hit" : "miss"}</td>
        <td>{cached ? "0ms" : `${row.latency_ms || 0}ms`}</td>
        <td>
          {batchId ? (
            <span title={batch ? `${batch.predicates.length} predicates · ${batch.latency_ms}ms` : ""}>
              {batchId.slice(0, 6)}
            </span>
          ) : (
            "-"
          )}
        </td>
        <td className="reason-cell">{row.reason || ""}</td>
      </tr>
    </>
  );
}

function PromptBlock({ label, text, redact }) {
  const value = String(text || "").trim();
  if (!value) return null;
  return (
    <div className="prompt-block">
      <strong>{label}</strong>
      <pre>{redact ? "[redacted; toggle redact off to view]" : value}</pre>
    </div>
  );
}

export { TraceDetail };
