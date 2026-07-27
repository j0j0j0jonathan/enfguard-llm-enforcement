import { useCallback, useEffect, useRef, useState } from "react";
import { getPendingApprovals, resolveApproval } from "../api.js";

const APPROVAL_POLL_MS = 2000;

function ApprovalsLayer({ setStatus }) {
  const [pending, setPending] = useState([]);
  const [busyTid, setBusyTid] = useState(null);
  const intervalRef = useRef(null);

  const refresh = useCallback(async () => {
    try {
      const result = await getPendingApprovals();
      setPending(Array.isArray(result.pending) ? result.pending : []);
    } catch {
      // silent — pending approvals failing should not break the rest of the UI
    }
  }, []);

  useEffect(() => {
    refresh();
    intervalRef.current = window.setInterval(refresh, APPROVAL_POLL_MS);
    return () => {
      if (intervalRef.current) window.clearInterval(intervalRef.current);
    };
  }, [refresh]);

  // Local one-second clock so the countdown ticks smoothly between the slower
  // server polls. The deadline itself comes from the server (created_ts +
  // timeout_seconds), so the display stays accurate without drifting.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!pending.length) return undefined;
    const handle = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(handle);
  }, [pending.length]);

  async function decide(entry, decision) {
    setBusyTid(entry.tid);
    try {
      await resolveApproval(entry.tid, decision);
      setPending((current) => current.filter((row) => row.tid !== entry.tid));
      setStatus({ kind: "ok", text: `T${entry.tid}: ${decision}` });
    } catch (err) {
      setStatus({ kind: "error", text: err.message });
    } finally {
      setBusyTid(null);
    }
  }

  if (!pending.length) return null;
  return (
    <div className="approvals-layer">
      {pending.map((entry) => {
        // Prefer a client-side deadline (created_ts + timeout_seconds) so the
        // countdown ticks every second. Fall back to the server's snapshot
        // value when the timing fields are missing.
        const hasDeadline =
          Number.isFinite(entry.created_ts) && Number.isFinite(entry.timeout_seconds);
        const deadlineMs = hasDeadline
          ? (entry.created_ts + entry.timeout_seconds) * 1000
          : null;
        const remaining = hasDeadline
          ? Math.max(0, Math.ceil((deadlineMs - now) / 1000))
          : Math.max(0, Number(entry.remaining_seconds) || 0);
        const total = Number(entry.timeout_seconds) || 0;
        const pct = total > 0 ? Math.max(0, Math.min(100, (remaining / total) * 100)) : 0;
        const urgent = remaining <= 10;
        const label = String(entry.label || "").trim();
        return (
          <div className="approval-card" key={entry.tid}>
            <div className="approval-header">
              <strong>T{entry.tid} needs a decision</strong>
              <span className={urgent ? "approval-count urgent" : "approval-count"}>
                {remaining}s
              </span>
            </div>
            <div className="approval-meta">
              {entry.phase ? <span className="tag tag-session">{entry.phase}</span> : null}
              {entry.sid ? <span className="muted">session {String(entry.sid).slice(0, 8)}</span> : null}
              <span className="muted">fallback: {entry.on_timeout}</span>
            </div>
            <div className="approval-progress" aria-hidden="true">
              <span
                className={urgent ? "approval-progress-fill urgent" : "approval-progress-fill"}
                style={{ width: `${pct}%` }}
              />
            </div>
            {label ? (
              <div className="approval-preview">
                <span className="approval-preview-label">action</span>
                <p>{label}</p>
              </div>
            ) : (
              <p className="muted">No action preview provided.</p>
            )}
            <div className="approval-actions">
              <button
                className="button secondary"
                type="button"
                disabled={busyTid === entry.tid}
                onClick={() => decide(entry, "deny")}
              >
                {entry.phase === "tool" ? "Block Tool Use" : "Deny"}
              </button>
              <button
                className="button primary"
                type="button"
                disabled={busyTid === entry.tid}
                onClick={() => decide(entry, "approve")}
              >
                {entry.phase === "tool" ? "Allow Tool Use" : "Approve"}
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}

export { ApprovalsLayer };
