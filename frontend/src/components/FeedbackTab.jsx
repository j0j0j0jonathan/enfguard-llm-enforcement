import { useState } from "react";
import { sendFeedback } from "../api.js";

function FeedbackTab({ sid, setStatus, enabled }) {
  const [tid, setTid] = useState("");
  const [kind, setKind] = useState("thumbs_up");
  const [payload, setPayload] = useState("");
  const [sending, setSending] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setSending(true);
    try {
      if (!enabled) {
        throw new Error("feedback is disabled by policy state");
      }
      const result = await sendFeedback(tid, kind, payload);
      setStatus({ kind: "ok", text: `Feedback logged for T${result.tid}` });
      setPayload("");
    } catch (error) {
      setStatus({ kind: "error", text: error.message });
    } finally {
      setSending(false);
    }
  }

  return (
    <section className="feedback-view">
      <form className="feedback-form" onSubmit={submit}>
        <div className="toolbar compact">
          <div>
            <h2>Feedback</h2>
            <p>{sid ? `Session ${sid.slice(0, 8)}` : "No session id in URL."}</p>
            {!enabled ? <p>Feedback is disabled in policy state.</p> : null}
          </div>
          <button className="button primary" type="submit" disabled={sending || !enabled}>
            {sending ? "Sending" : "Send"}
          </button>
        </div>
        <div className="split">
          <label className="field">
            <span>Tid</span>
            <input value={tid} onChange={(event) => setTid(event.target.value)} inputMode="numeric" />
          </label>
          <label className="field">
            <span>Kind</span>
            <select value={kind} onChange={(event) => setKind(event.target.value)}>
              <option value="thumbs_up">thumbs up</option>
              <option value="thumbs_down">thumbs down</option>
              <option value="approve_block">approve block</option>
              <option value="deny_allow">deny allow</option>
              <option value="freeform">freeform</option>
            </select>
          </label>
        </div>
        <label className="field block">
          <span>Payload</span>
          <textarea value={payload} onChange={(event) => setPayload(event.target.value)} />
        </label>
      </form>
    </section>
  );
}

export { FeedbackTab };
