import { useEffect, useMemo, useState } from "react";
import { POLICY_META } from "../policyMeta.js";
import { rangeStyle } from "../traceUtils.js";
import { ToggleControl } from "./ui.jsx";
import {
  LIVE_POLICY_DEFAULT_SCOPE,
  LIVE_POLICY_VALID_SCOPES,
  livePolicyTemplate,
  nextLivePolicyId,
} from "../livePolicy.js";

function PoliciesTab({
  draft,
  setDraft,
  onSave,
  onRefresh,
  onReload,
  onInstallLivePolicy,
  onRemoveLivePolicy,
}) {
  const [saving, setSaving] = useState(false);
  const [quickSaving, setQuickSaving] = useState("");
  const [showLiveEditor, setShowLiveEditor] = useState(false);
  const ids = useMemo(() => {
    const fromActive = Array.isArray(draft.active) ? draft.active : [];
    const fromPolicies = Array.isArray(draft.policies) ? draft.policies.map((policy) => policy.id) : [];
    return [...new Set([...fromPolicies, ...fromActive].filter(Boolean))];
  }, [draft.active, draft.policies]);
  const livePolicies = useMemo(() => {
    const policies = Array.isArray(draft.policies) ? draft.policies : [];
    return policies.filter((policy) => policy && policy.source === "live");
  }, [draft.policies]);

  const activeSet = new Set(draft.active || []);

  async function commitDraft(nextDraft, statusLabel = "") {
    setDraft(nextDraft);
    if (!statusLabel) return;
    setQuickSaving(statusLabel);
    try {
      await onSave(nextDraft);
    } finally {
      setQuickSaving("");
    }
  }

  function withPolicyEnabled(policyId, enabled) {
    const policies = Array.isArray(draft.policies) ? draft.policies : [];
    return policies.map((policy) => (policy.id === policyId ? { ...policy, enabled } : policy));
  }

  async function updateActive(policyId, enabled) {
    const nextActive = enabled
      ? [...new Set([...(draft.active || []), policyId])]
      : (draft.active || []).filter((id) => id !== policyId);
    const nextDraft = {
      ...draft,
      active: nextActive,
      policies: withPolicyEnabled(policyId, enabled),
    };
    await commitDraft(nextDraft, policyId);
  }

  function updateThreshold(policyId, value) {
    const meta = POLICY_META[policyId];
    const number = Number(value);
    const policyThresholds = { ...(draft.policy_thresholds || {}), [policyId]: number };
    const thresholds = { ...(draft.thresholds || {}) };
    if (meta?.predicate) thresholds[meta.predicate] = number;
    setDraft({ ...draft, policy_thresholds: policyThresholds, thresholds });
  }

  function updateBlocklist(text) {
    const values = text
      .split("\n")
      .map((item) => item.trim())
      .filter(Boolean);
    setDraft({ ...draft, model_blocklist: values });
  }

  async function updateFeedbackEnabled(enabled) {
    const nextDraft = { ...draft, feedback: { ...(draft.feedback || {}), enabled } };
    await commitDraft(nextDraft, "feedback");
  }

  async function updateHumanApprovalEnabled(enabled) {
    const nextDraft = {
      ...draft,
      human_approval: { ...(draft.human_approval || {}), enabled },
    };
    await commitDraft(nextDraft, "human_approval");
  }

  async function updateAggressiveBatching(enabled) {
    const nextDraft = {
      ...draft,
      runtime: {
        ...(draft.runtime || {}),
        judge_batching: enabled ? "aggressive" : "conservative",
      },
    };
    await commitDraft(nextDraft, "judge_batching");
  }

  async function updateAssistantTraceEnabled(enabled) {
    const nextDraft = {
      ...draft,
      runtime: {
        ...(draft.runtime || {}),
        trace_assistant_content: enabled,
      },
    };
    await commitDraft(nextDraft, "trace_assistant_content");
  }

  async function save() {
    setSaving(true);
    try {
      await onSave();
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="panel-grid">
      <div className="toolbar">
        <div>
          <h2>Policies</h2>
          <p>{ids.length} policies loaded from runtime state. YAML changes need reload or restart.</p>
        </div>
        <div className="toolbar-actions">
          <button
            className="button secondary"
            type="button"
            onClick={() => setShowLiveEditor((value) => !value)}
            title="Create a policy for this running proxy"
          >
            {showLiveEditor ? "Close editor" : "New live policy"}
          </button>
          <button className="button secondary" type="button" onClick={onRefresh} title="Refresh policies">
            Refresh
          </button>
          <button className="button secondary" type="button" onClick={onReload} title="Reload YAML">
            Reload YAML
          </button>
          <button className="button primary" type="button" onClick={save} disabled={saving} title="Save policies">
            {saving ? "Saving" : "Save"}
          </button>
        </div>
      </div>

      {livePolicies.length ? (
        <LivePoliciesList policies={livePolicies} onRemove={onRemoveLivePolicy} />
      ) : null}

      {showLiveEditor ? (
        <LivePolicyEditor existingPolicies={livePolicies} onInstall={onInstallLivePolicy} />
      ) : null}

      <div className="policy-list">
        {ids.map((id) => {
          const meta = POLICY_META[id] || {
            title: id,
            predicate: "",
            phase: "custom",
            category: "custom",
          };
          const threshold =
            draft.policy_thresholds?.[id] ?? (meta.predicate ? draft.thresholds?.[meta.predicate] : undefined) ?? 0.5;
          const enabled = activeSet.has(id);
          const busy = quickSaving === id;
          return (
            <div className="policy-row" key={id}>
              <ToggleControl
                checked={enabled}
                onChange={(next) => updateActive(id, next)}
                title={enabled ? "Disable policy" : "Enable policy"}
                disabled={Boolean(quickSaving)}
              />
              <div className="policy-main">
                <div className="policy-title">
                  <strong>{id}</strong>
                  {busy ? <span>saving</span> : meta.title && meta.title !== id ? <span>{meta.title}</span> : null}
                </div>
                {/* Only render the meta strip when at least one piece of
                    info is non-default — avoids the "custom custom" noise
                    for user-authored policies that only have an id. */}
                {meta.predicate || (meta.phase && meta.phase !== "custom") ? (
                  <div className="policy-meta">
                    {meta.phase && meta.phase !== "custom" ? <span>{meta.phase}</span> : null}
                    {meta.predicate ? <span>{meta.predicate}</span> : null}
                  </div>
                ) : null}
              </div>
              {meta.predicate ? (
                <label className="slider-field">
                  <span>{Number(threshold).toFixed(2)}</span>
                  <input
                    type="range"
                    min="0"
                    max="1"
                    step="0.05"
                    value={threshold}
                    style={rangeStyle(threshold)}
                    onChange={(event) => updateThreshold(id, event.target.value)}
                  />
                </label>
              ) : null}
            </div>
          );
        })}
      </div>

      <div className="split">
        <label className="field block">
          <span>Model blocklist</span>
          <textarea
            value={(draft.model_blocklist || []).join("\n")}
            onChange={(event) => updateBlocklist(event.target.value)}
          />
        </label>
        <div className="runtime-box">
          <div className="box-title">
            <strong>Runtime gates</strong>
          </div>
          <div className="settings-list">
            <div className="settings-row">
              <div className="policy-main">
                <div className="policy-title">
                  <strong>optional feedback</strong>
                  <span>{draft.feedback?.enabled !== false ? "enabled" : "disabled"}</span>
                </div>
                <p>Thumbs and freeform feedback collection.</p>
              </div>
              <ToggleControl
                checked={draft.feedback?.enabled !== false}
                onChange={updateFeedbackEnabled}
                title="Toggle optional feedback"
                disabled={Boolean(quickSaving)}
              />
            </div>
            <div className="settings-row">
              <div className="policy-main">
                <div className="policy-title">
                  <strong>human approval</strong>
                  <span>{draft.human_approval?.enabled ? "enabled" : "disabled"}</span>
                </div>
                <p>Approve events can pause the request for review.</p>
              </div>
              <ToggleControl
                checked={Boolean(draft.human_approval?.enabled)}
                onChange={updateHumanApprovalEnabled}
                title="Toggle human approval gates"
                disabled={Boolean(quickSaving)}
              />
            </div>
            <div className="settings-row">
              <div className="policy-main">
                <div className="policy-title">
                  <strong>aggressive batching</strong>
                  <span>{draft.runtime?.judge_batching === "aggressive" ? "enabled" : "conservative"}</span>
                </div>
                <p>Phase 2 can batch inbound and outbound judge inputs.</p>
              </div>
              <ToggleControl
                checked={draft.runtime?.judge_batching === "aggressive"}
                onChange={updateAggressiveBatching}
                title="Toggle aggressive judge batching"
                disabled={Boolean(quickSaving)}
              />
            </div>
            <div className="settings-row">
              <div className="policy-main">
                <div className="policy-title">
                  <strong>assistant trace text</strong>
                  <span>{draft.runtime?.trace_assistant_content !== false ? "stored" : "omitted"}</span>
                </div>
                <p>CompletionObserved content and judge previews in traces.</p>
              </div>
              <ToggleControl
                checked={draft.runtime?.trace_assistant_content !== false}
                onChange={updateAssistantTraceEnabled}
                title="Toggle assistant text in traces"
                disabled={Boolean(quickSaving)}
              />
            </div>
          </div>
        </div>
        <FailModePanel draft={draft} setDraft={setDraft} />
      </div>
    </section>
  );
}

function LivePoliciesList({ policies, onRemove }) {
  const [removingId, setRemovingId] = useState("");

  async function remove(policyId) {
    if (!onRemove) return;
    setRemovingId(policyId);
    try {
      await onRemove(policyId);
    } catch (error) {
      // App-level handler already surfaces error in the status pill.
    } finally {
      setRemovingId("");
    }
  }

  return (
    <div className="runtime-box live-policy-list">
      <div className="box-title">
        <strong>Installed live policies</strong>
        <span>session-scoped entries clear on proxy restart</span>
      </div>
      <ul className="live-policy-rows">
        {policies.map((policy) => {
          const scope = (policy.scope || LIVE_POLICY_DEFAULT_SCOPE).toLowerCase();
          const isPersistent = scope === "persistent";
          const busy = removingId === policy.id;
          return (
            <li className="live-policy-row" key={policy.id}>
              <div className="live-policy-row-label">
                <code>{policy.id}</code>
                <span className={`tag tag-${isPersistent ? "persistent" : "session"}`}>
                  {isPersistent ? "persistent" : "session"}
                </span>
                {policy.enabled ? null : <span className="tag tag-muted">disabled</span>}
              </div>
              <button
                className="button secondary"
                type="button"
                onClick={() => remove(policy.id)}
                disabled={busy || !onRemove}
                title="Remove this live policy and reload"
              >
                {busy ? "Removing" : "Remove"}
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function LivePolicyEditor({ existingPolicies, onInstall }) {
  const initialId = useMemo(() => nextLivePolicyId(existingPolicies), [existingPolicies]);
  const [policyId, setPolicyId] = useState(initialId);
  const [policyIdEdited, setPolicyIdEdited] = useState(false);
  const [enabled, setEnabled] = useState(true);
  const [scope, setScope] = useState(LIVE_POLICY_DEFAULT_SCOPE);
  const [mfotl, setMfotl] = useState(() => livePolicyTemplate(initialId));
  const [mfotlEdited, setMfotlEdited] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [message, setMessage] = useState("");

  // If the user has not touched the id yet and another policy lands in the
  // list (e.g. via reload), keep the suggested id fresh.
  useEffect(() => {
    if (policyIdEdited) return;
    const fresh = nextLivePolicyId(existingPolicies);
    setPolicyId(fresh);
    if (!mfotlEdited) {
      setMfotl(livePolicyTemplate(fresh));
    }
  }, [existingPolicies, policyIdEdited, mfotlEdited]);

  function handleIdChange(event) {
    const next = event.target.value;
    setPolicyIdEdited(true);
    setPolicyId(next);
    if (!mfotlEdited) {
      setMfotl(livePolicyTemplate(next));
    }
  }

  function handleMfotlChange(event) {
    setMfotlEdited(true);
    setMfotl(event.target.value);
  }

  function resetForm(nextExisting) {
    const fresh = nextLivePolicyId(nextExisting);
    setPolicyId(fresh);
    setPolicyIdEdited(false);
    setEnabled(true);
    setScope(LIVE_POLICY_DEFAULT_SCOPE);
    setMfotl(livePolicyTemplate(fresh));
    setMfotlEdited(false);
  }

  async function install() {
    setInstalling(true);
    setMessage("");
    try {
      const merged = await onInstall({ id: policyId, enabled, mfotl, scope });
      setMessage(`Installed ${policyId} (${scope}). The next request uses this policy.`);
      const nextExisting = (merged && Array.isArray(merged.policies)
        ? merged.policies.filter((policy) => policy && policy.source === "live")
        : existingPolicies);
      resetForm(nextExisting);
    } catch (error) {
      setMessage(error.message);
    } finally {
      setInstalling(false);
    }
  }

  return (
    <div className="runtime-box live-policy-editor">
      <div className="box-title">
        <strong>New live policy</strong>
        <span>installed into the running proxy and merged on reload</span>
      </div>
      <div className="live-policy-grid">
        <label className="field">
          <span>Policy id</span>
          <input value={policyId} onChange={handleIdChange} />
        </label>
        <label className="field">
          <span>Scope</span>
          <select value={scope} onChange={(event) => setScope(event.target.value)}>
            {LIVE_POLICY_VALID_SCOPES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
        <label className="field toggle-field">
          <span>Enabled after install</span>
          <ToggleControl checked={enabled} onChange={setEnabled} title="Enable live policy after install" />
        </label>
      </div>
      <p className="muted" style={{ margin: "0 0 8px", fontSize: 12 }}>
        <strong>session</strong> = wiped at proxy restart (good for experiments).{" "}
        <strong>persistent</strong> = kept across restarts in <code>state/live_policies.json</code>.
        For permanent thesis/demo config, copy the MFOTL into <code>enfguard.yaml</code>.
      </p>
      <label className="field block">
        <span>MFOTL</span>
        <textarea className="code-textarea" value={mfotl} onChange={handleMfotlChange} />
      </label>
      <div className="editor-actions">
        {message ? <span className="inline-status">{message}</span> : <span />}
        <button className="button primary" type="button" onClick={install} disabled={installing}>
          {installing ? "Installing" : "Install & reload"}
        </button>
      </div>
    </div>
  );
}

function FailModePanel({ draft, setDraft }) {
  const predicates = Array.isArray(draft.user_predicates) ? draft.user_predicates : [];
  const judgePredicates = predicates.filter((spec) => spec.kind === "llm_judge");
  const perPredicate = draft.judge_fail_modes || {};
  const globalMode = draft.judge_fail_mode || "closed";

  function setGlobal(mode) {
    setDraft({ ...draft, judge_fail_mode: mode });
  }

  function setPerPredicate(name, mode) {
    const next = { ...perPredicate };
    if (!mode) {
      delete next[name];
    } else {
      next[name] = mode;
    }
    setDraft({ ...draft, judge_fail_modes: next });
  }

  return (
    <div className="runtime-box">
      <div className="box-title">
        <strong>Judge fail modes</strong>
      </div>
      <p className="muted" style={{ margin: "0 0 8px", fontSize: 12 }}>
        What happens when a judge LLM call fails:{" "}
        <strong>closed</strong> = treat as fired (block),{" "}
        <strong>open</strong> = treat as not fired (allow),{" "}
        <strong>warn</strong> = block becomes warn. Save to apply.
      </p>
      <div className="fail-mode-row">
        <strong>(global default)</strong>
        <select value={globalMode} onChange={(event) => setGlobal(event.target.value)}>
          <option value="closed">closed</option>
          <option value="open">open</option>
          <option value="warn">warn</option>
        </select>
      </div>
      {judgePredicates.map((spec) => {
          const current = perPredicate[spec.name] || "";
          return (
            <div className="fail-mode-row" key={spec.name}>
              <strong>{spec.name}</strong>
              <select
                value={current}
                onChange={(event) => setPerPredicate(spec.name, event.target.value)}
              >
                <option value="">use global ({globalMode})</option>
                <option value="closed">closed</option>
                <option value="open">open</option>
                <option value="warn">warn</option>
              </select>
            </div>
          );
        })}
      {judgePredicates.length === 0 ? (
        <p className="muted" style={{ fontSize: 12, marginTop: 6 }}>
          No judge predicates declared in YAML yet. Add a <code>kind: llm_judge</code>{" "}
          predicate to override the fail mode here.
        </p>
      ) : null}
    </div>
  );
}

export { PoliciesTab };
