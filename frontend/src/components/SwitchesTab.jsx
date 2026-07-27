import { useMemo, useState } from "react";
import { rangeStyle } from "../traceUtils.js";
import { ToggleControl } from "./ui.jsx";

function SwitchesTab({ switches, onRefresh, onUpdate, setStatus }) {
  const [refreshing, setRefreshing] = useState(false);
  const visibleSwitches = useMemo(
    () => switches.filter((entry) => entry.id !== "enforcement_mode"),
    [switches],
  );

  async function refresh() {
    setRefreshing(true);
    try {
      await onRefresh();
    } finally {
      setRefreshing(false);
    }
  }

  async function update(id, value) {
    try {
      const result = await onUpdate(id, value);
      setStatus({ kind: "ok", text: `Switch ${id} set to ${result.value}` });
    } catch (err) {
      setStatus({ kind: "error", text: err.message });
    }
  }

  return (
    <section className="panel-grid">
      <div className="toolbar">
        <div>
          <h2>Switches</h2>
          <p>
            {visibleSwitches.length
              ? `${visibleSwitches.length} switch${visibleSwitches.length === 1 ? "" : "es"} declared in YAML.`
              : "No switches declared. Add a switches: block to enfguard.yaml to expose user-controllable parameters."}
          </p>
        </div>
        <div className="toolbar-actions">
          <button className="button secondary" type="button" onClick={refresh} title="Refresh switches" disabled={refreshing}>
            Refresh
          </button>
        </div>
      </div>
      <div className="settings-list surface-list">
        {visibleSwitches.map((entry) => (
          <SwitchRow key={entry.id} entry={entry} onChange={update} />
        ))}
      </div>
    </section>
  );
}

function SwitchRow({ entry, onChange }) {
  if (entry.kind === "boolean") {
    const enabled = String(entry.current).toLowerCase() === "true";
    return (
      <div className="settings-row">
        <div className="policy-main">
          <div className="policy-title">
            <strong>{entry.id}</strong>
            <span>{entry.label || ""}</span>
          </div>
          <div className="policy-meta">
            <span>boolean</span>
            <span>default {String(entry.default)}</span>
          </div>
        </div>
        <div className="control-cluster">
          <code>{enabled ? "true" : "false"}</code>
          <ToggleControl
            checked={enabled}
            onChange={(next) => onChange(entry.id, next)}
            title={entry.label}
          />
        </div>
      </div>
    );
  }
  if (entry.kind === "int" || entry.kind === "float" || entry.kind === "number") {
    const isInt = entry.kind !== "float";
    const min = entry.min ?? 0;
    const max = entry.max ?? Math.max(1, Number(entry.current) || 1);
    const step = isInt ? Math.max(1, Math.round((max - min) / 100) || 1) : (max - min) / 100 || 0.01;
    return (
      <div className="settings-row">
        <div className="policy-main">
          <div className="policy-title">
            <strong>{entry.id}</strong>
            <span>{entry.label || ""}</span>
          </div>
          <div className="policy-meta">
            <span>{isInt ? "int" : "float"}</span>
            <span>
              [{min}, {max}]
            </span>
            <span>default {String(entry.default)}</span>
          </div>
        </div>
        <label className="slider-field">
          <span>{entry.current}</span>
          <input
            type="range"
            min={min}
            max={max}
            step={step}
            value={Number(entry.current) || 0}
            style={rangeStyle(entry.current, min, max)}
            onChange={(event) => {
              const raw = Number(event.target.value);
              onChange(entry.id, isInt ? Math.round(raw) : raw);
            }}
          />
        </label>
      </div>
    );
  }
  if (entry.kind === "choice") {
    return (
      <div className="settings-row">
        <div className="policy-main">
          <div className="policy-title">
            <strong>{entry.id}</strong>
            <span>{entry.label || ""}</span>
          </div>
          <div className="policy-meta">
            <span>choice</span>
            <span>default {String(entry.default)}</span>
          </div>
        </div>
        <select
          value={entry.current}
          onChange={(event) => onChange(entry.id, event.target.value)}
        >
          {(entry.options || []).map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      </div>
    );
  }
  return null;
}

export { SwitchesTab };
