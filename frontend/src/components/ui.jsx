function StatusPill({ kind, text }) {
  return (
    <div className={`status ${kind}`}>
      <span>{text}</span>
    </div>
  );
}

function Metric({ label, value }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function EnforcementModeControl({ value, onChange }) {
  return (
    <div className="mode-control" aria-label="Enforcement mode">
      {["audit", "warn", "enforce"].map((mode) => (
        <button
          key={mode}
          className={value === mode ? "active" : ""}
          type="button"
          onClick={() => onChange(mode)}
          title={`Set enforcement mode to ${mode}`}
        >
          {mode}
        </button>
      ))}
    </div>
  );
}

function ToggleControl({ checked, onChange, title, disabled = false }) {
  return (
    <button
      className={checked ? "switch on" : "switch"}
      type="button"
      onClick={() => onChange(!checked)}
      title={title}
      disabled={disabled}
      aria-pressed={checked}
    >
      <span className="switch-thumb" />
    </button>
  );
}

function SwitchMini({ entry, onChange }) {
  if (entry.kind === "boolean") {
    const enabled = String(entry.current).toLowerCase() === "true";
    return (
      <div className="switch-mini">
        <div className="switch-mini-label">
          <code>{entry.id}</code>
          {entry.label ? <span className="muted">{entry.label}</span> : null}
        </div>
        <ToggleControl checked={enabled} onChange={(next) => onChange(entry.id, next)} title={entry.label || entry.id} />
      </div>
    );
  }
  if (entry.kind === "choice") {
    return (
      <div className="switch-mini">
        <div className="switch-mini-label">
          <code>{entry.id}</code>
        </div>
        <select value={entry.current} onChange={(event) => onChange(entry.id, event.target.value)}>
          {(entry.options || []).map((option) => (
            <option key={option} value={option}>{option}</option>
          ))}
        </select>
      </div>
    );
  }
  // numeric: show value compactly (fine control lives in the Switches tab)
  return (
    <div className="switch-mini">
      <div className="switch-mini-label">
        <code>{entry.id}</code>
        {entry.label ? <span className="muted">{entry.label}</span> : null}
      </div>
      <span className="switch-mini-value">{entry.current}</span>
    </div>
  );
}

export { StatusPill, Metric, EnforcementModeControl, ToggleControl, SwitchMini };
