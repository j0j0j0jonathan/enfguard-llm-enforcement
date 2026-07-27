// Pure, stateless helpers shared across the trace and console views.
// Extracted from App.jsx so the view components stay focused on rendering and
// these stay independently testable. No React imports on purpose.

export function rangeStyle(value, min = 0, max = 1) {
  const number = Number(value);
  const lower = Number(min);
  const upper = Number(max);
  const percent = upper === lower ? 0 : ((number - lower) / (upper - lower)) * 100;
  return { "--range-progress": `${Math.min(100, Math.max(0, percent))}%` };
}

export function formatEvent(event) {
  const args = (event.args || []).map(formatEventArg).join(", ");
  return `${event.name}(${args})`;
}

export function formatEventArg(value) {
  if (typeof value === "string") {
    const trimmed = value.length > 80 ? `${value.slice(0, 80)}…` : value;
    return JSON.stringify(trimmed);
  }
  return String(value);
}

export function phaseTimingLabel(phase) {
  // Old traces only carry `wall_ms`. New traces carry `enfguard_ms`
  // (engine) and `judge_ms` (HTTP) separately. When the breakdown is
  // available, surface it inline so the user sees where the time went.
  const engine = Number(phase.enfguard_ms || 0);
  const judge = Number(phase.judge_ms || 0);
  const model = Number(phase.upstream_ms || 0);
  const total = Number(phase.wall_ms || engine + judge + model);
  if (engine || judge || model) {
    const parts = [`enfguard ${engine}ms`, `judge ${judge}ms`];
    if (model) parts.push(`model ${model}ms`);
    return `${total}ms (${parts.join(" · ")})`;
  }
  return `${total}ms`;
}

// Map a raw verdict/action string to one of the four pill kinds the UI styles.
export function verdictKind(action) {
  const text = String(action || "").toLowerCase();
  if (text.includes("block")) return "block";
  if (text.includes("warn")) return "warn";
  if (text.includes("approval")) return "warn";
  if (text === "allowed" || text === "") return "allow";
  return "allow";
}

export function verdictLabel(action) {
  const text = String(action || "");
  if (!text) return "—";
  if (text === "allowed") return "ALLOW";
  if (text.startsWith("request_")) return text.slice("request_".length).toUpperCase();
  if (text.startsWith("response_")) return text.slice("response_".length).toUpperCase();
  return text.toUpperCase();
}
