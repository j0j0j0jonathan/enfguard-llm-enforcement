"""In-memory switch state for the EnfGuard proxy.

A "switch" is a user-declared parameterisable control (number / boolean /
choice) that the user manipulates from the enforcement UI. Switches surface
as MFOTL events emitted at the start of every phase: the proxy pushes one
``SwitchInt(t, name, value)``, ``SwitchBool(t, name, value)`` (0 or 1), or
``SwitchString(t, name, value)`` event per declared switch.

State is process-local: values reset to YAML defaults on every restart. The
proxy never persists switch values to disk; the YAML is the only source of
defaults.

The ``enforcement_mode`` switch is special: the proxy guarantees one is
always present so operational mode can be changed without editing every
policy. The supported modes are ``audit``, ``warn``, and ``enforce``.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

from instrlib import Event

DRY_RUN_SWITCH_ID = "dry_run"
ENFORCEMENT_MODE_SWITCH_ID = "enforcement_mode"
ENFORCEMENT_MODE_CHOICES = ("audit", "warn", "enforce")
# `number` is a back-compat alias for `int`; loaders normalise to `int`
# but we still accept it here so any in-process spec construction works.
_VALID_KINDS = frozenset({"int", "number", "boolean", "choice"})
_NUMERIC_KINDS = frozenset({"int", "number"})


@dataclass(frozen=True)
class SwitchSpec:
    """One YAML-declared switch description."""

    id: str
    kind: str
    label: str = ""
    default: Any = None
    min_value: float | None = None
    max_value: float | None = None
    options: tuple[str, ...] = ()


def default_dry_run_spec() -> SwitchSpec:
    """Return the legacy dry_run spec for old configs/tests.

    New configs should use ``enforcement_mode`` instead.
    """

    return SwitchSpec(
        id=DRY_RUN_SWITCH_ID,
        kind="boolean",
        label="Dry-run mode (log only, never block)",
        default=False,
    )


def default_enforcement_mode_spec(default: str = "enforce") -> SwitchSpec:
    """Return the global operational-mode switch used when YAML omits it."""

    if default not in ENFORCEMENT_MODE_CHOICES:
        default = "enforce"
    return SwitchSpec(
        id=ENFORCEMENT_MODE_SWITCH_ID,
        kind="choice",
        label="Enforcement mode",
        default=default,
        options=ENFORCEMENT_MODE_CHOICES,
    )


class SwitchState:
    """Thread-safe in-memory store for switch values + immutable schema."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._specs: dict[str, SwitchSpec] = {}
        self._values: dict[str, str] = {}

    def install(self, specs: list[SwitchSpec]) -> None:
        """Replace the schema and reset values to declared defaults."""

        with self._lock:
            self._specs = {}
            self._values = {}
            for spec in specs:
                if spec.kind not in _VALID_KINDS:
                    raise ValueError(
                        f"switch {spec.id!r} has unsupported kind {spec.kind!r}"
                    )
                if spec.id in self._specs:
                    raise ValueError(f"duplicate switch id: {spec.id!r}")
                self._specs[spec.id] = spec
                self._values[spec.id] = _coerce_default(spec)
            if ENFORCEMENT_MODE_SWITCH_ID not in self._specs:
                fallback = default_enforcement_mode_spec(
                    "warn" if self.get_bool(DRY_RUN_SWITCH_ID) else "enforce"
                )
                self._specs[ENFORCEMENT_MODE_SWITCH_ID] = fallback
                self._values[ENFORCEMENT_MODE_SWITCH_ID] = _coerce_default(fallback)

    def specs(self) -> list[SwitchSpec]:
        with self._lock:
            return list(self._specs.values())

    def get_spec(self, switch_id: str) -> SwitchSpec | None:
        with self._lock:
            return self._specs.get(switch_id)

    def has(self, switch_id: str) -> bool:
        with self._lock:
            return switch_id in self._specs

    def get_value(self, switch_id: str) -> str:
        with self._lock:
            return self._values.get(switch_id, "")

    def get_bool(self, switch_id: str) -> bool:
        return self.get_value(switch_id).strip().lower() == "true"

    def get_int(self, switch_id: str) -> int:
        text = self.get_value(switch_id).strip()
        if not text:
            return 0
        try:
            return int(float(text))
        except ValueError:
            return 0

    def set_value(self, switch_id: str, value: Any) -> str:
        """Validate ``value`` against the spec and store it. Returns the canonical string."""

        with self._lock:
            spec = self._specs.get(switch_id)
            if spec is None:
                raise KeyError(switch_id)
            normalized = _validate_and_coerce(spec, value)
            self._values[switch_id] = normalized
            return normalized

    def snapshot(self) -> dict[str, str]:
        with self._lock:
            return dict(self._values)

    def emit_events(self, tid: int) -> list[Event]:
        """Return one MFOTL event per setting with the current value at ``tid``.

        v4 emits ``SettingInt``, ``SettingBool``, or ``SettingString`` — one
        per declared switch. Policies that need float-precision thresholds
        encode them as int basis points (700 stands for 0.70).
        """

        events: list[Event] = []
        with self._lock:
            for switch_id, value in self._values.items():
                spec = self._specs.get(switch_id)
                if spec is None:
                    continue
                if spec.kind in {"int", "number"}:
                    try:
                        events.append(Event("SettingInt", tid, switch_id, int(float(value))))
                    except ValueError:
                        events.append(Event("SettingInt", tid, switch_id, 0))
                elif spec.kind == "boolean":
                    flag = 1 if value.strip().lower() == "true" else 0
                    events.append(Event("SettingBool", tid, switch_id, flag))
                else:  # choice (or any future text-shaped kind)
                    events.append(Event("SettingString", tid, switch_id, value))
        return events

    def to_admin_payload(self) -> list[dict[str, Any]]:
        """Return a JSON-shaped list with both schema and current values for the UI."""

        payload: list[dict[str, Any]] = []
        with self._lock:
            for switch_id, spec in self._specs.items():
                entry: dict[str, Any] = {
                    "id": spec.id,
                    "kind": spec.kind,
                    "label": spec.label,
                    "current": self._values.get(switch_id, ""),
                    "default": _coerce_default(spec),
                }
                if spec.kind in _NUMERIC_KINDS:
                    if spec.min_value is not None:
                        entry["min"] = spec.min_value
                    if spec.max_value is not None:
                        entry["max"] = spec.max_value
                if spec.kind == "choice":
                    entry["options"] = list(spec.options)
                payload.append(entry)
        return payload


def _coerce_default(spec: SwitchSpec) -> str:
    if spec.kind == "boolean":
        return "true" if bool(spec.default) else "false"
    if spec.kind in _NUMERIC_KINDS:
        if spec.default is None:
            base = 0
        else:
            try:
                base = int(float(spec.default))
            except (TypeError, ValueError):
                base = 0
        return str(base)
    if spec.kind == "choice":
        if spec.default is None or str(spec.default) == "":
            return spec.options[0] if spec.options else ""
        return str(spec.default)
    return str(spec.default if spec.default is not None else "")


def _validate_and_coerce(spec: SwitchSpec, value: Any) -> str:
    if spec.kind in _NUMERIC_KINDS:
        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"switch {spec.id!r} requires a number, got {value!r}"
            ) from exc
        if float(value) != int(float(value)):
            raise ValueError(
                f"switch {spec.id!r}: int switch requires an integer, got {value!r}"
            )
        if spec.min_value is not None and number < spec.min_value:
            raise ValueError(
                f"switch {spec.id!r}: {number} is below the configured minimum {spec.min_value}"
            )
        if spec.max_value is not None and number > spec.max_value:
            raise ValueError(
                f"switch {spec.id!r}: {number} is above the configured maximum {spec.max_value}"
            )
        return str(int(number))
    if spec.kind == "boolean":
        if isinstance(value, bool):
            return "true" if value else "false"
        text = str(value).strip().lower()
        if text in {"true", "1", "yes", "on"}:
            return "true"
        if text in {"false", "0", "no", "off"}:
            return "false"
        raise ValueError(f"switch {spec.id!r} requires a boolean, got {value!r}")
    if spec.kind == "choice":
        text = str(value)
        if spec.options and text not in spec.options:
            raise ValueError(
                f"switch {spec.id!r} requires one of {list(spec.options)}, got {value!r}"
            )
        return text
    raise ValueError(f"switch {spec.id!r} has unsupported kind {spec.kind!r}")


