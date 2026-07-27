"""
instrlib.schema

Runtime type registry for EnfGuard events.

Maps event names to their argument type lists and validates Event objects before sent to efguard.
"""

from itertools import chain
from typing import Dict, List, Type

from instrlib.event import Event


class Schema:

    def __init__(self) -> None:
        self._types: Dict[str, List[Type]] = {}

    # registration 
    def add(self, name: str, types: List[Type]) -> None:
        """Register an event name with its argument types."""
        if name in self._types:
            raise ValueError(f"Schema: event '{name}' already registered.")
        self._types[name] = types

    def remove(self, name: str) -> None:
        self._types.pop(name, None)

    # validation
    
    def validate(self, event: Event) -> None:
        """
        Check that event.name is registered and its args match the declared types.
        Coerces args in place (e.g. int → float, str → int for numeric strings).
        Raises ValueError on any type mismatch that cannot be coerced.
        """
        if event.name not in self._types:
            raise ValueError(f"Schema: unknown event '{event.name}'.")

        expected = self._types[event.name]
        actual   = list(event.args)

        if len(actual) != len(expected):
            raise ValueError(
                f"Schema: '{event.name}' expects {len(expected)} args, "
                f"got {len(actual)}."
            )

        coerced = []
        for i, (arg, typ) in enumerate(zip(actual, expected)):
            if isinstance(arg, typ):
                coerced.append(arg)
            elif typ is str:
                coerced.append(str(arg))
            elif typ is int and isinstance(arg, str) and arg.lstrip("-").isnumeric():
                coerced.append(int(arg))
            elif typ is float and isinstance(arg, (int, float)):
                coerced.append(float(arg))
            else:
                raise ValueError(
                    f"Schema: '{event.name}' arg {i}: expected {typ.__name__}, "
                    f"got {type(arg).__name__} ({arg!r})."
                )
        event.args = tuple(coerced)

    def get_types(self, name: str) -> List[Type]:
        if name not in self._types:
            raise ValueError(f"Schema: unknown event '{name}'.")
        return self._types[name]

    # composition 
    def __or__(self, other: "Schema") -> "Schema":
        s = Schema()
        s._types = dict(chain(self._types.items(), other._types.items()))
        return s

    def __contains__(self, name: str) -> bool:
        return name in self._types

    def __iter__(self):
        return iter(self._types)
