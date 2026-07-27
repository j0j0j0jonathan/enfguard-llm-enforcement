"""
instrlib.pep

Policy Enforcement Point: wires together η_i mappings and η_e handlers.

PEP holds three registries:
  mapping              — (ClassName, method_name) → η_i function
                         Called by @Instrument to produce events from a method call.
  causation_handlers   — event_name (or tuple) → η_e callable
                         Called when EnfGuard issues a Cause command.
  suppression_handlers — event_name (or tuple) → η_e callable
                         Called when EnfGuard issues a Suppress command.

The PEP is instantiated empty in proxy.py and populated by the deployment code.

"""
from itertools import chain
from typing import Any, Callable, Dict, List, Tuple, Union

from instrlib.event import Event
from instrlib.handler_graph import generate_graph


class PEP:

    def __init__(
        self,
        mapping:              Dict[Tuple[str, str], Callable[..., List[Event]]] = {},
        causation_handlers:   Dict[Union[str, Tuple[str, ...]], Any]            = {},
        suppression_handlers: Dict[Union[str, Tuple[str, ...]], Any]            = {},
    ) -> None:
        # η_i mapping registry: (ClassName, method_name) → callable
        self._mapping: Dict[Tuple[str, str], Callable] = {}
        for key, fn in mapping.items():
            self._mapping[key] = fn

        # η_e handler registries
        self.cau_event_map: Dict[Union[str, Tuple[str, ...]], Any] = causation_handlers
        self.sup_event_map: Dict[Union[str, Tuple[str, ...]], Any] = suppression_handlers

        # Hasse diagrams for priority resolution
        self.cau_graph = generate_graph(self.cau_event_map)
        self.sup_graph = generate_graph(self.sup_event_map)

    # η_i access

    def __contains__(self, key: Tuple[str, str]) -> bool:
        return key in self._mapping

    def __getitem__(self, key: Tuple[str, str]) -> Callable:
        if key not in self._mapping:
            raise KeyError(f"PEP: no mapping registered for {key}.")
        return self._mapping[key]

    def __iter__(self):
        return iter(self._mapping)

    # Composition 
    def __or__(self, other: "PEP") -> "PEP":
        return PEP(
            mapping              = dict(chain(self._mapping.items(),       other._mapping.items())),
            causation_handlers   = dict(chain(self.cau_event_map.items(),  other.cau_event_map.items())),
            suppression_handlers = dict(chain(self.sup_event_map.items(),  other.sup_event_map.items())),
        )
