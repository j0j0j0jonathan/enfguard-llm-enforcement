"""
instrlib.instrument

currently not used, only for first version

@Instrument class decorator, transparently enforces policies on application classes.

@Instrument intercepts every call to a registered method and:
  1.  Calls the η_i mapping function → List[Event]
  2.  Sends events to logger.log(events, tid) → verdict
  3.  Calls the original method → baseline result
  4.  Routes verdict to the appropriate η_e handler → enforced result
  5.  Returns enforced result (or original if no verdict)
"""

from typing import Any, Callable, Dict, List, Optional, Tuple, Type

from instrlib.event  import Event
from instrlib.logger import Logger
from instrlib.pep    import PEP


class Instrument:
    """Class decorator. Usage: @Instrument(logger)"""

    def __init__(self, logger: Logger) -> None:
        self._logger = logger

    def __call__(self, cls: Type) -> Type:
        class_name = cls.__qualname__
        logger     = self._logger
        pep        = logger.pep

        for method_name in list(vars(cls)):
            key = (class_name, method_name)
            if key not in pep:
                continue
            original   = getattr(cls, method_name)
            mapping_fn = pep[key]
            setattr(cls, method_name, _make_wrapper(original, mapping_fn, logger, pep))

        return cls


def _make_wrapper(
    original:   Callable,
    mapping_fn: Callable,
    logger:     Logger,
    pep:        PEP,
) -> Callable:
    """
    Build the enforcement wrapper for a single instrumented method.

    Execution order
    1. η_i  : mapping_fn(*args, **kwargs)       → List[Event]
    2. PDP  : logger.log(events, tid)           → (cau_flag, sup_flag, cau_enc, sup_enc)
    3. SuE  : original(inst, *args, **kwargs)   → original_result
    4. η_e  : handler(original_result, ...)     → enforced_result
    5. return enforced_result
    """
    def wrapper(inst: Any, *args: Any, **kwargs: Any) -> Any:
        # Step 1: η_i produce events
        events: List[Event] = mapping_fn(*args, **kwargs)

        # Extract tid from first event's first argument
        tid: int = events[0].args[0] if events and events[0].args else 0

        # Step 2: PDP  get verdict from EnfGuard
        cau_flag, sup_flag, cau_enc, sup_enc = logger.log(events, tid)

        # Step 3: SuE, call original method (baseline result)
        original_result: Any = original(inst, *args, **kwargs)

        # Step 4a: causation, most-specific handler wins (registration order)
        if cau_flag:
            for event_name, handler in pep.cau_event_map.items():
                if event_name in cau_enc:
                    args_list = cau_enc[event_name]
                    return handler(original_result, args_list)

        # Step 4b: suppression
        if sup_flag:
            for event_name, args_list in sup_enc.items():
                handler = pep.sup_event_map.get(event_name)
                if handler is not None:
                    return handler(original_result, args_list)

        # Step 5: pass-through
        return original_result

    return wrapper
