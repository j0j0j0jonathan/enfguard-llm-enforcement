"""
instrlib.logger

Logger: central coordinator that ties Schema, PEP, and Enforcer together.


  validate   — check events against the schema before sending to EnfGuard
  log()      — send events + wait for verdict → return parsed (cau, sup) dicts
  log_only() — send events for bookkeeping only, no verdict needed

"""

import threading
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from instrlib.enforcer import Enforcer
from instrlib.event     import Event
from instrlib.pep       import PEP
from instrlib.schema    import Schema


class Logger:

    def __init__(self, pep: PEP, schema: Schema, enforcer: Enforcer) -> None:
        self.pep      = pep
        self.schema   = schema
        self.enforcer = enforcer
        self._lock    = threading.Lock()

        # Wire PEP into enforcer for proactive causation
        self.enforcer._pep = pep

    #  Main enforcement path 
    def log(
        self,
        events: List[Event],
        tid:    int,
    ) -> Tuple[
        bool,                        # cau_flag : any causation?
        bool,                        # sup_flag : any suppression?
        Dict[str, List[tuple]],      # cau_enc  : {"EventName": [(args,...), ...]}
        Dict[str, List[tuple]],      # sup_enc  : {"EventName": [(args,...), ...]}
    ]:
        """
        Validate events, send to EnfGuard via query(), parse verdict.
        Acquires the serialization lock, concurrent calls queue up.
        """
        with self._lock:
            for event in events:
                self.schema.validate(event)

            raw = self.enforcer.query(events, tid)
            return self._parse_verdict(raw)

    # Bookkeeping-only path

    def log_only(self, events: List[Event], tid: int) -> None:
        """
        Write events to EnfGuard trace without blocking
        """
        with self._lock:
            for event in events:
                self.schema.validate(event)
            self.enforcer.log(events, tid)

    # Verdict parsing

    @staticmethod
    def _parse_verdict(
        raw: Dict[str, Any],
    ) -> Tuple[bool, bool, Dict[str, List[tuple]], Dict[str, List[tuple]]]:
        """
        Convert raw JSON verdict into typed dicts.

        Raw format (from EnfGuard JSON output):
            {"cause":    [{"name": "BlockAction", "args": [3]}, ...],
             "suppress": [{"name": "Completion",  "args": [3, "hi", 50]}, ...]}

        Output format:
            cau_enc = {"BlockAction": [(3,)], ...}
            sup_enc = {"Completion":  [(3, "hi", 50)], ...}
        """
        cau_enc: Dict[str, List[tuple]] = {}
        sup_enc: Dict[str, List[tuple]] = {}

        for item in raw.get("cause", []):
            name = item["name"]
            args = tuple(item.get("args", []))
            cau_enc.setdefault(name, []).append(args)

        for item in raw.get("suppress", []):
            name = item["name"]
            args = tuple(item.get("args", []))
            sup_enc.setdefault(name, []).append(args)

        return bool(cau_enc), bool(sup_enc), cau_enc, sup_enc
