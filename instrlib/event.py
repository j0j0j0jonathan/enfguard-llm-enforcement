"""
instrlib.event
Adapted from instrlib-main/miniTwitter_case_study/.../instrlib/event.py.
"""

from typing import Any, Tuple


class Event:
    """
    A single MFOTL event: a name and zero or more arguments.

    Serializes to EnfGuard log format:

    String arguments automatically quoted and escaped.
    Numeric arguments are emitted as-is.
    """

    def __init__(self, name: str, *args: Any) -> None:
        self.name: str            = name
        self.args: Tuple[Any,...] = args

    def get_num_args(self) -> int:
        return len(self.args)

    @staticmethod
    def _format_arg(s: Any) -> str:
        """Format a single argument for the EnfGuard log."""
        s = str(s)
        if s.lstrip("-").isnumeric() or _is_float(s):
            return s
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'

    def __str__(self) -> str:
        args_str = ", ".join(self._format_arg(a) for a in self.args)
        return f"{self.name}({args_str})"

    def __repr__(self) -> str:
        return self.__str__()

    def __hash__(self) -> int:
        return hash(repr(self))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Event) and hash(self) == hash(other)


class TimedTuple:
    """
    Priority-queue entry: an event bundle with a timestamp and a flag
    indicating whether EnfGuard is expected to respond.

    tsp            : queue-order key (= request counter / tid)
    event_tuple    : (threading.Event flag, result Queue, bytes to send)

    The MFOTL trace timestamp serialized after ``@`` is already embedded in
    ``stm``. It may be wall-clock seconds and is intentionally separate from
    this ordering key.
    """

    def __init__(
        self,
        tsp: int,
        event_tuple: Tuple[Any, ...],
        expects_response: bool = True,
    ) -> None:
        self.tsp              = tsp
        self.event_tuple      = event_tuple
        self.expects_response = expects_response

    def __lt__(self, other: "TimedTuple") -> bool:
        return self.tsp < other.tsp


# helpers

def _is_float(s: str) -> bool:
    try:
        float(s)
        return True
    except ValueError:
        return False
