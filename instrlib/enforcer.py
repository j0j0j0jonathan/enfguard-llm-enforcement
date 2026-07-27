"""
instrlib.enforcer: Persistent EnfGuard process manager with writer + reader threads

Trace format (sent to EnfGuard stdin)

  @<trace_timestamp> Event1(args) Event2(args);

``trace_timestamp`` is either the historical logical ``tid`` or Unix seconds.
Event arguments still carry ``tid`` for identity and UI/proxy correlation.

Verdict format (received from EnfGuard stdout)

  {"suppress": [{"name": "...", "args": [...]}, ...],
   "cause":    [{"name": "...", "args": [...]}, ...]}
"""

import json
import os
import datetime
import re
import time
from queue import Queue, PriorityQueue, Empty
from subprocess import Popen, PIPE, STDOUT, TimeoutExpired
from threading import Thread, Event as ThreadEvent, Lock
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from instrlib.event import Event, TimedTuple
from instrlib.handler_graph import max_element


# Liveness guards against the temporal-policy "proactive flood" bug. A bounded
# metric MFOTL obligation (e.g. nested `ONCE [*, 1000]` under `IMPLIES:R`) can
# drive EnfGuard into an unbounded proactive-timestamp stream that never returns
# the awaited verdict for a pending query. Without a guard, the query in _send()
# blocks forever (flag.wait() with no timeout) and the whole request hangs.
# Both limits are env-tunable.
#   _QUERY_TIMEOUT_S  — backstop wait in _send(); on expiry return a fail-open
#                       default ({} cause/suppress = pass through) and log.
#   _PROACTIVE_CAP    — primary guard in the reader: if this many proactive
#                       messages arrive while a query is pending, release the
#                       oldest waiter fail-open AND consume its read-queue slot so
#                       request/response alignment is preserved.
_QUERY_TIMEOUT_S = float(os.environ.get("ENFGUARD_QUERY_TIMEOUT_S", "20"))
_PROACTIVE_CAP   = int(os.environ.get("ENFGUARD_PROACTIVE_CAP", "500"))
_HEARTBEAT_INTERVAL_S = float(os.environ.get("ENFGUARD_HEARTBEAT_SECONDS", "1"))
_METRIC_TEMPORAL_RE = re.compile(
    r"\b(?:ONCE|EVENTUALLY|HISTORICALLY|ALWAYS|SINCE|UNTIL)\s*\[",
    re.IGNORECASE,
)


# colour-coded debug printer

_COLORS = {
    "writer":    "\033[32m",
    "reader":    "\033[33m",
    "proactive": "\033[35m",
    "reset":     "\033[0m",
}

def _log(agent: str, msg: str) -> None:
    ts    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    pad   = agent + (10 - len(agent)) * " "
    color = _COLORS.get(agent, "")
    reset = _COLORS["reset"]
    print(f"{color}[{ts}] [{pad}]: {msg}{reset}", flush=True)


# enforcer 

class Enforcer:
    """

    Lifecycle
 
    enforcer = Enforcer(binary, sig, formula, env, time_mode="wall_seconds")
    enforcer.start()     ← spawns EnfGuard, starts writer + reader threads
    enforcer.stop()      ← signals threads to exit, waits for EnfGuard to terminate

    Sending events

    verdict = enforcer.query(events, tid)
        → sends "@trace_timestamp Event1() Event2();" to EnfGuard
        → blocks until JSON verdict arrives
        → returns {"cause": [...], "suppress": [...]}

    enforcer.log(events, tid)
        → sends "@trace_timestamp Event1() Event2();" to EnfGuard
        → returns immediately
    """

    def __init__(
        self,
        binary:     str,
        sig:        str,
        formula:    str,
        env:        Optional[Dict[str, str]] = None,
        fun:        Optional[str] = None,
        trace_path: Optional[str] = None,
        time_mode:  str = "logical",
        clock:      Callable[[], float] = time.time,
    ) -> None:
        self._binary  = binary
        self._sig     = sig
        self._formula = formula
        self._env     = env
        self._fun     = fun           # path to Python functions file for -func flag
        self._trace_path = trace_path # path to trace log file (cleared on start)
        if time_mode not in {"logical", "wall_seconds"}:
            raise ValueError(f"unsupported EnfGuard time mode: {time_mode!r}")
        self._time_mode = time_mode
        self._clock = clock
        self._last_trace_ts: Optional[int] = None
        self._timestamp_lock = Lock()

        self._proc:         Optional[Popen]  = None
        self._writer_thread: Optional[Thread] = None
        self._reader_thread: Optional[Thread] = None
        self._heartbeat_thread: Optional[Thread] = None
        self._heartbeat_lock = Lock()
        self._explicit_trace_time_seen = False

        self._write_prio: PriorityQueue  = PriorityQueue()
        self._read_queue: Queue          = Queue()
        self._stop_flag:  ThreadEvent    = ThreadEvent()
        self._last_event_tid: int = 0
        self._tid_lock = Lock()
        # Count of proactive messages seen since the last real verdict; reset on
        # every non-proactive message. Used by the reader's proactive-flood guard.
        self._proactive_since_verdict: int = 0

        self._trace_file = None
        self._trace_lock = Lock()

    # trace file

    def _trace(self, direction: str, content: str) -> None:
        """Append one entry to the trace file (thread-safe). No-op if no trace path."""
        if self._trace_file is None:
            return
        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        with self._trace_lock:
            self._trace_file.write(f"[{ts}] {direction:<10} {content}\n")

    def trace_request_start(self, tid: int) -> None:
        """Write a visual separator at the start of each new request. Called by proxy."""
        if self._trace_file is None:
            return
        with self._trace_lock:
            self._trace_file.write(f"\nRequest {tid}\n")

    # lifecycle

    def start(self) -> None:
        # Open trace file (clear it) before starting threads
        if self._trace_path:
            self._trace_file = open(self._trace_path, "w", encoding="utf-8", buffering=1)
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                policy_text = open(self._formula, encoding="utf-8").read().strip() or "(empty, all requests pass through)"
            except Exception:
                policy_text = "(could not read formula file)"
            self._trace_file.write("\n")
            self._trace_file.write(f"  EnfGuard Trace {ts}\n")
            self._trace_file.write("\n")
            self._trace_file.write(f"Policy:\n{policy_text}\n")
            self._trace_file.write("\n")

        cmd = [
            self._binary,
            "-sig",     self._sig,
            "-formula", self._formula,
            "-json",
        ]
        if self._fun:
            cmd += ["-func", self._fun]
        _log("writer", f"Starting EnfGuard: {' '.join(cmd)}")
        self._proc = Popen(
            cmd,
            stdin=PIPE, stdout=PIPE, stderr=STDOUT,
            env=self._env,
        )
        self._writer_thread = Thread(target=self._run_writer, daemon=True)
        self._reader_thread = Thread(target=self._run_reader, daemon=True)
        self._writer_thread.start()
        self._reader_thread.start()

    def stop(self) -> None:
        _log("writer", "Stopping EnfGuard.")
        self._stop_flag.set()
        if self._proc is not None:
            try:
                self._proc.stdin.close()
            except Exception:
                pass
            try:
                self._proc.wait(timeout=5)
            except TimeoutExpired:
                _log("writer", "EnfGuard did not exit in 5s, killing.")
                self._proc.kill()
        if self._trace_file is not None:
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with self._trace_lock:
                self._trace_file.write("\n\n")
                self._trace_file.write(f"  Trace ended {ts}\n")
                self._trace_file.write("\n")
                self._trace_file.close()
            self._trace_file = None

    # public API 

    def query(
        self,
        events: List[Event],
        tid: int,
        trace_ts: Optional[int] = None,
    ) -> Dict[str, List]:
        if trace_ts is not None:
            self._explicit_trace_time_seen = True
        self._record_event_tid(tid)
        timestamp = self._trace_timestamp(tid, trace_ts)
        stm = self._format(events, timestamp)
        verdict = self._send(stm, tid, timestamp, expects_response=True)
        self._ensure_heartbeat_started(trace_ts)
        return verdict

    def log(
        self,
        events: List[Event],
        tid: int,
        trace_ts: Optional[int] = None,
    ) -> None:
        if trace_ts is not None:
            self._explicit_trace_time_seen = True
        self._record_event_tid(tid)
        timestamp = self._trace_timestamp(tid, trace_ts)
        stm = self._format(events, timestamp)
        self._send(stm, tid, timestamp, expects_response=False)
        self._ensure_heartbeat_started(trace_ts)

    # formatting 

    @staticmethod
    def _format(events: List[Event], timestamp: int) -> bytes:
        body = " ".join(str(e) for e in events)
        line = f"@{timestamp} {body};"
        return line.encode()

    def _trace_timestamp(self, tid: int, explicit: Optional[int]) -> int:
        """Resolve a nondecreasing MFOTL timestamp independently from ``tid``."""

        if explicit is not None:
            candidate = int(explicit)
        elif self._time_mode == "wall_seconds":
            candidate = int(self._clock())
        else:
            candidate = int(tid)

        with self._timestamp_lock:
            if self._last_trace_ts is not None:
                candidate = max(candidate, self._last_trace_ts)
            self._last_trace_ts = candidate
        return candidate

    # internal send
    
    def _send(
        self,
        stm:              bytes,
        tid:              int,
        trace_ts:         int,
        expects_response: bool,
        queue_key:        Optional[float] = None,
        quiet:            bool = False,
    ) -> Dict[str, List]:
        flag        = ThreadEvent()
        result_q: Queue = Queue()
       
        
        item = TimedTuple(
            tid if queue_key is None else queue_key,
            (flag, result_q, stm, trace_ts, quiet),
            expects_response=expects_response,
        )
        self._write_prio.put(item)

        if not expects_response:
            return {}          # don't wait, flag will be set by reader, nobody cares

        # Bounded wait. A metric/temporal policy can drive EnfGuard into an
        # unbounded proactive-timestamp stream and never return the verdict for
        # this query; flag.wait() with no timeout would then hang the request
        # forever and freeze NanoClaw. The reader's proactive cap is the primary
        # guard (and keeps the read queue aligned); this timeout is the backstop
        # for any other stall. On expiry, fail open (pass the request through).
        if not flag.wait(timeout=_QUERY_TIMEOUT_S):
            removed = self._remove_pending_waiter(flag)
            _log("reader",
                 f"[guard] query tid={tid} got no verdict in {_QUERY_TIMEOUT_S}s; "
                 f"returning fail-open default (pending_removed={removed})")
            self._trace(
                "TIMEOUT",
                f"tid={tid} no verdict in {_QUERY_TIMEOUT_S}s; "
                f"pending_removed={removed}",
            )
            return {"cause": [], "suppress": []}
        verdict = result_q.get()
        return verdict

    # writer thread
    
    def _run_writer(self) -> None:
        _log("writer", "Started.")
        while not self._stop_flag.is_set():
            try:
                item: TimedTuple = self._write_prio.get(timeout=0.1)
            except Empty:
                continue

            flag, result_q, stm, trace_ts, quiet = item.event_tuple

            # Always register so reader can drain EnfGuard's response for this statement.
            # For ';' sends (expects_response=False), the flag is set but nobody waits on it.
            self._read_queue.put(
                TimedTuple(item.tsp, (flag, result_q, stm, trace_ts, quiet))
            )

            assert self._proc is not None
            if self._proc.poll() is None:
                try:
                    self._proc.stdin.write(stm)
                    self._proc.stdin.flush()
                    if not quiet:
                        line = stm.decode().rstrip()
                        _log("writer", f"→ {line}")
                        self._trace("SEND", line)
                except Exception as e:
                    _log("writer", f"Error writing to stdin: {e}")
        _log("writer", "Terminated.")

    # reader thread

    def _run_reader(self) -> None:
        _log("reader", "Started.")
        assert self._proc is not None

        try:
            while self._proc.poll() is None:
                try:
                    raw = self._proc.stdout.readline()
                    if not raw:
                        time.sleep(0.01)
                        continue
                    msg_str = raw.decode()
                    try:
                        msg = json.loads(msg_str)
                    except json.JSONDecodeError:
                        stripped = msg_str.strip()
                        _log("reader", f"Skipping non-JSON: {stripped}")
                        self._trace("FUNC", stripped)
                        continue

                    # Proactive messages are pushed by EnfGuard without a corresponding query.
                    if msg.get("proactive"):
                        if msg.get("cause"):
                            _log("reader", f"← {msg}")
                            self._trace("PROACTIVE", msg_str.strip())
                            self._handle_proactive(msg)
                        # Liveness guard: a metric/temporal policy can make
                        # EnfGuard stream proactive timestamps without ever
                        # returning the awaited verdict. If the stream exceeds the
                        # cap while a query is pending, release the oldest waiter
                        # fail-open and consume its read-queue slot so the next
                        # real verdict still lines up with the right query.
                        proactive_ts = msg.get("ts")
                        target_ts = self._pending_trace_timestamp()
                        expected_catch_up = (
                            isinstance(proactive_ts, int)
                            and target_ts is not None
                            and proactive_ts <= target_ts
                        )
                        if not expected_catch_up:
                            self._proactive_since_verdict += 1
                        if (self._proactive_since_verdict > _PROACTIVE_CAP
                                and not self._read_queue.empty()):
                            try:
                                item = self._read_queue.get_nowait()
                                flag, result_q, _, _, _ = item.event_tuple
                                result_q.put({"cause": [], "suppress": []})
                                flag.set()
                                _log("reader",
                                     f"[guard] proactive flood > {_PROACTIVE_CAP} "
                                     f"with a query pending; released waiter fail-open")
                                self._trace("GUARD",
                                            f"proactive flood > {_PROACTIVE_CAP}; released waiter")
                            except Empty:
                                pass
                            self._proactive_since_verdict = 0
                        continue

                    # A real (non-proactive) verdict arrived: clear the flood counter.
                    self._proactive_since_verdict = 0

                    # Match to the waiting request
                    item: TimedTuple    = self._read_queue.get()
                    flag, result_q, _, _, quiet = item.event_tuple
                    if not quiet:
                        _log("reader", f"← {msg}")
                        self._trace("RECV", msg_str.strip())
                    result_q.put(msg)
                    flag.set()

                except Exception as e:
                    _log("reader", f"Error: {e}")

        finally:
            # EnfGuard process exited (crash or normal stop).
            # Drain every item still in _read_queue so that any main-thread
            # caller blocked in flag.wait() gets an empty-verdict response
            # instead of hanging forever.
            _log("reader", "Draining pending waiters after process exit.")
            while True:
                try:
                    item = self._read_queue.get_nowait()
                    flag, result_q, _, _, _ = item.event_tuple
                    result_q.put({"cause": [], "suppress": []})
                    flag.set()
                except Empty:
                    break

            _log("reader", "EnfGuard process terminated.")

    def _pending_trace_timestamp(self) -> Optional[int]:
        """Peek at the oldest query's target timestamp without dequeuing it."""

        with self._read_queue.mutex:
            if not self._read_queue.queue:
                return None
            item = self._read_queue.queue[0]
            return int(item.event_tuple[3])

    def _remove_pending_waiter(self, flag: ThreadEvent) -> bool:
        """Remove a timed-out waiter so later verdicts cannot be misrouted."""

        with self._read_queue.mutex:
            for index, item in enumerate(self._read_queue.queue):
                if item.event_tuple[0] is flag:
                    del self._read_queue.queue[index]
                    self._read_queue.not_full.notify()
                    return True
        return False

    def _record_event_tid(self, tid: int) -> None:
        with self._tid_lock:
            self._last_event_tid = max(self._last_event_tid, int(tid))

    def _heartbeat_enabled(self) -> bool:
        if self._time_mode != "wall_seconds" or _HEARTBEAT_INTERVAL_S <= 0:
            return False
        try:
            formula = open(self._formula, encoding="utf-8").read()
        except OSError:
            return False
        return bool(_METRIC_TEMPORAL_RE.search(formula))

    def _ensure_heartbeat_started(self, trace_ts: Optional[int]) -> None:
        if trace_ts is not None or self._explicit_trace_time_seen:
            return
        with self._heartbeat_lock:
            if self._heartbeat_thread is not None or not self._heartbeat_enabled():
                return
            self._heartbeat_thread = Thread(target=self._run_heartbeat, daemon=True)
            self._heartbeat_thread.start()

    def _run_heartbeat(self) -> None:
        """Advance metric trace time while the agent is otherwise idle."""

        while not self._stop_flag.wait(_HEARTBEAT_INTERVAL_S):
            timestamp = self._trace_timestamp(0, None)
            with self._tid_lock:
                queue_key = self._last_event_tid + 0.5
            self._send(
                self._format([], timestamp),
                tid=0,
                trace_ts=timestamp,
                expects_response=True,
                queue_key=queue_key,
                quiet=True,
            )

    # proactive causation 
    def _handle_proactive(self, msg: Dict[str, Any]) -> None:
        _log("proactive", f"Proactive cause received: {msg.get('cause')}")
        if self._pep is not None:
            names = tuple({e["name"] for e in msg["cause"]})
            from instrlib.handler_graph import max_element
            for h_key in max_element(self._pep.cau_graph, names):
                handler = self._pep.cau_event_map.get(h_key)
                if handler:
                    relevant = [e for e in msg["cause"] if e["name"] in h_key]
                    handler(relevant)

    # Attached by Logger after construction
    _pep = None
