"""Executes LLM-authored Python against the open binary.

The code runs in this process with Binary Ninja's own privileges. There is no sandbox: a
plugin that takes no dependencies has no way to build one, and `bv` alone reaches enough of the
process that restricting the rest would not buy anything. Binding to localhost and requiring the
API key are the boundary.
"""

import ast
import ctypes
import json
import math
import sys
import threading
import time
import traceback
import types
from dataclasses import dataclass
from io import StringIO
from typing import TYPE_CHECKING

import binaryninja

if TYPE_CHECKING:
    from binaryninja import BinaryView

# Keeps a single oversized dump from swamping the model's context. The cap applies to the rendered
# result only: the code itself always sees whole values, so an aggregate it computes is never
# quietly taken from a truncated list.
CHARS_PER_TOKEN = 4

# How long to keep trying to stop a timed-out thread before giving up and refusing further work,
# and how often to retry within that when only the fallback mechanism is available.
INTERRUPT_GRACE_S = 5.0
INTERRUPT_RETRY_S = 0.25

# sys.monitoring arrived in 3.12; Binary Ninja 4.0 predates it. Where it exists it is the right
# tool by a distance, so the async-exception path below stays only for older interpreters.
_HAS_MONITORING = hasattr(sys, "monitoring")


@dataclass
class ExecutionResult:
    """Result of code execution."""

    success: bool
    output: str
    error: str | None
    timed_out: bool = False


class CodeExecutor:
    """Executes Python with the plugin's namespaces, the BinaryView and binaryninja in scope."""

    def __init__(
        self,
        namespaces: dict,
        bv: "BinaryView",
        max_output_tokens: int = 6_000,
        timeout: float = 30.0,
    ):
        # The same mapping the tool description is rendered from, so the names the model is told
        # about are by construction the names it can actually call.
        self.namespaces = namespaces
        self.bv = bv
        self.max_output_tokens = max_output_tokens
        self.timeout = timeout
        # A timed-out thread that would not stop. It still holds the BinaryView, so the next
        # request is refused rather than run alongside it.
        self._abandoned: threading.Thread | None = None
        self._abandoned_code: list = []

    def validate(self, code: str) -> tuple[bool, str | None]:
        """Check that the code parses, so syntax errors are reported before anything runs."""
        try:
            compile(code, "<mcp>", "exec")
        except SyntaxError as e:
            return False, f"Syntax error: {e}"
        return True, None

    def execute(self, code: str) -> ExecutionResult:
        """Execute code and return whatever it printed, or the traceback it raised."""
        if self._abandoned is not None:
            # Nudge it again: it may since have left the core call that swallowed the earlier
            # attempts, in which case the server recovers here rather than needing a restart.
            if self._abandoned.is_alive():
                _stop(self._abandoned, self._abandoned_code, INTERRUPT_RETRY_S)
            if self._abandoned.is_alive():
                return ExecutionResult(
                    success=False,
                    output="",
                    error="A previous execution timed out and could not be interrupted; it is "
                    "still running against this BinaryView. Running now would let two scripts "
                    "mutate the database at once. Wait for it to finish, or restart the MCP "
                    "server from Binary Ninja's plugin menu if it never will.",
                )
            self._abandoned = None

        is_valid, error = self.validate(code)
        if not is_valid:
            return ExecutionResult(success=False, output="", error=error)

        printed = StringIO()
        body, tail = _split_trailing_expression(code)
        namespace = {
            **self.namespaces,
            "bv": self.bv,
            "bn": binaryninja,
            "print": lambda *args, **kwargs: print(*args, file=printed, **kwargs),
        }

        start_time = time.time()
        result_holder = {"value": None, "error": None}

        # Compiled out here rather than in the thread so the code objects are available to
        # _stop(), which arms line events on them and on nothing else.
        body_code = compile(body, "<mcp>", "exec")
        tail_code = compile(tail, "<mcp>", "eval") if tail is not None else None
        own_code = list(_nested_code(body_code))
        if tail_code is not None:
            own_code += list(_nested_code(tail_code))

        def run_code():
            try:
                # One dict for globals and locals: with separate ones, a function defined by the
                # code cannot see the names the code assigned, since its body resolves globals.
                exec(body_code, namespace)
                if tail_code is not None:
                    result_holder["value"] = eval(tail_code, namespace)
            except KeyboardInterrupt:
                # Raised into this thread by _interrupt() after the timeout. The result has
                # already gone back to the caller, so there is nothing to record.
                pass
            except Exception as e:
                result_holder["error"] = f"{type(e).__name__}: {e}\n{traceback.format_exc()}"

        # A daemon thread, so a runaway that outlives its call cannot hold up Binary Ninja's own
        # shutdown while the interpreter waits to join it.
        thread = threading.Thread(target=run_code, daemon=True)
        thread.start()
        thread.join(timeout=self.timeout)

        if thread.is_alive():
            elapsed = time.time() - start_time
            _stop(thread, own_code, INTERRUPT_GRACE_S)
            if thread.is_alive():
                self._abandoned = thread
                self._abandoned_code = own_code
                stopped = (
                    " It could not be interrupted and is still running, so the next call will be "
                    "refused until it finishes."
                )
            else:
                stopped = " It has since stopped, so nothing of it is still running."
            return ExecutionResult(
                success=False,
                output=self._truncate(printed.getvalue()),
                error=f"Execution timed out after {elapsed:.1f}s "
                f"(limit: {self.timeout}s).{stopped} Any output before the timeout is shown "
                f"above. Narrow the work: a smaller range, or fewer functions per call.",
                timed_out=True,
            )

        if result_holder["error"]:
            return ExecutionResult(
                success=False,
                output=self._truncate(printed.getvalue()),
                error=result_holder["error"],
            )

        return ExecutionResult(
            success=True,
            output=self._truncate(_render(printed.getvalue(), result_holder["value"])),
            error=None,
        )

    def _truncate(self, text: str) -> str:
        limit = self.max_output_tokens * CHARS_PER_TOKEN
        if len(text) <= limit:
            return text
        # Report what the whole result would have cost rather than what was dropped: the model
        # needs the size of its mistake to judge how much further to narrow.
        estimated = math.ceil(len(text) / CHARS_PER_TOKEN)
        return (
            f"{text[:limit]}\n\n--- TRUNCATED ---\n"
            f"This result was ~{estimated:,} tokens (limit: {self.max_output_tokens:,}). "
            f"Return a summary rather than the rows: aggregate with len() or "
            f"collections.Counter(), or project only the fields you need."
        )


def _nested_code(code: types.CodeType):
    """A code object and every code object defined inside it.

    Functions, comprehensions and generators the executed code defines are separate code objects,
    and a runaway loop is as likely to be inside one of those as in the module body.
    """
    yield code
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            yield from _nested_code(const)


def _stop(thread: threading.Thread, own_code: list, deadline_s: float) -> bool:
    """Try to stop a thread until it dies or the deadline passes. True if it died.

    Python cannot kill a thread, so both mechanisms here work by raising into it.
    """
    if _HAS_MONITORING:
        return _stop_by_monitoring(thread, own_code, deadline_s)
    return _stop_by_async_exc(thread, deadline_s)


def _stop_by_monitoring(thread: threading.Thread, own_code: list, deadline_s: float) -> bool:
    """Raise at the next line of the executed code, and nowhere else.

    Line events are armed on the executed code objects alone, so the exception can only surface
    between statements the model wrote. That matters more than it sounds: the async-exception
    fallback lands wherever the thread happens to be, which for analysis code is usually inside a
    Binary Ninja destructor, where Python discards it and the C free it was part of never runs.
    Arming happens only after a timeout, so ordinary execution carries no tracing cost.
    """
    mon = sys.monitoring
    tool_id = _acquire_tool_id(mon)
    if tool_id is None:
        return _stop_by_async_exc(thread, deadline_s)

    def interrupt(*_args):
        raise KeyboardInterrupt

    # LINE alone misses a loop whose body sits on the same line as its header - `while True:
    # i += 1` never reaches a new line - and JUMP alone would miss straight-line code. The
    # back-edge of every loop is a JUMP, so together they cover anything that can run forever.
    events = mon.events.LINE | mon.events.JUMP
    try:
        mon.register_callback(tool_id, mon.events.LINE, interrupt)
        mon.register_callback(tool_id, mon.events.JUMP, interrupt)
        for code in own_code:
            mon.set_local_events(tool_id, code, events)
        thread.join(timeout=deadline_s)
        return not thread.is_alive()
    finally:
        for code in own_code:
            try:
                mon.set_local_events(tool_id, code, 0)
            except ValueError:
                pass
        mon.register_callback(tool_id, mon.events.LINE, None)
        mon.register_callback(tool_id, mon.events.JUMP, None)
        mon.free_tool_id(tool_id)


def _acquire_tool_id(mon):
    """Claim a sys.monitoring tool id, or None if a debugger and profiler already hold them all."""
    for tool_id in range(mon.TOOL_ID_COUNT if hasattr(mon, "TOOL_ID_COUNT") else 6):
        try:
            mon.use_tool_id(tool_id, "binja-codemode-mcp")
        except ValueError:
            continue
        return tool_id
    return None


def _stop_by_async_exc(thread: threading.Thread, deadline_s: float) -> bool:
    """Fallback for interpreters without sys.monitoring: raise wherever the thread happens to be.

    Retried, because the exception is only raised at a bytecode boundary and a delivery that
    lands inside a destructor is discarded rather than propagated. Each discarded delivery is a
    destructor that did not finish, which is the cost this path carries and the monitoring one
    does not.
    """
    deadline = time.monotonic() + deadline_s
    while True:
        _interrupt(thread)
        thread.join(timeout=INTERRUPT_RETRY_S)
        if not thread.is_alive():
            return True
        if time.monotonic() >= deadline:
            return False


def _interrupt(thread: threading.Thread) -> int:
    """Raise KeyboardInterrupt inside a thread. Returns how many threads took it."""
    if thread.ident is None:
        return 0
    return ctypes.pythonapi.PyThreadState_SetAsyncExc(
        ctypes.c_ulong(thread.ident), ctypes.py_object(KeyboardInterrupt)
    )


def _split_trailing_expression(code: str) -> tuple[ast.Module, ast.Expression | None]:
    """Peel off a trailing bare expression so its value can come back without a print()."""
    module = ast.parse(code)
    if module.body and isinstance(module.body[-1], ast.Expr):
        return module, ast.Expression(module.body.pop().value)
    return module, None


def _render(printed: str, value) -> str:
    parts = []
    if printed.strip():
        parts.append(printed.rstrip())
    if value is not None:
        parts.append(json.dumps(value, indent=2, default=repr))
    return "\n".join(parts) if parts else "Success (nothing printed, no value)."
