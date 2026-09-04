"""Executes LLM-authored Python against the open binary.

The code runs in this process with Binary Ninja's own privileges. There is no sandbox: a
plugin that takes no dependencies has no way to build one, and `bv` alone reaches enough of the
process that restricting the rest would not buy anything. Binding to localhost and requiring the
API key are the boundary.
"""

import ast
import json
import math
import threading
import time
import traceback
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

    def validate(self, code: str) -> tuple[bool, str | None]:
        """Check that the code parses, so syntax errors are reported before anything runs."""
        try:
            compile(code, "<mcp>", "exec")
        except SyntaxError as e:
            return False, f"Syntax error: {e}"
        return True, None

    def execute(self, code: str) -> ExecutionResult:
        """Execute code and return whatever it printed, or the traceback it raised."""
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

        def run_code():
            try:
                # One dict for globals and locals: with separate ones, a function defined by the
                # code cannot see the names the code assigned, since its body resolves globals.
                exec(compile(body, "<mcp>", "exec"), namespace)
                if tail is not None:
                    result_holder["value"] = eval(compile(tail, "<mcp>", "eval"), namespace)
            except Exception as e:
                result_holder["error"] = f"{type(e).__name__}: {e}\n{traceback.format_exc()}"

        thread = threading.Thread(target=run_code)
        thread.start()
        thread.join(timeout=self.timeout)

        if thread.is_alive():
            elapsed = time.time() - start_time
            return ExecutionResult(
                success=False,
                output=self._truncate(printed.getvalue()),
                error=f"Execution timed out after {elapsed:.1f}s "
                f"(limit: {self.timeout}s). Any output before the timeout is shown above. "
                f"Narrow the work: use the batch methods, a smaller range, or fewer functions.",
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
