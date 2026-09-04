"""Executes LLM-authored Python against the open binary.

The code runs in this process with Binary Ninja's own privileges. There is no sandbox: a
plugin that takes no dependencies has no way to build one, and `bv` alone reaches enough of the
process that restricting the rest would not buy anything. Binding to localhost and requiring the
API key are the boundary.
"""

import threading
import time
import traceback
from dataclasses import dataclass
from io import StringIO
from typing import TYPE_CHECKING

import binaryninja

if TYPE_CHECKING:
    from binaryninja import BinaryView

    from .api import BinjaAPI


@dataclass
class ExecutionResult:
    """Result of code execution."""

    success: bool
    output: str
    error: str | None
    timed_out: bool = False


class CodeExecutor:
    """Executes Python with the binja API, the BinaryView and the binaryninja module in scope."""

    def __init__(
        self,
        api: "BinjaAPI",
        bv: "BinaryView",
        max_output_bytes: int = 100_000,
        timeout: float = 30.0,
    ):
        self.api = api
        self.bv = bv
        self.max_output_bytes = max_output_bytes
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

        stdout_capture = StringIO()
        start_time = time.time()

        def progress_print(*args, **kwargs):
            elapsed = time.time() - start_time
            print(f"[{elapsed:.1f}s]", *args, file=stdout_capture, **kwargs)

        namespace = {
            "binja": self.api,
            "bv": self.bv,
            "bn": binaryninja,
            "print": progress_print,
        }

        result_holder = {"result": None, "error": None}

        def run_code():
            try:
                exec(code, namespace, {})
                result_holder["result"] = stdout_capture.getvalue()
            except Exception as e:
                result_holder["error"] = (
                    f"{type(e).__name__}: {e}\n{traceback.format_exc()}"
                )
                result_holder["result"] = stdout_capture.getvalue()

        thread = threading.Thread(target=run_code)
        thread.start()
        thread.join(timeout=self.timeout)

        if thread.is_alive():
            elapsed = time.time() - start_time
            return ExecutionResult(
                success=False,
                output=stdout_capture.getvalue(),
                error=f"Execution timed out after {elapsed:.1f}s\n"
                f"(Timeout limit: {self.timeout}s)\n"
                f"Partial output shown above.\n"
                f"Suggestion: Use batch processing or reduce iteration size.",
                timed_out=True,
            )

        if result_holder["error"]:
            return ExecutionResult(
                success=False,
                output=result_holder["result"] or "",
                error=result_holder["error"],
            )

        output = result_holder["result"] or ""
        if len(output) > self.max_output_bytes:
            output = output[: self.max_output_bytes] + "\n... (output truncated)"

        return ExecutionResult(success=True, output=output, error=None)
