"""Code validation and execution for Code Mode MCP."""

import ast
import builtins
import threading
import time
import traceback
from dataclasses import dataclass
from io import StringIO
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .api import BinjaAPI


# Forbidden modules and attributes
_FORBIDDEN_MODULES = frozenset(
    {
        "os",
        "subprocess",
        "socket",
        "requests",
        "urllib",
        "http",
        "importlib",
        "sys",
        "builtins",
        "__builtins__",
        "pickle",
        "shelve",
        "marshal",
        "ctypes",
        "multiprocessing",
        "threading",
        "code",
        "codeop",
        "shutil",
        "pathlib",
        "glob",
    }
)

_FORBIDDEN_ATTRIBUTES = frozenset(
    {
        "__import__",
        "eval",
        "exec",
        "compile",
        "open",
        "__subclasses__",
        "__bases__",
        "__globals__",
        "__code__",
        "__builtins__",
        "__loader__",
        "__spec__",
    }
)


class CodeValidator(ast.NodeVisitor):
    """AST visitor that checks for forbidden operations."""

    def __init__(self):
        self.errors: list[str] = []

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            module = alias.name.split(".")[0]
            if module in _FORBIDDEN_MODULES:
                self.errors.append(f"Forbidden import: {alias.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            module = node.module.split(".")[0]
            if module in _FORBIDDEN_MODULES:
                self.errors.append(f"Forbidden import: {node.module}")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        if node.attr in _FORBIDDEN_ATTRIBUTES:
            self.errors.append(f"Forbidden attribute access: {node.attr}")
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        if node.id in _FORBIDDEN_ATTRIBUTES:
            self.errors.append(f"Forbidden name: {node.id}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name):
            if node.func.id in _FORBIDDEN_ATTRIBUTES:
                self.errors.append(f"Forbidden call: {node.func.id}()")
        self.generic_visit(node)


@dataclass
class ExecutionResult:
    """Result of code execution."""

    success: bool
    output: str
    error: str | None
    timed_out: bool = False


class CodeExecutor:
    """Validates and executes Python code in a restricted environment."""

    def __init__(
        self,
        api: "BinjaAPI",
        max_output_bytes: int = 100_000,
        timeout: float = 30.0,
    ):
        self.api = api
        self.max_output_bytes = max_output_bytes
        self.timeout = timeout

    def validate(self, code: str) -> tuple[bool, str | None]:
        """Validate code via AST analysis."""
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return False, f"Syntax error: {e}"

        validator = CodeValidator()
        validator.visit(tree)

        if validator.errors:
            return False, "; ".join(validator.errors)

        return True, None

    def execute(self, code: str) -> ExecutionResult:
        """Execute code with binja API in scope."""

        # Validate first
        is_valid, error = self.validate(code)
        if not is_valid:
            return ExecutionResult(success=False, output="", error=error)

        # Capture stdout
        stdout_capture = StringIO()

        # Track execution progress
        start_time = time.time()

        def progress_print(*args, **kwargs):
            """Enhanced print that tracks execution progress."""
            elapsed = time.time() - start_time
            print(f"[{elapsed:.1f}s]", *args, file=stdout_capture, **kwargs)

        # Restricted globals. We build a single namespace (no separate locals) so
        # that top-level assignments and imports are visible to nested scopes -
        # comprehensions, generator expressions, and helper `def`s. The old
        # `exec(code, globals, {})` form landed top-level names in an isolated
        # locals dict that nested scopes could not see, so every comprehension or
        # helper referencing a top-level variable raised NameError.
        #
        # `__builtins__` is set EXPLICITLY to a curated dict. If it were omitted,
        # `exec` would silently inject the FULL builtins (including `open`,
        # `eval`, `exec`, `__import__`) - which is what happened before, making
        # the sandbox looser than it appeared. The AST validator blocks direct
        # calls to the dangerous names; restricting `__builtins__` closes the
        # reach-via-dict gap too.
        safe_builtin_names = (
            "len", "range", "enumerate", "zip", "map", "filter", "sorted",
            "reversed", "list", "dict", "set", "tuple", "frozenset", "str",
            "int", "float", "bool", "bytes", "bytearray", "hex", "bin", "oct",
            "ord", "chr", "abs", "min", "max", "sum", "round", "pow", "divmod",
            "any", "all", "isinstance", "issubclass", "hasattr", "getattr",
            "setattr", "delattr", "repr", "format", "slice", "iter", "next",
            "type", "dir", "callable", "hash", "id", "ascii", "object",
            "super", "memoryview", "complex", "staticmethod", "classmethod",
            "property",
            # Exceptions commonly caught by real analysis snippets
            "Exception", "ValueError", "TypeError", "KeyError", "IndexError",
            "AttributeError", "RuntimeError", "StopIteration", "NameError",
            "NotImplementedError",
        )
        safe_builtins = {name: getattr(builtins, name) for name in safe_builtin_names}
        # `import` statements need __import__; `class` statements need
        # __build_class__. Neither is reachable as a direct call/name - the AST
        # validator blocks `__import__` (in _FORBIDDEN_ATTRIBUTES) and direct
        # forbidden-module imports, so `import os` / `__import__("os")` stay
        # blocked while legitimate `import struct` works, including inside helpers.
        #
        # Resolve the TRUE original import function, not whatever
        # builtins.__import__ currently is. PySide6's feature system
        # (imported transitively via binaryninjaui -> shiboken6) monkeypatches
        # builtins.__import__ with its own __feature_import__ hook and stashes
        # the real one as builtins.__orig_import__. If we copied the hook into
        # the sandbox, every `import` would route through the hook, which itself
        # calls __orig_import__ - and if we'd set both to the hook that's
        # instant infinite recursion (RecursionError on `import binaryninjaui`).
        # Using the unhooked original bypasses the feature hook for sandbox
        # code (which has no need for PySide feature selection) and terminates.
        _real_import = getattr(builtins, "__orig_import__", None) or builtins.__import__
        safe_builtins["__import__"] = _real_import
        safe_builtins["__build_class__"] = builtins.__build_class__
        safe_builtins["__name__"] = "__main__"
        # `__orig_import__` is the name shiboken6 looks up on the active frame's
        # `__builtins__` during its module init (PyDict_GetItemString(builtins,
        # "__orig_import__")). On a miss it calls Py_FatalError ->
        # `Fatal Python error: libshiboken: builtins has no "__orig_import__"
        # function`, which aborts the whole Binary Ninja process (SIGABRT, exit
        # 134). Because our curated dict replaced `__builtins__`, a sandboxed
        # `import binaryninjaui` (e.g. a pasted view-enumerator snippet) used to
        # take the container down with no recovery short of a full restart.
        # Mirror the same unhooked original here so the lookup resolves. This
        # opens no new path: it is the same vetted import function, and the AST
        # validator still blocks forbidden module names at the `import`
        # statement level and `__import__` as a direct call/name.
        safe_builtins["__orig_import__"] = _real_import

        restricted_globals = {
            "__builtins__": safe_builtins,
            "binja": self.api,
            "print": progress_print,
            "None": None,
            "True": True,
            "False": False,
        }

        # Execute with timeout
        result_holder = {"result": None, "error": None}

        def run_code():
            try:
                exec(code, restricted_globals)
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
            # Get partial output before timeout
            partial_output = stdout_capture.getvalue()
            elapsed = time.time() - start_time

            return ExecutionResult(
                success=False,
                output=partial_output,
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
