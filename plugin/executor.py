"""Code validation and execution for Code Mode MCP."""

import ast
import re
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


# Common attribute mistakes and their correct alternatives
_API_SUGGESTIONS = {
    "strings": "list_strings(limit=None, min_length=4)",
    "functions": "list_functions(limit=None)",
    "imports": "list_imports()",
    "exports": "list_exports()",
    "segments": "list_segments()",
    "bv": "# binja IS the API - use binja.method() directly",
    "binary_view": "# binja IS the API - use binja.method() directly",
    "view": "# binja IS the API - use binja.method() directly",
    "file": "get_binary_status()",
    "filename": "get_binary_status()['filename']",
    "arch": "get_binary_status()['architecture']",
    "platform": "get_binary_status()['platform']",
    "start": "get_binary_status()['start']",
    "end": "get_binary_status()['end']",
    "entry_point": "get_binary_status()['entry_point']",
}


def _get_api_hint(attr: str) -> str:
    """Return helpful hint when an attribute is not found on BinjaAPI."""
    hint_lines = ["\n\n--- API HINT ---"]

    if attr in _API_SUGGESTIONS:
        hint_lines.append(f"Instead of 'binja.{attr}', use: binja.{_API_SUGGESTIONS[attr]}")
    else:
        hint_lines.append(f"'binja.{attr}' does not exist.")

    hint_lines.append("\nCommon methods:")
    hint_lines.append("  binja.list_strings()      - Get all strings")
    hint_lines.append("  binja.list_functions()    - Get all functions")
    hint_lines.append("  binja.decompile(func)     - Decompile function")
    hint_lines.append("  binja.get_xrefs_to(addr)  - Find cross-references")
    hint_lines.append("  binja.get_binary_status() - Get binary info")
    hint_lines.append("\nRead 'binja://api-reference' resource for full API.")

    return "\n".join(hint_lines)


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

        # Restricted globals
        restricted_globals = {
            "binja": self.api,
            "print": progress_print,
            # Safe built-ins
            "len": len,
            "range": range,
            "enumerate": enumerate,
            "zip": zip,
            "map": map,
            "filter": filter,
            "sorted": sorted,
            "reversed": reversed,
            "list": list,
            "dict": dict,
            "set": set,
            "tuple": tuple,
            "frozenset": frozenset,
            "str": str,
            "int": int,
            "float": float,
            "bool": bool,
            "bytes": bytes,
            "bytearray": bytearray,
            "hex": hex,
            "bin": bin,
            "oct": oct,
            "ord": ord,
            "chr": chr,
            "abs": abs,
            "min": min,
            "max": max,
            "sum": sum,
            "round": round,
            "pow": pow,
            "divmod": divmod,
            "any": any,
            "all": all,
            "isinstance": isinstance,
            "issubclass": issubclass,
            "hasattr": hasattr,
            "getattr": getattr,
            "setattr": setattr,
            "repr": repr,
            "format": format,
            "slice": slice,
            "iter": iter,
            "next": next,
            "None": None,
            "True": True,
            "False": False,
            # Exceptions
            "Exception": Exception,
            "ValueError": ValueError,
            "TypeError": TypeError,
            "KeyError": KeyError,
            "IndexError": IndexError,
            "AttributeError": AttributeError,
            "RuntimeError": RuntimeError,
        }

        # Execute with timeout
        result_holder = {"result": None, "error": None}

        def run_code():
            try:
                # Use same dict for globals and locals to fix scoping issues for nested functions
                exec(code, restricted_globals, restricted_globals)
                result_holder["result"] = stdout_capture.getvalue()
            except AttributeError as e:
                err_msg = str(e)
                hint = ""
                # Check if the error is about BinjaAPI having no attribute
                if "BinjaAPI" in err_msg and "has no attribute" in err_msg:
                    # Extract attribute name: 'BinjaAPI' object has no attribute 'X'
                    match = re.search(r"has no attribute '(\w+)'", err_msg)
                    attr = match.group(1) if match else ""
                    hint = _get_api_hint(attr)
                result_holder["error"] = (
                    f"{type(e).__name__}: {e}\n{traceback.format_exc()}{hint}"
                )
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
