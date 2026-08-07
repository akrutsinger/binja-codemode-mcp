"""Regression tests for the Code Mode MCP ``execute`` sandbox.

These run under plain ``python3`` with NO Binary Ninja installed: the executor
module's only runtime imports are the standard library, and its ``BinjaAPI``
dependency is a ``TYPE_CHECKING``-only import, so we load it by file path and
hand it a dummy API object.

Two things must never regress:

1. **Scoping** - top-level variables, comprehensions, generator expressions,
   helper ``def``s, ``import`` inside helpers, and ``class`` statements all
   work. (Previously ``exec(code, globals, {})`` stranded top-level names in an
   isolated locals dict, so every one of these raised ``NameError``.)
2. **Security** - ``open``, ``eval``, ``exec``, direct ``__import__``, forbidden
   module imports, and ``__subclasses__``/``__bases__`` escapes are blocked at
   validation. (Previously the sandbox ALSO leaked the full ``__builtins__`` via
   ``exec`` auto-injection; the curated ``__builtins__`` must keep them out.)

Run: ``python3 -m pytest tests/test_executor_sandbox.py`` or
``python3 tests/test_executor_sandbox.py``.
"""

import importlib.util
import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_executor():
    """Load plugin/executor.py without importing the binaryninja-dependent package."""
    if "plugin" not in sys.modules:
        pkg = types.ModuleType("plugin")
        pkg.__path__ = [str(REPO_ROOT / "plugin")]
        sys.modules["plugin"] = pkg
    if "plugin.api" not in sys.modules:
        api = types.ModuleType("plugin.api")

        class BinjaAPI:  # pragma: no cover - only needed for type checking
            pass

        api.BinjaAPI = BinjaAPI
        sys.modules["plugin.api"] = api

    mod_path = REPO_ROOT / "plugin" / "executor.py"
    spec = importlib.util.spec_from_file_location("plugin.executor", mod_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["plugin.executor"] = module
    spec.loader.exec_module(module)
    return module


class _FakeAPI:
    """Stand-in for BinjaAPI - the executor never calls it for these tests."""


def _make_executor():
    module = _load_executor()
    return module.CodeExecutor(_FakeAPI(), max_output_bytes=100_000, timeout=5.0)


# ---------------------------------------------------------------------------
# Scoping: everything below used to raise NameError before the fix.
# ---------------------------------------------------------------------------


def test_helper_references_top_level_variable():
    ex = _make_executor()
    r = ex.execute("x = 5\ndef h():\n    return x\nprint(h())")
    assert r.success, r.error
    assert "5" in r.output


def test_comprehension_references_top_level_variable():
    ex = _make_executor()
    r = ex.execute("x = 5\nprint([i for i in range(x)])")
    assert r.success, r.error
    assert "[0, 1, 2, 3, 4]" in r.output


def test_generator_expression_references_top_level_variable():
    ex = _make_executor()
    r = ex.execute("x = 4\nprint(sum(i for i in range(x)))")
    assert r.success, r.error
    assert "6" in r.output


def test_import_inside_helper():
    ex = _make_executor()
    r = ex.execute(
        "import struct\ndef h():\n    return struct.pack('<I', 1).hex()\nprint(h())"
    )
    assert r.success, r.error
    assert "01000000" in r.output


def test_class_statement():
    ex = _make_executor()
    r = ex.execute("class C:\n    def __init__(self, v):\n        self.v = v\nprint(C(7).v)")
    assert r.success, r.error
    assert "7" in r.output


def test_nested_helper_closure():
    ex = _make_executor()
    r = ex.execute(
        "total = 0\n"
        "def outer(n):\n"
        "    def inner(i):\n"
        "        return i * 2\n"
        "    return sum(inner(i) for i in range(n))\n"
        "total = outer(3)\n"
        "print(total)"
    )
    assert r.success, r.error
    assert "6" in r.output  # 0*2 + 1*2 + 2*2


# ---------------------------------------------------------------------------
# Security: these must be rejected at validation, not executed.
# ---------------------------------------------------------------------------


def test_open_blocked():
    ex = _make_executor()
    r = ex.execute("f = open('/etc/passwd')\nprint(f.read(5))")
    assert not r.success
    assert "open" in r.error


def test_eval_blocked():
    ex = _make_executor()
    r = ex.execute("eval('1+1')")
    assert not r.success
    assert "eval" in r.error


def test_exec_blocked():
    ex = _make_executor()
    r = ex.execute("exec('print(1)')")
    assert not r.success
    assert "exec" in r.error


def test_direct_dunder_import_blocked():
    ex = _make_executor()
    r = ex.execute("os = __import__('os')\nprint(os.getcwd())")
    assert not r.success
    assert "__import__" in r.error


def test_forbidden_module_import_blocked():
    ex = _make_executor()
    r = ex.execute("import os\nprint(os.getcwd())")
    assert not r.success
    assert "os" in r.error


def test_subclasses_escape_blocked():
    ex = _make_executor()
    r = ex.execute("print([].__class__.__bases__[0].__subclasses__())")
    assert not r.success
    assert "__subclasses__" in r.error or "__bases__" in r.error


def test_builtins_not_leaked():
    """The curated __builtins__ must NOT contain the dangerous builtins, even
    though `exec` would auto-inject the FULL builtins if __builtins__ were
    absent (which is the pre-fix behavior this replaces).

    We can't reference ``__builtins__`` by name in sandbox code (the AST
    validator blocks it), so prove it behaviorally: ``globals``/``vars`` are
    NOT in the curated set and are NOT in _FORBIDDEN_ATTRIBUTES, so they would
    resolve only if the full builtins leaked. They must NameError; ``type``
    (in the curated set) must work. ``open``/``eval``/``exec`` are covered by
    the AST-blocked tests above, but absence here is the belt-and-braces check
    that the curated dict - not the auto-injected one - is in effect.
    """
    ex = _make_executor()
    r = ex.execute("print(type(5).__name__)")  # curated -> works
    assert r.success, r.error
    assert "int" in r.output

    for escape in ("globals", "vars", "input", "breakpoint"):
        r = ex.execute(f"print({escape}())")
        assert not r.success, f"{escape} should be absent from the curated builtins"
        assert "NameError" in r.error


# ---------------------------------------------------------------------------
# Sanity: whitelisted use still works.
# ---------------------------------------------------------------------------


def test_whitelisted_builtins_work():
    ex = _make_executor()
    r = ex.execute("print(hex(255), ord('A'), sum([1, 2, 3]))")
    assert r.success, r.error
    assert "0xff 65 6" in r.output


def test_stop_iteration_catchable():
    ex = _make_executor()
    r = ex.execute("try:\n    raise StopIteration\nexcept StopIteration:\n    print('caught')")
    assert r.success, r.error
    assert "caught" in r.output


if __name__ == "__main__":
    # Minimal runner for environments without pytest.
    import traceback

    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
            passed += 1
        except Exception:
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
