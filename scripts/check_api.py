"""Check that BinjaAPI documents itself well enough to generate from.

    PYTHONPATH=/path/to/binaryninja/python python3 scripts/check_api.py [--check]

Every public method needs a docstring summary, and one returning a dict needs a `Returns:` line
giving its shape, because both are rendered verbatim into what the LLM reads. Prints the tool
description's size so growth stays visible. With --check, also fails when the README's generated
API section is stale.
"""

import inspect
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT.parent))

from binja_codemode_mcp.plugin import tools  # noqa: E402
from binja_codemode_mcp.plugin.api import BinjaAPI  # noqa: E402
from generate_docs import README, render_markdown, splice  # noqa: E402

CHARS_PER_TOKEN = 4


def undocumented(surface):
    """Report every method whose docstring will render badly, as (name, complaint) pairs."""
    problems = []
    for name, method in surface.items():
        doc = inspect.getdoc(method) or ""
        lines = [line.strip() for line in doc.splitlines()]
        if not lines or not lines[0]:
            problems.append((name, "no docstring summary"))
            continue
        annotation = inspect.signature(method).return_annotation
        rendered = "" if annotation is inspect.Signature.empty else str(annotation)
        if "dict" in rendered and "Returns:" not in lines:
            problems.append((name, f"returns {rendered} but documents no shape"))
    return problems


def main():
    surface = tools.api_surface(BinjaAPI)
    problems = undocumented(surface)
    for name, complaint in problems:
        print(f"FAIL {name}: {complaint}")

    description = tools.build_tool_definition(surface)["description"]
    print(
        f"{len(surface)} methods | tool description {len(description):,} chars "
        f"(~{len(description) // CHARS_PER_TOKEN:,} tokens)"
    )

    stale = False
    if "--check" in sys.argv:
        text = README.read_text()
        stale = splice(text, render_markdown(surface)) != text
        if stale:
            print("FAIL README.md API section is stale; run scripts/generate_docs.py")

    if problems or stale:
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()
