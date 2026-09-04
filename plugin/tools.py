"""The execute tool definition.

The method list is generated from BinjaAPI by introspection, so adding a method there is all it
takes to advertise it to the LLM. Method names, signatures and summaries cannot drift from the
code that implements them.
"""

import inspect
import re

TOOL_NAME = "execute"

# The method list comes first on purpose. Clients that truncate this description clip the tail, and
# losing the prose is survivable in a way that losing the API surface is not.
_HEADER = """CODE MODE: execute Python against the binary open in Binary Ninja.

AVAILABLE METHODS
"""

_GUIDE = """
ENVIRONMENT
- The methods above hang off `binja`, which is already in scope. Do not import or construct it.
- Both what you print() and the value of the last expression come back, so a trailing bare
  expression needs no print().
- Ending on a bare collection dumps all of it. Results are truncated at ~6,000 tokens, so
  aggregate in code and print the fields you need rather than whole rows.
- Each call runs in a fresh namespace; nothing persists between calls. binja.write_file() and
  binja.read_file() carry results forward, and binja.save_skill() stores code worth reusing.
- If the method list above did not reach you intact, call binja.list_methods() for the same
  signatures from inside the execution namespace.

USING THE API
- Every `func` argument takes either a function name or an address, so binja.decompile("main")
  and binja.decompile(0x401000) are the same call.
- Addresses are ints. Write them as hex literals.
- Many methods return None when a function or address does not resolve. Check before using.
- Prefer the batch methods over a Python loop that calls a single-item method N times:
  analyze_functions_batch(), bulk_rename() and batch_set_types() each cost one pass.
- Mutations are tracked. Take a checkpoint before a batch of renames, retypes or patches so the
  whole batch can be rolled back as a unit.
"""

_EXAMPLE = """
EXAMPLE
# Get your bearings before analysing anything.
print(binja.get_binary_status())

# Narrow server-side with the method's own filters rather than listing everything and filtering
# in Python.
for f in binja.list_functions(name_contains="auth", min_size=64):
    print(hex(f["address"]), f["name"], f["size"])

# Read the code, then act on what it says.
print(binja.decompile("check_license"))

# The last expression comes back on its own; no print needed.
[m["function"] for m in binja.search_decompiled("strcpy")]
"""

_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "code": {
            "type": "string",
            "description": "Python code calling the binja API methods.",
        },
        "description": {
            "type": "string",
            "description": "What this code does.",
        },
    },
    "required": ["code"],
}

_SECTION_DIVIDER = re.compile(r"^    # =+$")
_COMMENT = re.compile(r"^    # (.+)$")
_METHOD_DEF = re.compile(r"^    def (\w+)\(")


_CHECKPOINT_TOOL = {
    "name": "checkpoint",
    "description": (
        "Name the current state of the database so a later rollback can return to it. Take one "
        "before any batch of renames, retypes or patches."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Checkpoint name."},
        },
        "required": ["name"],
    },
}

_ROLLBACK_TOOL = {
    "name": "rollback",
    "description": (
        "Undo every change made since the named checkpoint, discarding any checkpoints taken "
        "after it."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Checkpoint to return to."},
        },
        "required": ["name"],
    },
}


def build_tool_definitions(surface, state_summary=""):
    """Build every tools/list entry the bridge serves."""
    return [
        build_tool_definition(surface, state_summary),
        _CHECKPOINT_TOOL,
        _ROLLBACK_TOOL,
    ]


def build_tool_definition(surface, state_summary=""):
    """Build the tools/list entry describing every method the LLM can call."""
    return {
        "name": TOOL_NAME,
        "description": (
            f"{build_context_header(surface, state_summary)}"
            f"{_HEADER}{build_api_reference(surface)}\n{_GUIDE}{_EXAMPLE}"
        ),
        "inputSchema": _INPUT_SCHEMA,
    }


def build_context_header(surface, state_summary=""):
    """Describe the binary and session the code will run against.

    Empty for an unbound surface, so the docs tooling can render the reference without a
    BinaryView to ask.
    """
    if not _is_bound(surface):
        return ""

    status = surface["get_binary_status"]()
    skills = surface["list_skills"]()
    lines = [
        f"Binary: {status['filename']}",
        f"Arch: {status['architecture']} | Platform: {status['platform']} | "
        f"Functions: {status['function_count']} | "
        f"Range: {status['start']:#x}-{status['end']:#x}",
        f"Workspace: {len(surface['list_files']())} file(s) | "
        f"Skills: {len(skills)} available",
    ]
    if skills:
        lines.append("Saved skills: " + ", ".join(skill["name"] for skill in skills))
    if state_summary:
        lines.append(state_summary)
    return "\n".join(lines) + "\n\n"


def api_surface(api):
    """Map name -> method for every public method the LLM can call.

    Accepts an instance or the class itself, so the docs can be rendered without a BinaryView.
    """
    return {
        name: member
        for name, member in inspect.getmembers(api, inspect.isroutine)
        if not name.startswith("_")
    }


def build_api_reference(surface):
    """Render a name -> method mapping as grouped signature lines with summaries."""
    lines = []
    for section, names in group_by_section(surface).items():
        lines.append(f"\n# {section}")
        lines.extend(f"- binja.{name}{describe_method(surface[name])}" for name in names)
    return "\n".join(lines).lstrip("\n")


def describe_method(method):
    """Render one method as its signature, summary and return shape."""
    doc = [line.strip() for line in (inspect.getdoc(method) or "").splitlines()]
    summary = doc[0] if doc and doc[0] else "(undocumented)"
    shape = doc[doc.index("Returns:") + 1] if "Returns:" in doc else ""
    suffix = f" Returns {shape}" if shape else ""
    return f"{_signature(method)}: {summary}{suffix}"


def group_by_section(surface):
    """Map each section comment in the API source to the methods declared under it.

    Grouping is read back out of the source rather than listed here, so a method added under an
    existing section is grouped without touching this module.
    """
    sections = {}
    current = "API"
    after_divider = False
    for line in _api_source(surface).splitlines():
        comment = _COMMENT.match(line)
        method = _METHOD_DEF.match(line)
        if _SECTION_DIVIDER.match(line):
            after_divider = True
        elif after_divider and comment:
            current = comment.group(1).strip()
            after_divider = False
        elif method and method.group(1) in surface:
            sections.setdefault(current, []).append(method.group(1))
        else:
            after_divider = False
    return sections


def _is_bound(surface):
    return all(hasattr(method, "__self__") for method in surface.values())


def _api_source(surface):
    owner = next((m.__self__ for m in surface.values() if hasattr(m, "__self__")), None)
    return inspect.getsource(type(owner) if owner else _declaring_class(surface))


def _declaring_class(surface):
    method = next(iter(surface.values()))
    module = inspect.getmodule(method)
    return getattr(module, method.__qualname__.split(".")[0])


def _signature(method):
    """Render a call signature, dropping `self` when the method is unbound."""
    parameters = list(inspect.signature(method).parameters.values())
    if parameters and parameters[0].name == "self":
        parameters = parameters[1:]
    rendered = ", ".join(str(parameter) for parameter in parameters)
    annotation = inspect.signature(method).return_annotation
    returns = "" if annotation is inspect.Signature.empty else f" -> {_name(annotation)}"
    return f"({rendered}){returns}"


def _name(annotation):
    rendered = (
        annotation if isinstance(annotation, str) else inspect.formatannotation(annotation)
    )
    return rendered.replace("typing.", "")
