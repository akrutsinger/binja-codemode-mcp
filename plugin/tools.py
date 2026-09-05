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
- Five names are already in scope: `binja` for analysing the binary, `workspace` for files that
  outlive a call, `skills` for saved code, `bv` for the raw BinaryView and `bn` for the
  binaryninja module. Do not import or construct them.
- The methods above are deliberately few. They are the things that are awkward to render, easy
  to get wrong, or impossible from inside one call - not a wrapper around Binary Ninja. `bv` and
  `bn` are the full API, and writing Python against them is the normal way to work here, not a
  fallback: to list functions, iterate `bv.functions`; to find bytes, call `bv.find_next_data`;
  to read strings, read `bv.strings`.
- binja.search_api(query) finds a member and binja.describe(name) gives its real signature and
  docstring, read from the Binary Ninja that is actually running. describe() takes a class name
  too, so a constructor's arguments and an enum's members are each one call away. Do not guess
  at API names; look them up, then call them.
- This is ordinary CPython inside Binary Ninja, so the whole standard library is importable.
- Both what you print() and the value of the last expression come back, so a trailing bare
  expression needs no print().
- Ending on a bare collection dumps all of it. Results are truncated at ~6,000 tokens, so
  aggregate in code and print the fields you need rather than whole rows.
- Each call runs in a fresh namespace; nothing persists between calls. workspace.write() and
  workspace.read() carry results forward, and skills.save() stores code worth reusing. Run a
  saved one with exec(skills.get_code(name)) at the top level, which defines its names here.
- Workspace files belong to this binary alone; another binary has its own and cannot see these.
  Skills are shared across every binary, so save code that generalises and write findings about
  this one to the workspace.
- If the method list above did not reach you intact, call binja.list_methods() for the same
  signatures from inside the execution namespace.

USING THE API
- Every `func` argument takes a function name, an address, or a Function itself, so
  binja.decompile("main"), binja.decompile(0x401000) and binja.decompile(binja.function("main"))
  are the same call.
- Addresses are ints. Write them as hex literals.
- Many methods return None when a function or address does not resolve. Check before using.
- binja.decompile() renders the body, whose declarations carry each variable's type already. For
  the whole variable set including ones the body never names, read binja.function(f).vars.
- binja.function(name_or_addr) hands back the real Function object, and `bv` reaches the rest:
  assign to its attributes directly, as in binja.function("main").name = "parse_header".
- Assigning a function's type only queues reanalysis, so `binja.function("f").type = ...` reads
  back as the old signature until `bv.update_analysis_and_wait()` runs. Variable types, renames
  and comments apply immediately; function signatures do not.
- Patching is Binary Ninja's own API. bv.write(addr, data) writes bytes, bv.convert_to_nop(addr)
  NOPs one instruction correctly for the architecture, and bv.arch.assemble(asm, addr) returns
  the bytes to write. Read bv.read(addr, n) first if you want to be able to put it back.
- binja.checkpoint(name) before a batch of renames, retypes or patches, and binja.rollback(name)
  to undo the whole batch as a unit. Rollback covers changes made through `bv` too. Checkpoints
  are for spanning calls, which is the one thing a `with` block cannot do.
- For atomicity inside a single call, `with bv.undoable_transaction():` groups everything in the
  block into one undo entry and reverts all of it if an exception escapes. Prefer it for a risky
  batch. The rest of the undo API is Binary Ninja's own: search_api("undo") lists it.
"""

_EXAMPLE = """
EXAMPLE
# The header above already names the binary, so start from the functions. Filter in Python;
# there is no round trip to save by asking for a narrower list.
for f in bv.functions:
    if "auth" in f.name.lower() and f.total_bytes > 64:
        print(hex(f.start), f.name, f.total_bytes)

# Read the code, then act on what it says.
print(binja.decompile("check_license"))

# binja.function() hands back the real Function object, and assigning to it is a normal
# mutation that a checkpoint can roll back.
f = binja.function("check_license")
print(f.name, len(f.basic_blocks), f.total_bytes)
f.name = "verify_license"

# Look names up rather than guessing. A wrong enum member is a silent empty result.
print(binja.describe("SymbolType")["members"])
for sym in bv.get_symbols_of_type(bn.SymbolType.ImportAddressSymbol)[:5]:
    print(sym.name, hex(sym.address))

# The last expression comes back on its own; no print needed.
[line for f in bv.functions if f.hlil for line in str(f.hlil).splitlines() if "strcpy" in line]
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

_OWN_MODULE = re.compile(re.escape(__name__.split(".")[0]) + r"(?:\.\w+)*\.")
_SECTION_DIVIDER = re.compile(r"^    # =+$")
_COMMENT = re.compile(r"^    # (.+)$")
_METHOD_DEF = re.compile(r"^    def (\w+)\(")


def build_tool_definition(namespaces):
    """Build the tools/list entry describing every method the LLM can call.

    `namespaces` maps the name each object is bound to in the execution namespace to the object
    itself. The executor builds its globals from the same mapping, so what the model is told it
    can call and what it can actually call cannot drift.
    """
    return {
        "name": TOOL_NAME,
        "description": (
            f"{build_context_header(namespaces)}"
            f"{_HEADER}{build_api_reference(namespaces)}\n{_GUIDE}{_EXAMPLE}"
        ),
        "inputSchema": _INPUT_SCHEMA,
    }


def build_context_header(namespaces):
    """Describe the binary and session the code will run against.

    Empty when the objects are classes rather than instances, so the docs tooling can render the
    reference without a BinaryView to ask.
    """
    binja = namespaces["binja"]
    if inspect.isclass(binja):
        return ""

    bv = binja.bv
    skills = namespaces["skills"].list()
    checkpoints = binja.list_checkpoints()
    lines = [
        f"Binary: {bv.file.filename}",
        (
            f"Arch: {bv.arch.name if bv.arch else None} | "
            f"Platform: {bv.platform.name if bv.platform else None} | "
            f"Functions: {len(bv.functions)} | "
            f"Range: {bv.start:#x}-{bv.end:#x}"
        ),
        (
            f"Workspace: {len(namespaces['workspace'].list())} file(s) | "
            f"Skills: {len(skills)} available"
        ),
    ]
    if skills:
        lines.append("Saved skills: " + ", ".join(skill["name"] for skill in skills))
    if checkpoints:
        lines.append("Checkpoints: " + ", ".join(cp["name"] for cp in checkpoints))
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


def build_api_reference(namespaces):
    """Render each namespace as grouped signature lines, prefixed with the name it is bound to."""
    lines = []
    for prefix, owner in namespaces.items():
        surface = api_surface(owner)
        for section, names in group_by_section(owner, surface).items():
            lines.append(f"\n# {section}")
            lines.extend(f"- {prefix}.{name}{describe_method(surface[name])}" for name in names)
    return "\n".join(lines).lstrip("\n")


def describe_method(method):
    """Render one method as its signature, summary and return shape."""
    return f"{method_signature(method)}: {method_summary(method)}"


def method_summary(method):
    """The docstring's first line, plus the return shape when it documents one."""
    doc = [line.strip() for line in (inspect.getdoc(method) or "").splitlines()]
    summary = doc[0] if doc and doc[0] else "(undocumented)"
    shape = doc[doc.index("Returns:") + 1] if "Returns:" in doc else ""
    return f"{summary} Returns {shape}" if shape else summary


def group_by_section(owner, surface):
    """Map each section comment in the owner's source to the methods declared under it.

    Grouping is read back out of the source rather than listed here, so a method added under an
    existing section is grouped without touching this module. A class with no section dividers
    gets one section named from its own docstring.
    """
    cls = owner if inspect.isclass(owner) else type(owner)
    sections = {}
    current = _default_section(cls)
    after_divider = False
    for line in inspect.getsource(cls).splitlines():
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


def _default_section(cls):
    """The section header for a class with no dividers: its own docstring summary."""
    doc = [line.strip() for line in (inspect.getdoc(cls) or "").splitlines()]
    return doc[0].rstrip(".") if doc and doc[0] else cls.__name__


def method_signature(method):
    """Render a call signature, dropping `self` when the method is unbound."""
    signature = inspect.signature(method)
    parameters = list(signature.parameters.values())
    if parameters and parameters[0].name == "self":
        parameters = parameters[1:]
    rendered = ", ".join(_parameter(parameter) for parameter in parameters)
    annotation = signature.return_annotation
    returns = "" if annotation is inspect.Signature.empty else f" -> {_name(annotation)}"
    return f"({rendered}){returns}"


def _parameter(parameter):
    """One parameter, as `name: type = default`.

    Rendered here rather than by str(parameter) so the annotation goes through _name(): a quoted
    annotation is the only way to name a Binary Ninja type without inspect rendering its whole
    module path, and str() would show the quotes.
    """
    rendered = parameter.name
    if parameter.annotation is not inspect.Parameter.empty:
        rendered += f": {_name(parameter.annotation)}"
    if parameter.default is not inspect.Parameter.empty:
        rendered += f" = {parameter.default!r}"
    return rendered


def _name(annotation):
    rendered = annotation if isinstance(annotation, str) else inspect.formatannotation(annotation)
    # The plugin's own classes render fully qualified, which is a module path the model has no
    # use for: "Skill" says what "binja_codemode_mcp.plugin.workspace.Skill" says.
    return _OWN_MODULE.sub("", rendered).replace("typing.", "")
