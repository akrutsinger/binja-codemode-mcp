"""Binary Ninja API wrapper for LLM code execution."""

import re
from typing import TYPE_CHECKING

from binaryninja import Function

if TYPE_CHECKING:
    from binaryninja import BinaryView


class BinjaAPIError(Exception):
    """Custom exception for API errors with detailed messages."""


class BinjaAPI:
    """
    Binary Ninja API wrapper for LLM code execution.
    All methods operate on the current BinaryView.
    """

    def __init__(self, bv: "BinaryView"):
        self._bv = bv
        # name -> how many committed transactions deep the database was. Deliberately in memory
        # only: the undo stack outlives the session in the .bndb, so a depth saved to disk could
        # be meaningfully wrong on reload, while one held here can only be from this session.
        self._checkpoints: dict[str, int] = {}

    @property
    def bv(self):
        """The BinaryView these methods operate on.

        For the tool description's context header, which has a binary to describe but only the
        namespace mapping to reach it through. Not part of the model's surface: api_surface()
        renders routines, and the executor binds `bv` into the namespace itself.
        """
        return self._bv

    # =========================================================================
    # Query Operations (read-only)
    # =========================================================================

    def decompile(self, func: "Function | str | int", il_level: str = "hlil") -> str | None:
        """Decompile function to C-like pseudocode.

        Args:
            func: Function name or address
            il_level: IL level - "hlil" (high), "mlil" (medium), or "llil" (low)
        """
        # Validate il_level parameter
        valid_levels = ["hlil", "mlil", "llil"]
        if il_level not in valid_levels:
            raise ValueError(f"il_level must be one of {valid_levels}, got '{il_level}'")

        f = self._resolve_function(func)
        if not f:
            return None

        # No variable listing: HLIL already declares each variable inline with its type at first
        # assignment, so the block repeated what the body says, and most of what it named was
        # compiler temporaries. It was 41% of this method's output. binja.function(f).vars still
        # has them for the rare case that wants the whole set.
        lines = [f"// {f.name} @ {f.start:#x}", str(f.type), "{"]

        # Handle different IL levels with their specific APIs
        if il_level == "mlil" and f.mlil:
            for instr in f.mlil.instructions:
                lines.append(f"    {instr}")
        elif il_level == "llil" and f.llil:
            for instr in f.llil.instructions:
                lines.append(f"    {instr}")
        elif il_level == "hlil" and f.hlil:
            for line in f.hlil.root.lines:
                lines.append(f"    {line}")
        else:
            # Requested IL not available
            return None

        lines.append("}")

        result = "\n".join(lines)

        return result

    def get_assembly(self, func: "Function | str | int") -> str | None:
        """Get disassembly for function."""
        f = self._resolve_function(func)
        if not f:
            return None

        lines = []
        for block in f.basic_blocks:
            for instr in block.disassembly_text:
                text = "".join(t.text for t in instr.tokens)
                lines.append(f"{instr.address:#x}: {text}")
        return "\n".join(lines)

    def get_all_xrefs(
        self, addr: int, include_data: bool = True, include_code: bool = True
    ) -> dict:
        """Get all cross-references (both code and data) to/from one address, not a whole function.

        Asked for a function's entry point it reports what jumps or calls there, and `xrefs_from`
        covers that one address rather than the whole body, so it is usually empty. For what a
        function calls, read `binja.function(f).callees`.

        Args:
            addr: Address to analyze
            include_data: Include data references (default: True)
            include_code: Include code references (default: True)

        Returns:
            {address, xrefs_to: [{type, from_address, from_function}], xrefs_from: [{type, to_address, to_function}]}
        """
        xrefs_to = []
        xrefs_from = []

        if include_code:
            # get_code_refs() points inward and get_code_refs_from() outward, the same split the
            # data refs get below. Without the second, a call site reported nothing leaving it and
            # `include_code` reached only half of what it names.
            for ref in self._bv.get_code_refs(addr):
                caller = self._bv.get_functions_containing(ref.address)
                xrefs_to.append(
                    {
                        "type": "code",
                        "from_address": ref.address,
                        "from_function": caller[0].name if caller else None,
                    }
                )
            for ref in self._bv.get_code_refs_from(addr):
                target = self._bv.get_functions_containing(ref)
                xrefs_from.append(
                    {
                        "type": "code",
                        "to_address": ref,
                        "to_function": target[0].name if target else None,
                    }
                )

        if include_data:
            for ref in self._bv.get_data_refs(addr):
                source = self._bv.get_functions_containing(ref)
                xrefs_to.append(
                    {
                        "type": "data",
                        "from_address": ref,
                        "from_function": source[0].name if source else None,
                    }
                )
            for ref in self._bv.get_data_refs_from(addr):
                target = self._bv.get_functions_containing(ref)
                xrefs_from.append(
                    {
                        "type": "data",
                        "to_address": ref,
                        "to_function": target[0].name if target else None,
                    }
                )

        return {"address": addr, "xrefs_to": xrefs_to, "xrefs_from": xrefs_from}

    def function(self, func: "Function | str | int"):
        """Get the Function object for a name or an address, for work these methods do not cover.

        The real Binary Ninja object, not a rendered dict: read and assign its attributes
        directly, as in binja.function("main").name = "parse_header". Every `func` argument
        takes the same forms, including a Function itself, so one can be passed straight on.

        Returns:
            A binaryninja.Function, or None if nothing resolves
        """
        return self._resolve_function(func)

    # =========================================================================
    # Mutation Operations (tracked)
    # =========================================================================

    def define_type(self, c_definition: str) -> list[str]:
        """Define types from C syntax, and name the ones it defined.

        A bare True said only that nothing raised, which C declaring no type at all satisfies:
        `int x;` is a variable and a comment is nothing, and both answered True having defined
        nothing. An empty list is the honest answer to those, and the parser's own diagnostic,
        with a line and a column, is what comes back when the C does not parse.

        Returns:
            [name, ...] for each type defined, empty when the C declared none
        """
        parsed = self._bv.parse_types_from_string(c_definition)
        for name, type_ in parsed.types.items():
            self._bv.define_user_type(name, type_)
        return [str(name) for name in parsed.types]

    def set_function_signature(self, func: "Function | str | int", signature: str) -> bool:
        """Set function prototype, and wait for the analysis that makes it visible.

        Assigning a function type only queues reanalysis, so reading the signature back in the
        same call returns the old one. This waits, which is the whole reason the method is still
        here: True means the new signature is in effect, not that it has been scheduled.

        Args:
            func: Function name or address
            signature: Function signature string (e.g., "int foo(char* bar)")

        Returns:
            True, or False if the function does not resolve; a signature that does not parse raises
        """
        f = self._resolve_function(func)
        if not f:
            return False

        # parse_type_string raises SyntaxError naming the line and column it gave up at. Letting it
        # out is the entire diagnostic: caught, the caller was left a bare False to guess at.
        parsed_type, _ = self._bv.parse_type_string(signature)
        f.type = parsed_type
        self._bv.update_analysis_and_wait()
        return True

    # =========================================================================
    # Checkpoints
    # =========================================================================

    def checkpoint(self, name: str) -> bool:
        """Name the current state of the database so a later rollback can return to it. Lasts as long as the server runs.

        Covers changes made through `bv` directly as well as through these methods, because
        Binary Ninja commits every mutation as its own undo entry. For atomicity inside a single
        call, `with bv.undoable_transaction():` is cheaper and reverts itself on an exception.

        Stopping the server forgets the names, while the undo stack they point into survives in
        the database, so a name from before a restart is gone rather than stale and rollback()
        answers False.

        Returns:
            True, or False if a checkpoint of that name already exists
        """
        if name in self._checkpoints:
            return False
        self._checkpoints[name] = self._undo_depth()
        return True

    def rollback(self, name: str) -> bool:
        """Undo every change made since the named checkpoint, discarding later checkpoints.

        Waits for analysis before returning, so a reverted function signature reads back as the
        old one rather than needing another call to become visible.

        Returns:
            True, or False if no checkpoint of that name exists
        """
        if name not in self._checkpoints:
            return False

        # Undo back down to the recorded depth rather than a counted number of actions, so a redo
        # or a change made in the GUI cannot leave the two out of step. A depth below the current
        # one yields an empty range, which is what keeps a stale checkpoint from undoing work that
        # predates it.
        for _ in range(self._undo_depth() - self._checkpoints[name]):
            self._bv.undo()

        # Undoing a function type change only queues the reanalysis that makes it visible, the
        # same way setting one does.
        self._bv.update_analysis_and_wait()

        taken_at = self._checkpoints[name]
        self._checkpoints = {
            key: depth for key, depth in self._checkpoints.items() if depth <= taken_at
        }
        return True

    def delete_checkpoint(self, name: str) -> bool:
        """Forget a checkpoint without undoing anything.

        Rollback discards the checkpoints taken after the one it returns to, and keeps the rest,
        so a session that guards several batches accumulates names it will not use again. Each
        one is listed in this tool's description on every call, which is what makes forgetting
        them worth a method.

        Returns:
            True, or False if no checkpoint of that name exists
        """
        return self._checkpoints.pop(name, None) is not None

    def list_checkpoints(self) -> list[dict]:
        """List saved checkpoints, oldest first.

        Returns:
            [{name, undo_depth}, ...]
        """
        return [{"name": name, "undo_depth": depth} for name, depth in self._checkpoints.items()]

    def _undo_depth(self) -> int:
        """How many committed transactions deep the database currently is.

        Commits first. A mutation made outside an explicit transaction sits in an anonymous one
        that Binary Ninja commits at its own pace, so measuring without committing misses
        everything the calling code has just done: a checkpoint would record a depth from before
        its own call's work, and a rollback in that same call would undo nothing while reporting
        success. Committing is safe inside a `with bv.undoable_transaction():`, which still
        reverts its own block on an exception.
        """
        self._bv.commit_undo_actions()
        return len(self._bv.file.undo_entries)

    # =========================================================================
    # Helpers
    # =========================================================================

    def _function_at_address(self, addr: int):
        """The function starting at addr, else whichever function contains it.

        get_functions_containing() on its own is wrong wherever two functions share a basic
        block: asked for an address that is one function's entry point it can answer with a
        different function that merely covers it, and the caller then decompiles, renames or
        patches the wrong function with nothing to show that it did.
        """
        exact = self._bv.get_function_at(addr)
        if exact is not None:
            return exact
        containing = self._bv.get_functions_containing(addr)
        return containing[0] if containing else None

    def _resolve_function(self, func):
        """Resolve a Function, a name or an address to the Function it names.

        A Function passes straight through. binja.function() hands one back and the guide says so,
        which makes handing it to the next method the obvious next line; resolving only strings and
        addresses turned that line into None, and the caller then read it as "no such function".

        Returns:
            Function object or None if not found
        """
        if isinstance(func, Function):
            return func

        if isinstance(func, int):
            return self._function_at_address(func)

        if not isinstance(func, str):
            return None

        # An address first, in either of the cases a hex literal gets written in.
        try:
            return self._function_at_address(
                int(func, 16) if func[:2].lower() == "0x" else int(func)
            )
        except ValueError:
            pass  # Not an address, treat as name

        # By name through the core's index. Scanning bv.functions is linear in the size of the
        # binary and this runs once per call, so a loop over names was quadratic in it. The exact
        # match comes first, because the index also answers to a name a function has since been
        # renamed away from.
        matches = self._bv.get_functions_by_name(func)
        for match in matches:
            if match.name == func:
                return match
        return matches[0] if matches else None

    # =========================================================================
    # Discovery
    # =========================================================================

    def list_methods(self) -> str:
        """List every method callable here, with signatures and summaries."""
        from . import tools
        from .workspace import SkillsManager, WorkspaceManager

        # The classes rather than the live managers: this only renders signatures, and reaching
        # the instances would mean holding references the API no longer has any other use for.
        return tools.build_api_reference(
            {"binja": self, "workspace": WorkspaceManager, "skills": SkillsManager}
        )

    def search_api(self, query: str, limit: int = 40) -> list[dict]:
        """Search Binary Ninja's own API by keyword, for what the methods above do not cover.

        Returns:
            [{name, kind, signature, summary}, ...] where name is what describe() accepts
        """
        terms = query.lower().split()
        matches = [
            entry
            for name, member in _binaryninja_members().items()
            for entry in [_describe_member(name, member)]
            if all(term in name.lower() or term in entry["summary"].lower() for term in terms)
        ]
        matches.sort(key=lambda entry: entry["name"])
        return matches[:limit]

    def describe(self, name: str) -> dict:
        """Full signature and docstring for one Binary Ninja API member, class or enum.

        Takes a qualified name like "BinaryView.read", a bare one like "read", or a class name
        like "Symbol". A bare name that sits on several types resolves to the most central one
        and reports the rest. A class answers with its constructor signature, and an enum with
        its members, because "how do I build one of these" is the question a member cannot
        answer.

        Returns:
            {name, kind, signature, doc}, plus also_defined_on for an ambiguous bare name or members for an enum
        """
        members = _binaryninja_members()
        others = []
        if name not in members:
            cls = _resolve_class_name(name)
            if cls is not None:
                return _describe_class(name, cls)
            name, others = _resolve_member_name(name, members)
        detail = _describe_member(name, members[name], summary_only=False)
        if others:
            detail["also_defined_on"] = others
        return detail


# Where search_api() and describe() look, plus the module's own top-level functions. This is the
# escape hatch the whole design leans on: the wrapper methods cover the common path, and anything
# they do not cover has to be findable here or it is a dead end. So the list covers the types the
# model actually threads through when it leaves the wrapper, not just the ones the wrapper itself
# uses. A name absent from the running version is skipped rather than raising, so listing a type
# that some builds do not ship costs nothing.
#
# Deliberately absent: Settings, TypeLibrary, Component and FlowGraph configure or extend Binary
# Ninja rather than describe a binary, and none of them come up in analysis code.
_DISCOVERY_ROOTS = (
    # Core
    "BinaryView",
    "Function",
    "BasicBlock",
    "Architecture",
    "Platform",
    "FileMetadata",
    # Data and references
    "Variable",
    "DataVariable",
    "Section",
    "Segment",
    "Symbol",
    "StringReference",
    "ReferenceSource",
    # Types
    "Type",
    "NamedTypeReferenceType",
    "StructureBuilder",
    "EnumerationBuilder",
    "TypeParser",
    # Intermediate languages
    "LowLevelILFunction",
    "MediumLevelILFunction",
    "HighLevelILFunction",
    "LowLevelILInstruction",
    "MediumLevelILInstruction",
    "HighLevelILInstruction",
    # Enums worth spelling out, since a wrong member is a silent empty result
    "SymbolType",
    "SymbolBinding",
    # Tags, raw IO and rendering
    "Tag",
    "TagType",
    "BinaryReader",
    "BinaryWriter",
    "InstructionTextToken",
)


def _binaryninja_members() -> dict:
    """Map 'Class.member' to the member, over the roots worth searching.

    Read from the installed binaryninja module rather than a checked-in list, so it describes
    whichever version is running and never needs regenerating.
    """
    import inspect

    import binaryninja

    catalog = {}
    for root in _DISCOVERY_ROOTS:
        cls = getattr(binaryninja, root, None)
        if cls is None:
            continue
        for name, member in inspect.getmembers(cls):
            if not name.startswith("_"):
                catalog[f"{root}.{name}"] = member

    for name, member in inspect.getmembers(binaryninja, inspect.isfunction):
        if not name.startswith("_"):
            catalog[f"binaryninja.{name}"] = member

    return catalog


_FORWARD_REF = re.compile(r"ForwardRef\('([^']+)'\)")


def _describe_member(name: str, member, summary_only: bool = True) -> dict:
    import inspect

    if isinstance(member, property):
        kind, signature = "property", ""
        doc = inspect.getdoc(member.fget) or inspect.getdoc(member) or ""
    else:
        kind = "method" if callable(member) else "attribute"
        try:
            signature = str(inspect.signature(member))
        except Exception:
            # Some Binary Ninja annotations fail to resolve at introspection time. A missing
            # signature is worth far less than losing the member from the catalogue entirely.
            signature = ""
        doc = inspect.getdoc(member) or ""

    entry = {"name": name, "kind": kind, "signature": _FORWARD_REF.sub(r"\1", signature)}
    if summary_only:
        lines = [line for line in doc.splitlines() if line.strip()]
        entry["summary"] = lines[0] if lines else ""
    else:
        entry["doc"] = doc
    return entry


def _resolve_class_name(name: str):
    """The class object for a bare class name, or None if the name is not one.

    Read off the binaryninja module rather than _DISCOVERY_ROOTS, so a type that only ever
    appears in an annotation - CoreSymbol, say - still answers.
    """
    import inspect

    import binaryninja

    cls = getattr(binaryninja, name, None)
    return cls if inspect.isclass(cls) else None


def _describe_class(name: str, cls) -> dict:
    """Constructor signature for a class, member list for an enum.

    An enum's __init__ is int's and says nothing; the members are the whole point, and passing a
    wrong one is a silent empty result rather than an error.
    """
    import enum
    import inspect

    doc = inspect.getdoc(cls) or ""

    if issubclass(cls, enum.Enum):
        return {
            "name": name,
            "kind": "enum",
            "signature": "",
            "doc": doc,
            "members": [member.name for member in cls],
        }

    try:
        signature = str(inspect.signature(cls))
    except (TypeError, ValueError):
        # Some Binary Ninja classes are constructed by the core and expose no Python __init__.
        signature = ""
    return {
        "name": name,
        "kind": "class",
        "signature": _FORWARD_REF.sub(r"\1", signature),
        "doc": doc,
    }


def _resolve_member_name(name: str, members: dict) -> tuple[str, list[str]]:
    """Accept a bare member name, so describe('get_functions_containing') works.

    Roughly a third of bare names sit on more than one type, and refusing to answer without a
    qualified name costs a round trip to learn something the caller usually did not care about.
    Ties break towards the earliest entry in _DISCOVERY_ROOTS, which is ordered by how central the
    type is to analysis code, so a bare name lands on BinaryView before FileMetadata. The result
    is qualified and names the types that lost the tie, so the choice is visible rather than
    silent.
    """
    order = {root: index for index, root in enumerate(_DISCOVERY_ROOTS)}
    candidates = sorted(
        (key for key in members if key.split(".")[-1] == name),
        key=lambda key: (order.get(key.split(".")[0], len(order)), key),
    )
    if not candidates:
        raise BinjaAPIError(
            f"No Binary Ninja API member or class named {name!r}. Use search_api() to find one."
        )
    return candidates[0], candidates[1:]
