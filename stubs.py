"""API stub generator for LLM context."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from binaryninja import BinaryView

    from plugin.state import StateTracker
    from plugin.workspace import SkillsManager, WorkspaceManager


def generate_api_stubs(
    bv: "BinaryView",
    state: "StateTracker",
    workspace: "WorkspaceManager",
    skills: "SkillsManager",
) -> str:
    """Generate Python API documentation for LLM context."""

    try:
        # Binary info header
        binary_info = f"""# Binary Ninja Code Mode API
# Binary: {bv.file.filename}
# Arch: {bv.arch.name if bv.arch else "unknown"} | Platform: {bv.platform.name if bv.platform else "unknown"}
# Functions: {len(bv.functions)} | Range: {bv.start:#x}-{bv.end:#x}
"""

        # State summary
        state_info = state.get_summary()

        # Persistence summary
        files = workspace.list()
        skill_list = skills.list()
        persistence_info = (
            f"# Workspace: {len(files)} file(s) | Skills: {len(skill_list)} available"
        )

        # Skills hint
        skills_hint = ""
        if skill_list:
            names = ", ".join(s["name"] for s in skill_list[:5])
            if len(skill_list) > 5:
                names += f", ... (+{len(skill_list) - 5} more)"
            skills_hint = f"\n# Available skills: {names}"
    except Exception as e:
        return f"# Error generating stubs: {e}\n# Binary Ninja Code Mode API (fallback mode)\n"

    api_docs = """
# === BINARY NINJA CODE MODE API ===
# Access all functionality via the `binja` object.
# Use print() for output (automatically captured).
# Functions accept name (str) or address (int) where marked str|int.
# Most return values include both decimal and hex addresses (address + address_hex).

# QUICK START:
binja.list_functions(limit=10)              # List first 10 functions
binja.decompile("main")                     # Decompile function
binja.get_xrefs_to(0x401000)                # Find callers
binja.get_xrefs_from(0x401050)              # Find what this code references
binja.get_function_calls("process_packet")  # Find callees with call-site addresses
binja.find_bytes("48 89 e5")              # Search for byte pattern (hex string or bytes)
binja.write_file("notes.txt", "results")    # Save to workspace

## PROPERTIES (BinaryView-style access)
binja.functions -> list[dict]    # Alias for list_functions()
binja.strings -> list[dict]      # Alias for list_strings()
binja.file -> dict               # {filename, original_filename}
binja.start -> int               # Binary start address
binja.end -> int                 # Binary end address
binja.entry_point -> int         # Entry point address

## QUERY (READ-ONLY)

# Binary Info
binja.get_binary_status() -> dict  # {filename, architecture, platform, entry_point, function_count, start, end}
binja.list_functions(limit=None, min_size=None, max_size=None, name_contains=None, has_calls_to=None, offset=0) -> list[dict]  # [{name, address, address_hex, size}, ...]
binja.analyze_functions_batch(batch_size=100, offset=0, include_calls=False, include_xrefs=False, ...) -> dict  # For large-scale analysis
binja.list_imports(limit=None, offset=0) -> list[dict]   # [{name, address, address_hex, namespace}, ...]
binja.list_exports(limit=None, offset=0) -> list[dict]   # [{name, address, address_hex}, ...]
binja.list_segments(limit=None, offset=0) -> list[dict]  # [{start, start_hex, end, end_hex, length, readable, writable, executable}, ...]
binja.list_classes(limit=None, offset=0) -> list[str]
binja.list_namespaces(limit=None, offset=0) -> list[str]
binja.list_data_items() -> list[dict]  # [{name, address, address_hex}, ...]

# Code Analysis
binja.decompile(func: str|int, il_level="hlil", start_line=0, max_lines=None) -> str|None  # Paging for large functions
binja.get_assembly(func: str|int, start_line=0, max_lines=None) -> str|None  # Paging for large functions
binja.get_basic_blocks(func: str|int) -> list[dict]  # [{start, start_hex, end, end_hex, byte_length, instruction_count, successors, predecessors}, ...]

# Cross References
binja.get_xrefs_to(func: str|int) -> list[dict]         # [{from_function, from_address, from_address_hex}, ...] - who calls this?
binja.get_xrefs_from(addr: int) -> list[dict]           # [{to_address, to_address_hex, to_function, type}, ...] - what does this reference?
binja.get_function_calls(func: str|int) -> list[dict]   # [{to_function, to_address, to_address_hex, call_site, call_site_hex}, ...] - with call locations!
binja.get_data_xrefs_to(addr: int) -> list[dict]        # [{from_function, from_address, from_address_hex}, ...]
binja.get_data_xrefs_from(addr: int) -> list[dict]      # [{to_address}, ...] - data referenced by code at addr

# Data Reading
binja.read_bytes(addr: int, length: int) -> bytes|None
binja.read_string(addr: int, max_length=256) -> str|None  # NUL-terminated UTF-8/latin-1
binja.get_string_at(addr: int) -> str|None
binja.get_data_var_at(addr: int) -> dict|None  # {address, type, name}
binja.list_strings(limit=None, min_length=4, offset=0) -> list[dict]  # [{address, address_hex, value, length, type}, ...]

# Search & Lookup
binja.find_bytes(pattern: bytes|str, start=None, end=None, limit=100) -> list[int]  # Hex string "48 89 e5" or bytes b"\x48\x89\xe5"
binja.function_at(addr: int|str) -> dict|None  # {name, start, start_hex, end, end_hex, size} or None
binja.get_comment(addr: int) -> str|None
binja.get_function_comment(func: str|int) -> str|None
binja.get_type(name: str) -> str|None  # Structs/typedefs only. For functions use decompile() or function_at()

## MUTATIONS (return bool, tracked for rollback)
# Note: Use checkpoint/rollback MCP tools for undo support (session-scoped, not persisted across restarts)

# Renaming
binja.rename_function(func: str|int, new_name: str) -> bool
binja.rename_data(addr: int, new_name: str) -> bool
binja.rename_variable(func: str|int, old_name: str, new_name: str) -> bool

# Typing
binja.retype_variable(func: str|int, var_name: str, new_type: str) -> bool
binja.define_type(c_definition: str) -> bool  # Ex: "struct pkt { uint32_t id; char data[64]; }"
binja.set_function_signature(func: str|int, signature: str) -> bool  # Ex: "int proc(char* buf, size_t len)"

# Comments
binja.set_comment(addr: int, comment: str) -> bool
binja.set_function_comment(func: str|int, comment: str) -> bool
binja.delete_comment(addr: int) -> bool
binja.delete_function_comment(func: str|int) -> bool

## WORKSPACE (file persistence)
binja.write_file(name: str, content: str) -> bool
binja.read_file(name: str) -> str|None
binja.list_files() -> list[dict]  # [{name, size, modified}, ...]
binja.delete_file(name: str) -> bool

## SKILLS (reusable code)
binja.save_skill(name: str, code: str, description: str) -> bool
binja.load_skill(name: str) -> dict|None  # {name, description, code}
binja.list_skills() -> list[dict]  # [{name, description}, ...]
binja.delete_skill(name: str) -> bool

## HELPERS
binja.find_functions_calling_unsafe(unsafe_patterns=None) -> list[dict]  # Default patterns: strcpy, sprintf, gets, memcpy, malloc, etc.
binja.get_function_complexity(func: str|int) -> dict|None  # {name, address, size, basic_blocks, cyclomatic_complexity, callers_count, callees_count, instruction_count}

# Note: Many functions return None on failure - always check before using!
"""

    return (
        binary_info
        + state_info
        + "\n"
        + persistence_info
        + skills_hint
        + "\n"
        + api_docs
    )
