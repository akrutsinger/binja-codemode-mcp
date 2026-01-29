"""Binary Ninja API wrapper for LLM code execution."""

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from binaryninja import BinaryView

    from .state import StateTracker
    from .workspace import SkillsManager, WorkspaceManager


class BinjaAPIError(Exception):
    """Custom exception for API errors with detailed messages."""

    pass


class BinjaAPI:
    """
    Binary Ninja API wrapper for LLM code execution.
    All methods operate on the current BinaryView.
    """

    def __init__(
        self,
        bv: "BinaryView",
        state: "StateTracker",
        workspace: "WorkspaceManager",
        skills: "SkillsManager",
    ):
        self._bv = bv
        self._state = state
        self._workspace = workspace
        self._skills = skills

    # =========================================================================
    # BinaryView-Style Property Aliases
    # =========================================================================

    @property
    def functions(self) -> list[dict[str, Any]]:
        """BinaryView-style property alias for list_functions()."""
        return self.list_functions()

    @property
    def strings(self) -> list[dict]:
        """BinaryView-style property alias for list_strings()."""
        return self.list_strings(limit=None)

    @property
    def file(self) -> dict[str, Any]:
        """BinaryView-style property alias for binary info."""
        return {
            "filename": self._bv.file.filename,
            "original_filename": self._bv.file.original_filename,
        }

    @property
    def start(self) -> int:
        """Start address of the binary."""
        return self._bv.start

    @property
    def end(self) -> int:
        """End address of the binary."""
        return self._bv.end

    @property
    def entry_point(self) -> int:
        """Entry point address."""
        return self._bv.entry_point

    @property
    def bv(self) -> "BinaryView":
        """Direct BinaryView access for advanced operations.

        Use this for operations not covered by wrapper methods.
        For mutations, prefer wrapper methods (rename_function, set_comment, etc.)
        which track changes for rollback support.

        Example:
            # Access BV properties directly
            binja.bv.arch.name
            binja.bv.sections

            # Iterate raw function objects
            for f in binja.bv.functions[:5]:
                print(f.name, f.start)

            # Use with serialize() for readable output
            binja.serialize(binja.bv.functions[0])
        """
        return self._bv

    def serialize(self, obj: Any) -> dict | list | str:
        """Convert Binary Ninja objects to JSON-friendly format.

        Handles Function, Symbol, Segment, BasicBlock, Variable, and other
        common BN types. Use when working with raw binja.bv results.

        Args:
            obj: Any Binary Ninja object or collection

        Returns:
            Dict, list, or string representation suitable for display

        Example:
            binja.serialize(binja.bv.functions[0])
            # -> {'name': 'main', 'address': 4198400, 'address_hex': '0x401000', 'size': 256}

            binja.serialize(binja.bv.segments)
            # -> [{'name': '.text', 'start': ..., 'end': ...}, ...]
        """
        # Handle None
        if obj is None:
            return None

        # Handle lists/tuples recursively
        if isinstance(obj, (list, tuple)):
            return [self.serialize(x) for x in obj]

        # Handle dicts recursively
        if isinstance(obj, dict):
            return {k: self.serialize(v) for k, v in obj.items()}

        # Handle primitives
        if isinstance(obj, (str, int, float, bool, bytes)):
            if isinstance(obj, bytes):
                return self.fmt_hex(obj)
            return obj

        # Function object
        if hasattr(obj, "start") and hasattr(obj, "name") and hasattr(obj, "total_bytes"):
            return {
                "name": obj.name,
                "address": obj.start,
                "address_hex": f"{obj.start:#x}",
                "size": getattr(obj, "total_bytes", None),
            }

        # Segment object
        if hasattr(obj, "start") and hasattr(obj, "end") and hasattr(obj, "readable"):
            return {
                "start": obj.start,
                "start_hex": f"{obj.start:#x}",
                "end": obj.end,
                "end_hex": f"{obj.end:#x}",
                "length": getattr(obj, "length", obj.end - obj.start),
                "readable": obj.readable,
                "writable": obj.writable,
                "executable": obj.executable,
            }

        # Symbol object
        if hasattr(obj, "address") and hasattr(obj, "name") and hasattr(obj, "type"):
            return {
                "name": obj.name,
                "address": obj.address,
                "address_hex": f"{obj.address:#x}",
                "type": str(obj.type),
            }

        # BasicBlock object
        if hasattr(obj, "start") and hasattr(obj, "end") and hasattr(obj, "outgoing_edges"):
            return {
                "start": obj.start,
                "start_hex": f"{obj.start:#x}",
                "end": obj.end,
                "end_hex": f"{obj.end:#x}",
                "length": getattr(obj, "length", obj.end - obj.start),
            }

        # Variable object
        if hasattr(obj, "name") and hasattr(obj, "type") and not hasattr(obj, "start"):
            return {
                "name": obj.name,
                "type": str(obj.type) if obj.type else None,
            }

        # Generic object with address attribute
        if hasattr(obj, "address"):
            result = {"address": obj.address, "address_hex": f"{obj.address:#x}"}
            if hasattr(obj, "name"):
                result["name"] = obj.name
            return result

        # Generic object with start attribute
        if hasattr(obj, "start"):
            result = {"start": obj.start, "start_hex": f"{obj.start:#x}"}
            if hasattr(obj, "name"):
                result["name"] = obj.name
            if hasattr(obj, "end"):
                result["end"] = obj.end
                result["end_hex"] = f"{obj.end:#x}"
            return result

        # Fallback to string representation
        return str(obj)

    # =========================================================================
    # Query Operations (read-only)
    # =========================================================================

    def get_binary_status(self) -> dict[str, Any]:
        """Get current binary metadata."""
        return {
            "filename": self._bv.file.filename,
            "architecture": self._bv.arch.name if self._bv.arch else None,
            "platform": self._bv.platform.name if self._bv.platform else None,
            "entry_point": self._bv.entry_point,
            "function_count": len(self._bv.functions),
            "start": self._bv.start,
            "end": self._bv.end,
        }

    def list_functions(
        self,
        limit: int | None = None,
        min_size: int | None = None,
        max_size: int | None = None,
        name_contains: str | None = None,
        has_calls_to: str | None = None,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List functions with optional filtering and pagination.

        Args:
            limit: Maximum number of results (default: None = all)
            offset: Number of results to skip (default: 0)
            min_size: Minimum function size in bytes (default: None = no filter)
            max_size: Maximum function size in bytes (default: None = no filter)
            name_contains: Filter by name substring (default: None = no filter)
            has_calls_to: Filter to functions that call this function name (default: None = no filter)

        Returns:
            List of function dicts with name, address, size
        """
        results = []

        for f in self._bv.functions:
            # Apply filters
            if min_size is not None and f.total_bytes < min_size:
                continue
            if max_size is not None and f.total_bytes > max_size:
                continue
            if (
                name_contains is not None
                and name_contains.lower() not in f.name.lower()
            ):
                continue
            if has_calls_to is not None:
                # Check if this function calls the target
                target_lower = has_calls_to.lower()
                calls_target = any(
                    target_lower in callee.name.lower() for callee in f.callees
                )
                if not calls_target:
                    continue

            results.append({"name": f.name, "address": f.start, "address_hex": f"{f.start:#x}", "size": f.total_bytes})

        # Apply pagination
        if offset:
            results = results[offset:]
        if limit is not None:
            results = results[:limit]

        return results

    def analyze_functions_batch(
        self,
        batch_size: int = 100,
        offset: int = 0,
        include_calls: bool = False,
        include_xrefs: bool = False,
        min_size: int | None = None,
        max_size: int | None = None,
        name_contains: str | None = None,
        has_calls_to: str | None = None,
    ) -> dict:
        """Analyze functions in batches to avoid timeouts.

        Args:
            batch_size: Number of functions to analyze per batch (default: 100)
            offset: Starting offset in function list (default: 0)
            include_calls: Include function calls in results
            include_xrefs: Include cross-references in results
            min_size: Minimum function size in bytes
            max_size: Maximum function size in bytes
            name_contains: Filter by name substring
            has_calls_to: Filter to functions calling this function

        Returns:
            dict with 'functions' list, 'total_count', 'batch_size', 'offset', 'has_more'
        """
        # Get filtered function list
        all_funcs = self.list_functions(
            limit=None,
            offset=0,
            min_size=min_size,
            max_size=max_size,
            name_contains=name_contains,
            has_calls_to=has_calls_to,
        )
        total_count = len(all_funcs)

        # Apply batch pagination
        batch_end = min(offset + batch_size, total_count)
        batch_funcs = all_funcs[offset:batch_end]

        results = []
        for func_info in batch_funcs:
            result = func_info.copy()

            if include_calls:
                try:
                    result["calls"] = self.get_function_calls(func_info["name"])
                except Exception as e:
                    result["calls_error"] = str(e)

            if include_xrefs:
                try:
                    result["xrefs_to"] = self.get_xrefs_to(func_info["name"])
                except Exception as e:
                    result["xrefs_error"] = str(e)

            results.append(result)

        return {
            "functions": results,
            "total_count": total_count,
            "batch_size": batch_size,
            "offset": offset,
            "has_more": batch_end < total_count,
            "next_offset": batch_end if batch_end < total_count else None,
        }

    def list_imports(self, limit: int | None = None, offset: int = 0) -> list[dict]:
        """List imported symbols."""
        from binaryninja import SymbolType

        results = []
        for sym in self._bv.get_symbols_of_type(SymbolType.ImportedFunctionSymbol):
            results.append(
                {
                    "name": sym.name,
                    "address": sym.address,
                    "address_hex": f"{sym.address:#x}",
                    "namespace": sym.namespace if sym.namespace else None,
                }
            )

        if offset:
            results = results[offset:]
        if limit is not None:
            results = results[:limit]

        return results

    def list_exports(self, limit: int | None = None, offset: int = 0) -> list[dict]:
        """List exported symbols."""
        from binaryninja import SymbolBinding, SymbolType

        results = []
        for sym in self._bv.get_symbols_of_type(SymbolType.FunctionSymbol):
            if sym.binding == SymbolBinding.GlobalBinding:
                results.append({"name": sym.name, "address": sym.address, "address_hex": f"{sym.address:#x}"})

        if offset:
            results = results[offset:]
        if limit is not None:
            results = results[:limit]

        return results

    def list_segments(self, limit: int | None = None, offset: int = 0) -> list[dict]:
        """List memory segments."""
        results = [
            {
                "start": seg.start,
                "start_hex": f"{seg.start:#x}",
                "end": seg.end,
                "end_hex": f"{seg.end:#x}",
                "length": seg.length,
                "readable": seg.readable,
                "writable": seg.writable,
                "executable": seg.executable,
            }
            for seg in self._bv.segments
        ]

        if offset:
            results = results[offset:]
        if limit is not None:
            results = results[:limit]

        return results

    def list_classes(self, limit: int | None = None, offset: int = 0) -> list[str]:
        """List class/namespace names."""
        results = []
        for name, t in self._bv.types:
            if hasattr(t, "structure") and t.structure:
                results.append(str(name))

        if offset:
            results = results[offset:]
        if limit is not None:
            results = results[:limit]

        return results

    def list_namespaces(self, limit: int | None = None, offset: int = 0) -> list[str]:
        """List non-global namespaces."""
        namespaces = set()
        for sym in self._bv.get_symbols():
            if sym.namespace:
                namespaces.add(sym.namespace)
        results = list(namespaces)

        if offset:
            results = results[offset:]
        if limit is not None:
            results = results[:limit]

        return results

    def list_data_items(self) -> list[dict]:
        """List defined data labels."""
        from binaryninja import SymbolType

        results = []
        for sym in self._bv.get_symbols_of_type(SymbolType.DataSymbol):
            results.append(
                {
                    "name": sym.name,
                    "address": sym.address,
                    "address_hex": f"{sym.address:#x}",
                }
            )
        return results

    def decompile(
        self,
        func: str | int,
        il_level: str = "hlil",
        start_line: int = 0,
        max_lines: int | None = None,
    ) -> str | None:
        """Decompile function to C-like pseudocode.

        Args:
            func: Function name or address
            il_level: IL level - "hlil" (high), "mlil" (medium), or "llil" (low)
            start_line: First line to return (0-indexed, for paging large functions)
            max_lines: Maximum lines to return (None = all)

        Returns:
            Decompiled code or None if function not found
        """
        # Validate il_level parameter
        valid_levels = ["hlil", "mlil", "llil"]
        if il_level not in valid_levels:
            raise ValueError(
                f"il_level must be one of {valid_levels}, got '{il_level}'"
            )

        f = self._resolve_function(func)
        if not f:
            return None

        lines = [f"// {f.name} @ {f.start:#x}", str(f.type)]

        # Add variable definitions (only for HLIL)
        if il_level == "hlil" and f.vars:
            lines.append("// Variables:")
            for var in f.vars:
                var_type = str(var.type) if var.type else "auto"
                lines.append(f"//   {var_type} {var.name}")
            lines.append("")

        lines.append("{")

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

        # Apply paging
        total_lines = len(lines)
        if start_line > 0:
            lines = lines[start_line:]
        if max_lines is not None:
            lines = lines[:max_lines]

        # Add paging info if truncated
        if start_line > 0 or (max_lines is not None and start_line + len(lines) < total_lines):
            lines.insert(0, f"// [Lines {start_line}-{start_line + len(lines) - 1} of {total_lines}]")

        result = "\n".join(lines)

        return result

    def get_mlil(self, func: str | int, start_line: int = 0, max_lines: int | None = None) -> str | None:
        """Get Medium-Level IL for function (SSA form with explicit assignments).

        Args:
            func: Function name (str) or address (int)
        """
        return self.decompile(func, il_level="mlil", start_line=start_line, max_lines=max_lines)

    def get_hlil(self, func: str | int, start_line: int = 0, max_lines: int | None = None) -> str | None:
        """Get High-Level IL (C-like pseudocode) for function.

        Args:
            func: Function name (str) or address (int)
        """
        return self.decompile(func, il_level="hlil", start_line=start_line, max_lines=max_lines)

    def get_llil(self, func: str | int, start_line: int = 0, max_lines: int | None = None) -> str | None:
        """Get Low-Level IL for function (normalized assembly).

        Args:
            func: Function name (str) or address (int)
        """
        return self.decompile(func, il_level="llil", start_line=start_line, max_lines=max_lines)

    def get_assembly(
        self,
        func: str | int,
        start_line: int = 0,
        max_lines: int | None = None,
    ) -> str | None:
        """Get disassembly for function.

        Args:
            func: Function name or address
            start_line: First line to return (0-indexed, for paging large functions)
            max_lines: Maximum lines to return (None = all)

        Returns:
            Disassembly or None if function not found
        """
        f = self._resolve_function(func)
        if not f:
            return None

        lines = []
        for block in f.basic_blocks:
            for instr in block.disassembly_text:
                text = "".join(t.text for t in instr.tokens)
                lines.append(f"{instr.address:#x}: {text}")

        # Apply paging
        total_lines = len(lines)
        if start_line > 0:
            lines = lines[start_line:]
        if max_lines is not None:
            lines = lines[:max_lines]

        # Add paging info if truncated
        if start_line > 0 or (max_lines is not None and start_line + len(lines) < total_lines):
            lines.insert(0, f"; [Lines {start_line}-{start_line + len(lines) - 1} of {total_lines}]")

        return "\n".join(lines)

    def get_xrefs_to(self, func: str | int) -> list[dict]:
        """Get cross-references to function (callers)."""
        f = self._resolve_function(func)
        if not f:
            return []

        results = []
        for ref in self._bv.get_code_refs(f.start):
            caller = self._bv.get_functions_containing(ref.address)
            if caller:
                results.append(
                    {
                        "from_function": caller[0].name,
                        "from_address": ref.address,
                        "from_address_hex": f"{ref.address:#x}",
                    }
                )
        return results

    def get_data_xrefs_to(self, addr: int) -> list[dict]:
        """Get cross-references to data address."""
        results = []
        for ref in self._bv.get_code_refs(addr):
            caller = self._bv.get_functions_containing(ref.address)
            if caller:
                results.append(
                    {
                        "from_function": caller[0].name,
                        "from_address": ref.address,
                        "from_address_hex": f"{ref.address:#x}",
                    }
                )
        return results

    def get_data_xrefs_from(self, addr: int) -> list[dict]:
        """Get data addresses referenced by code at this address.

        Args:
            addr: Code address to check for data references

        Returns:
            List of dicts with 'to_address' for each data location referenced
        """
        results = []
        for ref in self._bv.get_data_refs_from(addr):
            results.append({"to_address": ref})
        return results

    def get_xrefs_from(self, addr: int) -> list[dict]:
        """Get cross-references from an address (what does this code call/reference?).

        Args:
            addr: Address to check for outgoing references

        Returns:
            List of dicts with 'to_address', 'to_address_hex', optionally 'to_function', and 'type'
        """
        results = []

        # Code references (calls, jumps)
        for ref in self._bv.get_code_refs_from(addr):
            target_funcs = self._bv.get_functions_containing(ref)
            results.append({
                "to_address": ref,
                "to_address_hex": f"{ref:#x}",
                "to_function": target_funcs[0].name if target_funcs else None,
                "type": "code"
            })

        # Data references
        for ref in self._bv.get_data_refs_from(addr):
            results.append({
                "to_address": ref,
                "to_address_hex": f"{ref:#x}",
                "type": "data"
            })

        return results

    def function_at(self, addr: int | str) -> dict | None:
        """Get function info containing address.

        Args:
            addr: Address as integer or hex string (e.g., 0x1000 or "0x1000")

        Returns:
            Dict with name, start, end, size or None if not found
        """
        if isinstance(addr, str):
            try:
                addr = int(addr, 16) if addr.startswith("0x") else int(addr)
            except ValueError:
                return None

        funcs = self._bv.get_functions_containing(addr)
        if not funcs:
            return None

        f = funcs[0]
        return {
            "name": f.name,
            "start": f.start,
            "start_hex": f"{f.start:#x}",
            "end": f.start + f.total_bytes,
            "end_hex": f"{f.start + f.total_bytes:#x}",
            "size": f.total_bytes,
        }

    def get_comment(self, addr: int) -> str | None:
        """Get comment at address. Returns None if no comment exists."""
        comment = self._bv.get_comment_at(addr)
        return comment if comment else None

    def get_function_comment(self, func: str | int) -> str | None:
        """Get function-level comment. Returns None if no comment exists."""
        f = self._resolve_function(func)
        if not f:
            return None
        return f.comment if f.comment else None

    def get_type(self, name: str) -> str | None:
        """Get user-defined type definition (structs, classes, typedefs).

        Args:
            name: Type name to look up (e.g., "my_struct", "PacketHeader")

        Returns:
            Type definition string or None if not found

        Note:
            This searches for exact match first, then tries common variations
            (struct prefix, class prefix, _t suffix). Built-in C types like
            'int', 'char', 'void' will return None.

            For function signatures, use decompile() or function_at() instead.
            For function type info, use set_function_signature() to define it.
        """
        # Try exact match first
        t = self._bv.get_type_by_name(name)
        if t:
            return str(t)

        # Try common variations
        for variant in [f"struct {name}", f"class {name}", f"{name}_t", f"struct {name}_t"]:
            t = self._bv.get_type_by_name(variant)
            if t:
                return str(t)

        return None

    def read_bytes(self, addr: int, length: int) -> bytes | None:
        """Read raw bytes from address."""
        try:
            data = self._bv.read(addr, length)
            return data if data else None
        except Exception:
            return None

    def read_string(self, addr: int, max_length: int = 256) -> str | None:
        """Read null-terminated string from address."""
        try:
            data = self._bv.read(addr, max_length)
            if not data:
                return None
            # Find null terminator
            null_idx = data.find(b"\x00")
            if null_idx >= 0:
                data = data[:null_idx]
            # Try to decode as UTF-8, fallback to latin-1
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                return data.decode("latin-1", errors="replace")
        except Exception:
            return None

    def get_data_var_at(self, addr: int) -> dict | None:
        """Get data variable info at address."""
        try:
            var = self._bv.get_data_var_at(addr)
            if var:
                return {
                    "address": var.address,
                    "type": str(var.type) if var.type else None,
                    "name": var.name if hasattr(var, "name") else None,
                }
            return None
        except Exception:
            return None

    def get_string_at(self, addr: int) -> str | None:
        """Get string defined at address (if any)."""
        try:
            string_ref = self._bv.get_string_at(addr)
            if string_ref:
                return str(string_ref)
            return None
        except Exception:
            return None

    def get_function_calls(self, func: str | int) -> list[dict]:
        """Get list of functions called by this function with call-site addresses.

        Returns:
            List of dicts with to_function, to_address, call_site (address where call is made)
        """
        f = self._resolve_function(func)
        if not f:
            return []

        results = []

        # Use HLIL to get call sites with addresses
        if f.hlil:
            from binaryninja import HighLevelILOperation

            for block in f.hlil:
                for instr in block:
                    if hasattr(instr, "operation") and instr.operation == HighLevelILOperation.HLIL_CALL:
                        call_site = instr.address
                        target = None
                        target_name = None

                        # Try to resolve target address
                        if hasattr(instr.dest, "constant"):
                            target = instr.dest.constant
                            target_funcs = self._bv.get_functions_containing(target)
                            target_name = target_funcs[0].name if target_funcs else f"sub_{target:x}"
                        elif hasattr(instr.dest, "value") and hasattr(instr.dest.value, "value"):
                            target = instr.dest.value.value
                            target_funcs = self._bv.get_functions_containing(target)
                            target_name = target_funcs[0].name if target_funcs else f"sub_{target:x}"

                        if target is not None:
                            results.append({
                                "to_function": target_name,
                                "to_address": target,
                                "to_address_hex": f"{target:#x}",
                                "call_site": call_site,
                                "call_site_hex": f"{call_site:#x}",
                            })

        # Fallback: if no HLIL results, use callees without call-site info
        if not results:
            for callee in f.callees:
                results.append({
                    "to_function": callee.name,
                    "to_address": callee.start,
                    "to_address_hex": f"{callee.start:#x}",
                    "call_site": None,
                    "call_site_hex": None,
                })

        return results

    def get_basic_blocks(self, func: str | int) -> list[dict]:
        """Get basic block info for function including CFG edges.

        Returns:
            List of dicts with start, end, byte_length, instruction_count,
            successors (list of block start addresses), predecessors (list of block start addresses)
        """
        f = self._resolve_function(func)
        if not f:
            return []

        results = []
        for block in f.basic_blocks:
            # Count actual instructions
            instr_count = sum(1 for _ in block.disassembly_text)

            results.append({
                "start": block.start,
                "start_hex": f"{block.start:#x}",
                "end": block.end,
                "end_hex": f"{block.end:#x}",
                "byte_length": block.length,
                "instruction_count": instr_count,
                "successors": [edge.target.start for edge in block.outgoing_edges],
                "predecessors": [edge.source.start for edge in block.incoming_edges],
            })
        return results

    def find_bytes(
        self, pattern: bytes | str, start: int | None = None, end: int | None = None, limit: int = 100
    ) -> list[int]:
        """Search for byte pattern in binary. Returns list of addresses.

        Args:
            pattern: Byte sequence to search for. Can be:
                - bytes: b"\\x48\\x89\\xe5"
                - hex string: "48 89 e5" or "4889e5" (spaces optional)
            start: Start address (default: binary start)
            end: End address (default: binary end)
            limit: Maximum results to return (default: 100)

        Returns:
            List of addresses where pattern was found (max 100 results)
        """
        # Parse hex string if provided
        if isinstance(pattern, str):
            pattern = bytes.fromhex(pattern.replace(" ", ""))

        if start is None:
            start = self._bv.start
        if end is None:
            end = self._bv.end

        results = []
        current = start

        while current < end and len(results) < limit:
            found = self._bv.find_next_data(current, pattern)
            if found is None or found >= end:
                break
            results.append(found)
            current = found + 1

        return results

    def list_strings(
        self, limit: int | None, min_length: int = 4, offset: int = 0
    ) -> list[dict]:
        """List strings in binary with pagination.

        Args:
            min_length: Minimum string length (default: 4)
            limit: Maximum number of results (default: None = all)
            offset: Number of results to skip (default: 0)

        Returns:
            List of string dicts with address, value, length, type
        """
        results = []
        for s in self._bv.strings:
            if s.length >= min_length:
                results.append(
                    {
                        "address": s.start,
                        "address_hex": f"{s.start:#x}",
                        "value": str(s),
                        "length": s.length,
                        "type": s.type.name if hasattr(s.type, "name") else str(s.type),
                    }
                )

        # Apply pagination
        if offset:
            results = results[offset:]
        if limit is not None:
            results = results[:limit]

        return results

    # =========================================================================
    # Mutation Operations (tracked)
    # =========================================================================

    def rename_function(self, func: str | int, new_name: str) -> bool:
        """Rename a function."""
        f = self._resolve_function(func)
        if not f:
            return False

        old_name = f.name
        f.name = new_name
        self._state.record_change(f"rename function: {old_name} -> {new_name}")
        return True

    def rename_data(self, addr: int, new_name: str) -> bool:
        """Rename data label at address."""
        from binaryninja import Symbol

        sym = self._bv.get_symbol_at(addr)
        if not sym:
            return False

        old_name = sym.name
        self._bv.define_user_symbol(Symbol(sym.type, addr, new_name))
        self._state.record_change(f"rename data: {old_name} -> {new_name}")
        return True

    def rename_variable(self, func: str | int, old_name: str, new_name: str) -> bool:
        """Rename variable within function."""
        f = self._resolve_function(func)
        if not f:
            return False

        for var in f.vars:
            if var.name == old_name:
                var.name = new_name
                self._state.record_change(
                    f"rename var in {f.name}: {old_name} -> {new_name}"
                )
                return True
        return False

    def retype_variable(self, func: str | int, var_name: str, new_type: str) -> bool:
        """Change variable type within function."""
        f = self._resolve_function(func)
        if not f:
            return False

        parsed_type, _ = self._bv.parse_type_string(new_type)
        if not parsed_type:
            return False

        for var in f.vars:
            if var.name == var_name:
                var.type = parsed_type
                self._state.record_change(
                    f"retype var {var_name} in {f.name} to {new_type}"
                )
                return True
        return False

    def set_comment(self, addr: int, comment: str) -> bool:
        """Set comment at address."""
        self._bv.set_comment_at(addr, comment)
        self._state.record_change(f"comment at {addr:#x}")
        return True

    def set_function_comment(self, func: str | int, comment: str) -> bool:
        """Set function-level comment."""
        f = self._resolve_function(func)
        if not f:
            return False

        f.comment = comment
        self._state.record_change(f"comment on {f.name}")
        return True

    def delete_comment(self, addr: int) -> bool:
        """Delete comment at address."""
        self._bv.set_comment_at(addr, "")
        self._state.record_change(f"delete comment at {addr:#x}")
        return True

    def delete_function_comment(self, func: str | int) -> bool:
        """Delete function comment."""
        f = self._resolve_function(func)
        if not f:
            return False

        f.comment = ""
        self._state.record_change(f"delete comment on {f.name}")
        return True

    def define_type(self, c_definition: str) -> bool:
        """Define type from C syntax."""
        try:
            types = self._bv.parse_types_from_string(c_definition)
            for name, t in types.types.items():
                self._bv.define_user_type(name, t)
                self._state.record_change(f"define type: {name}")
            return True
        except Exception:
            return False

    def set_function_signature(self, func: str | int, signature: str) -> bool:
        """Set function prototype."""
        f = self._resolve_function(func)
        if not f:
            return False

        try:
            parsed_type, _ = self._bv.parse_type_string(signature)
            if parsed_type:
                f.type = parsed_type
                self._state.record_change(f"signature on {f.name}: {signature}")
                return True
        except Exception:
            pass
        return False

    # =========================================================================
    # Workspace Operations
    # =========================================================================

    def write_file(self, name: str, content: str) -> bool:
        """Write content to workspace file."""
        return self._workspace.write(name, content)

    def read_file(self, name: str) -> str | None:
        """Read content from workspace file."""
        return self._workspace.read(name)

    def list_files(self) -> list[dict]:
        """List workspace files."""
        return self._workspace.list()

    def delete_file(self, name: str) -> bool:
        """Delete a workspace file."""
        return self._workspace.delete(name)

    # =========================================================================
    # Skills Operations
    # =========================================================================

    def save_skill(self, name: str, code: str, description: str) -> bool:
        """Save reusable analysis code as a skill."""
        return self._skills.save(name, code, description)

    def load_skill(self, name: str) -> dict | None:
        """Load a skill."""
        skill = self._skills.load(name)
        if skill:
            return {
                "name": skill.name,
                "description": skill.description,
                "code": skill.code,
            }
        return None

    def list_skills(self) -> list[dict]:
        """List available skills."""
        return self._skills.list()

    def delete_skill(self, name: str) -> bool:
        """Delete a skill."""
        return self._skills.delete(name)

    # =========================================================================
    # API Discovery
    # =========================================================================

    def help(self, method_name: str | None = None) -> str:
        """Get API documentation.

        Args:
            method_name: Specific method name, or None for full API docs.

        Examples:
            binja.help()              # Full API overview
            binja.help("decompile")   # Specific method help
        """
        if method_name is None:
            from stubs import generate_api_stubs
            return generate_api_stubs(self._bv, self._state, self._workspace, self._skills)

        # Return method docstring if exists
        if hasattr(self, method_name):
            method = getattr(self, method_name)
            if callable(method) and method.__doc__:
                return f"{method_name}:\n{method.__doc__}"

        return f"Unknown method: {method_name}. Use binja.help() for all methods."

    # =========================================================================
    # Helpers
    # =========================================================================

    def _resolve_function(self, func: str | int, raise_on_error: bool = False):
        """Resolve function by name or address.

        Args:
            func: Function name or address
            raise_on_error: If True, raise BinjaAPIError instead of returning None

        Returns:
            Function object or None if not found

        Raises:
            BinjaAPIError: If raise_on_error=True and function not found
        """
        if isinstance(func, int):
            funcs = self._bv.get_functions_containing(func)
            if not funcs:
                if raise_on_error:
                    raise BinjaAPIError(f"No function found at address {func:#x}")
                return None
            return funcs[0]
        elif isinstance(func, str):
            # Try to parse as hex string first
            try:
                addr = int(func, 16) if func.startswith("0x") else int(func)
                funcs = self._bv.get_functions_containing(addr)
                if funcs:
                    return funcs[0]
                if raise_on_error:
                    raise BinjaAPIError(f"No function found at address {addr:#x}")
                return None
            except ValueError:
                pass  # Not an address, treat as name

            # Search by function name
            for f in self._bv.functions:
                if f.name == func:
                    return f

            if raise_on_error:
                # Suggest similar names
                similar = [
                    f.name for f in self._bv.functions if func.lower() in f.name.lower()
                ]
                if similar:
                    suggestions = ", ".join(similar[:5])
                    raise BinjaAPIError(
                        f"Function '{func}' not found. Similar: {suggestions}"
                    )
                else:
                    raise BinjaAPIError(
                        f"Function '{func}' not found. Use list_functions() to see available functions."
                    )
            return None

        # Neither string nor int
        return None

    # =========================================================================
    # Common analysis patterns
    # =========================================================================
    def find_functions_calling_unsafe(
        self, unsafe_patterns: list[str] | None = None
    ) -> list[dict[str, Any]]:  # Changed return type for consistency
        """Find all functions calling potentially unsafe functions.

        Args:
            unsafe_patterns: List of function name patterns (default: common unsafe funcs)

        Returns:
            list of dicts with 'function_name', 'address', 'unsafe_calls'

        Example:
            [
                {
                    'function_name': 'main',
                    'address': 0x1000,
                    'unsafe_calls': ['strcpy', 'sprintf']
                },
                ...
            ]
        """
        if unsafe_patterns is None:
            unsafe_patterns = [
                "strcpy",
                "strcat",
                "sprintf",
                "gets",
                "scanf",
                "memcpy",
                "memmove",
                "malloc",
                "free",
                "realloc",
            ]

        results = []

        for func in self._bv.functions:
            unsafe_calls = []

            for callee in func.callees:
                callee_name_lower = callee.name.lower()
                for pattern in unsafe_patterns:
                    if pattern.lower() in callee_name_lower:
                        unsafe_calls.append(callee.name)
                        break

            if unsafe_calls:
                results.append(
                    {
                        "function_name": func.name,
                        "address": func.start,
                        "unsafe_calls": unsafe_calls,
                    }
                )

        return results

    def get_function_complexity(self, func: str | int) -> dict | None:
        """Get complexity metrics for a function.

        Returns:
            dict with cyclomatic_complexity, basic_blocks, size, callers_count, callees_count or
            None if function not found
        """
        f = self._resolve_function(func)
        if not f:
            return None

        # Calculate cyclomatic complexity (edges - nodes + 2)
        if f.hlil:
            edges = sum(len(block.outgoing_edges) for block in f.hlil.basic_blocks)
            nodes = len(f.hlil.basic_blocks)
            complexity = edges - nodes + 2
        else:
            complexity = 0

        return {
            "name": f.name,
            "address": f.start,
            "size": f.total_bytes,
            "basic_blocks": len(f.basic_blocks),
            "cyclomatic_complexity": complexity,
            "callers_count": len(f.callers),
            "callees_count": len(f.callees),
            "instruction_count": sum(len(block) for block in f.basic_blocks),
        }

    # =========================================================================
    # Output Formatting Helpers
    # =========================================================================

    def print_table(
        self,
        data: list[dict],
        columns: list[str] | None = None,
        max_rows: int | None = None,
        addr_cols: list[str] | None = None,
    ) -> str:
        """Format list of dicts as aligned table and print it.

        Args:
            data: List of dicts to display
            columns: Column keys to show (default: auto-detect from first row)
            max_rows: Maximum rows to display (default: all)
            addr_cols: Column names to format as hex addresses (default: auto-detect 'address', 'addr', 'start', 'end')

        Returns:
            The formatted table string (also printed)

        Example:
            binja.print_table(binja.list_functions(limit=10))
            binja.print_table(data, columns=["name", "address", "size"])
        """
        if not data:
            result = "(no data)"
            print(result)
            return result

        # Auto-detect columns from first row
        if columns is None:
            columns = list(data[0].keys())

        # Auto-detect address columns
        if addr_cols is None:
            addr_cols = ["address", "addr", "start", "end", "from_address", "to_address"]

        # Apply max_rows
        display_data = data[:max_rows] if max_rows else data
        truncated = max_rows and len(data) > max_rows

        # Calculate column widths
        widths = {}
        for col in columns:
            # Header width
            widths[col] = len(col)
            # Data widths
            for row in display_data:
                val = row.get(col, "")
                if col in addr_cols and isinstance(val, int):
                    formatted = f"0x{val:08x}"
                else:
                    formatted = str(val)
                widths[col] = max(widths[col], len(formatted))

        # Build format string
        header = "  ".join(col.upper().ljust(widths[col]) for col in columns)
        separator = "  ".join("-" * widths[col] for col in columns)

        lines = [header, separator]

        for row in display_data:
            cells = []
            for col in columns:
                val = row.get(col, "")
                if col in addr_cols and isinstance(val, int):
                    formatted = f"0x{val:08x}"
                elif isinstance(val, int):
                    formatted = str(val)
                elif isinstance(val, list):
                    formatted = ", ".join(str(v) for v in val[:3])
                    if len(val) > 3:
                        formatted += f" (+{len(val) - 3})"
                else:
                    formatted = str(val) if val is not None else ""
                cells.append(formatted.ljust(widths[col]))
            lines.append("  ".join(cells))

        if truncated:
            lines.append(f"... ({len(data) - max_rows} more rows)")

        result = "\n".join(lines)
        print(result)
        return result

    def fmt_addr(self, addr: int, width: int = 8) -> str:
        """Format integer as hex address.

        Args:
            addr: Address to format
            width: Minimum hex digits (default: 8)

        Returns:
            Formatted address string like '0x00401000'
        """
        return f"0x{addr:0{width}x}"

    def fmt_size(self, size: int) -> str:
        """Format byte size with appropriate units.

        Args:
            size: Size in bytes

        Returns:
            Formatted string like '1.5 KB' or '256 bytes'
        """
        if size < 1024:
            return f"{size} bytes"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.1f} MB"

    def fmt_hex(self, data: bytes, sep: str = " ") -> str:
        """Format bytes as hex string.

        Args:
            data: Bytes to format
            sep: Separator between bytes (default: space)

        Returns:
            Hex string like '48 89 e5 41 56'
        """
        return sep.join(f"{b:02x}" for b in data)

    def summary(self, data: Any) -> str:
        """Generate smart summary of data and print it.

        Args:
            data: Any data - dict, list, or primitive

        Returns:
            Formatted summary string (also printed)
        """
        if data is None:
            result = "(none)"
        elif isinstance(data, dict):
            lines = []
            for k, v in data.items():
                if isinstance(v, int) and k in ("address", "addr", "start", "end", "entry_point"):
                    lines.append(f"  {k}: {self.fmt_addr(v)}")
                elif isinstance(v, int) and "size" in k.lower():
                    lines.append(f"  {k}: {self.fmt_size(v)}")
                elif isinstance(v, list):
                    lines.append(f"  {k}: [{len(v)} items]")
                else:
                    lines.append(f"  {k}: {v}")
            result = "\n".join(lines)
        elif isinstance(data, list):
            if not data:
                result = "(empty list)"
            elif isinstance(data[0], dict):
                result = f"[{len(data)} items]\n"
                result += self.print_table(data, max_rows=10)
                return result  # Already printed by print_table
            else:
                result = f"[{len(data)} items]: " + ", ".join(str(x) for x in data[:10])
                if len(data) > 10:
                    result += f" ... (+{len(data) - 10} more)"
        else:
            result = str(data)

        print(result)
        return result
