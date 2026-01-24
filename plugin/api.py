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
        exclude_sections: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """List functions with optional filtering and pagination.

        Args:
            limit: Maximum number of results (default: None = all)
            offset: Number of results to skip (default: 0)
            min_size: Minimum function size in bytes (default: None = no filter)
            max_size: Maximum function size in bytes (default: None = no filter)
            name_contains: Filter by name substring (default: None = no filter)
            has_calls_to: Filter to functions that call this function name (default: None = no filter)
            exclude_sections: List of section names to exclude (default: None)

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

            # Section filtering
            section_name = "N/A"
            sections = self._bv.get_sections_at(f.start)
            if sections:
                section_name = sections[0].name

            if exclude_sections and section_name in exclude_sections:
                continue

            results.append({
                "name": f.name,
                "address": f.start,
                "size": f.total_bytes,
                "section": section_name
            })

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
                results.append({"name": sym.name, "address": sym.address})

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
                "end": seg.end,
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
                }
            )
        return results

    def decompile(self, func: str | int, il_level: str = "hlil") -> str | None:
        """Decompile function to C-like pseudocode.

        Args:
            func: Function name or address
            il_level: IL level - "hlil" (high), "mlil" (medium), or "llil" (low)

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

        result = "\n".join(lines)

        return result

    def get_assembly(
        self, func: str | int, max_lines: int | None = None
    ) -> str | None:
        """Get disassembly for function.

        Args:
            func: Function name or address
            max_lines: Maximum number of instruction lines to return (default: all)
        """
        f = self._resolve_function(func)
        if not f:
            return None

        lines = []
        for block in f.basic_blocks:
            for instr in block.disassembly_text:
                text = "".join(t.text for t in instr.tokens)
                lines.append(f"{instr.address:#x}: {text}")
                if max_lines and len(lines) >= max_lines:
                    break
            if max_lines and len(lines) >= max_lines:
                break
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
                    }
                )
        return results

    def get_data_xrefs_from(self, addr: int) -> list[dict]:
        """Get data references from address."""
        results = []
        for ref in self._bv.get_data_refs(addr):
            results.append({"to_address": ref})
        return results

    def function_at(self, addr: int | str) -> str | None:
        """Get function name containing address.

        Args:
            addr: Address as integer or hex string (e.g., 0x1000 or "0x1000")

        Returns:
            Function name or None if not found
        """
        if isinstance(addr, str):
            try:
                addr = int(addr, 16) if addr.startswith("0x") else int(addr)
            except ValueError:
                return None

        funcs = self._bv.get_functions_containing(addr)
        return funcs[0].name if funcs else None

    def get_comment(self, addr: int) -> str | None:
        """Get comment at address."""
        return self._bv.get_comment_at(addr)

    def get_function_comment(self, func: str | int) -> str | None:
        """Get function-level comment."""
        f = self._resolve_function(func)
        return f.comment if f else None

    def get_type(self, name: str) -> str | None:
        """Get user-defined type definition.

        Args:
            name: Type name to look up

        Returns:
            Type definition string or None if not found

        Note:
            This only returns user-defined types. Built-in C types like
            'int', 'char', 'void' will return None. Use define_type() to
            create custom types first.
        """
        t = self._bv.get_type_by_name(name)
        return str(t) if t else None

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
        """Get list of functions called by this function."""
        f = self._resolve_function(func)
        if not f:
            return []

        results = []
        seen = set()

        # Use callees property (most reliable)
        for callee in f.callees:
            if callee.start not in seen:
                seen.add(callee.start)
                results.append({"to_function": callee.name, "to_address": callee.start})

        # Also check for unresolved calls
        if f.hlil:
            for block in f.hlil:
                for instr in block:
                    if hasattr(instr, "dest"):
                        # Handle direct calls
                        if hasattr(instr.dest, "constant"):
                            target_addr = instr.dest.constant
                            if target_addr not in seen:
                                seen.add(target_addr)
                                target_funcs = self._bv.get_functions_containing(
                                    target_addr
                                )
                                if target_funcs:
                                    results.append(
                                        {
                                            "to_function": target_funcs[0].name,
                                            "to_address": target_addr,
                                        }
                                    )
                                else:
                                    # Unresolved call - still report it
                                    results.append(
                                        {
                                            "to_function": f"sub_{target_addr:x}",
                                            "to_address": target_addr,
                                        }
                                    )

        return results

    def get_basic_blocks(self, func: str | int) -> list[dict]:
        """Get basic block info for function."""
        f = self._resolve_function(func)
        if not f:
            return []

        results = []
        for block in f.basic_blocks:
            results.append(
                {
                    "start": block.start,
                    "end": block.end,
                    "length": block.length,
                    "instruction_count": len(block),
                }
            )
        return results

    def find_bytes(
        self, pattern: bytes, start: int | None, end: int | None, limit: int = 100
    ) -> list[int]:
        """Search for byte pattern in binary. Returns list of addresses.

        Args:
            pattern: Byte sequence to search for
            start: Start address (default: binary start)
            end: End address (default: binary end)
            limit: Maximum results to return (default: 100)

        Returns:
            List of addresses where pattern was found (max 100 results)
        """
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
        self, limit: int | None = None, min_length: int = 4, offset: int = 0
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
    # RE Coordination Helpers
    # =========================================================================

    def init_coordination_workspace(self) -> dict[str, bool]:
        """Initialize workspace directory structure for coordinated RE.

        Creates:
            - triage/     : Quick scan results per binary
            - annotations/: Proposed renames, types, comments
            - types/      : Recovered data structures
            - docs/       : Human-readable documentation
            - tasks/      : Work queue for agents

        Returns:
            dict mapping directory names to creation success
        """
        dirs = ["triage", "annotations", "types", "docs", "tasks"]
        results = {}

        for d in dirs:
            # Create a .gitkeep file to establish the directory
            success = self._workspace.write(f"{d}/.gitkeep", "")
            results[d] = success

        # Initialize empty task queue
        import json
        task_queue = {
            "pending": [],
            "in_progress": [],
            "completed": []
        }
        self._workspace.write("tasks/queue.json", json.dumps(task_queue, indent=2))

        return results

    def apply_annotations(self, annotations_file: str, dry_run: bool = False) -> dict:
        """Apply annotations from a workspace file.

        Args:
            annotations_file: Path to annotations JSON file in workspace
            dry_run: If True, only validate without applying

        Returns:
            dict with 'applied', 'skipped', 'errors' lists
        """
        import json

        content = self._workspace.read(annotations_file)
        if not content:
            raise BinjaAPIError(f"Annotations file not found: {annotations_file}")

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise BinjaAPIError(f"Invalid JSON in annotations file: {e}")

        annotations = data.get("annotations", [])
        results = {"applied": [], "skipped": [], "errors": []}

        for ann in annotations:
            ann_type = ann.get("type")
            confidence = ann.get("confidence", "low")

            # Skip low confidence unless explicitly requested
            if confidence == "low":
                results["skipped"].append({
                    "annotation": ann,
                    "reason": "low confidence"
                })
                continue

            if dry_run:
                results["applied"].append({"annotation": ann, "dry_run": True})
                continue

            try:
                if ann_type == "rename_function":
                    addr = int(ann["address"], 16) if isinstance(ann["address"], str) else ann["address"]
                    new_name = ann["proposed_name"]
                    self.rename_function(addr, new_name)
                    results["applied"].append(ann)

                elif ann_type == "comment":
                    addr = int(ann["address"], 16) if isinstance(ann["address"], str) else ann["address"]
                    comment = ann["comment"]
                    self.set_comment(addr, comment)
                    results["applied"].append(ann)

                elif ann_type == "set_type":
                    # Type setting is more complex, skip for now
                    results["skipped"].append({
                        "annotation": ann,
                        "reason": "type setting not yet implemented"
                    })

                else:
                    results["skipped"].append({
                        "annotation": ann,
                        "reason": f"unknown annotation type: {ann_type}"
                    })

            except Exception as e:
                results["errors"].append({
                    "annotation": ann,
                    "error": str(e)
                })

        return results

    def get_triage_summary(self) -> dict:
        """Generate a quick triage summary of the current binary.

        Returns:
            dict with binary info, imports, exports, interesting functions
        """
        # Categorize imports
        imports_by_category = {
            "network": [],
            "file": [],
            "memory": [],
            "process": [],
            "crypto": [],
            "other": []
        }

        network_funcs = {"socket", "connect", "bind", "listen", "accept", "send", "recv",
                         "sendto", "recvfrom", "read", "write", "select", "poll", "epoll"}
        file_funcs = {"open", "close", "read", "write", "fopen", "fclose", "fread", "fwrite",
                      "stat", "fstat", "lstat", "access", "unlink", "mkdir", "rmdir"}
        memory_funcs = {"malloc", "free", "realloc", "calloc", "mmap", "munmap", "memcpy",
                        "memmove", "memset", "strcpy", "strncpy", "strcat", "sprintf"}
        process_funcs = {"fork", "exec", "system", "popen", "kill", "signal", "wait",
                         "pthread", "clone"}
        crypto_funcs = {"aes", "des", "rsa", "sha", "md5", "encrypt", "decrypt", "hash",
                        "hmac", "ssl", "tls", "crypto"}

        for sym in self._bv.get_symbols_of_type(0):  # ImportedFunctionSymbol
            name_lower = sym.name.lower()
            categorized = False

            for pattern in network_funcs:
                if pattern in name_lower:
                    imports_by_category["network"].append(sym.name)
                    categorized = True
                    break

            if not categorized:
                for pattern in file_funcs:
                    if pattern in name_lower:
                        imports_by_category["file"].append(sym.name)
                        categorized = True
                        break

            if not categorized:
                for pattern in memory_funcs:
                    if pattern in name_lower:
                        imports_by_category["memory"].append(sym.name)
                        categorized = True
                        break

            if not categorized:
                for pattern in process_funcs:
                    if pattern in name_lower:
                        imports_by_category["process"].append(sym.name)
                        categorized = True
                        break

            if not categorized:
                for pattern in crypto_funcs:
                    if pattern in name_lower:
                        imports_by_category["crypto"].append(sym.name)
                        categorized = True
                        break

            if not categorized:
                imports_by_category["other"].append(sym.name)

        # Find high-complexity functions
        complex_funcs = []
        for func in self._bv.functions:
            complexity = self.get_function_complexity(func.start)
            if complexity and complexity["cyclomatic_complexity"] > 10:
                complex_funcs.append({
                    "name": func.name,
                    "address": hex(func.start),
                    "complexity": complexity["cyclomatic_complexity"],
                    "basic_blocks": complexity["basic_blocks"]
                })

        complex_funcs.sort(key=lambda x: x["complexity"], reverse=True)

        return {
            "binary": self._bv.file.filename,
            "architecture": self._bv.arch.name if self._bv.arch else None,
            "platform": self._bv.platform.name if self._bv.platform else None,
            "entry_point": hex(self._bv.entry_point),
            "function_count": len(self._bv.functions),
            "imports_by_category": {k: v for k, v in imports_by_category.items() if v},
            "high_complexity_functions": complex_funcs[:20],
            "strings_count": len(list(self._bv.strings))
        }
