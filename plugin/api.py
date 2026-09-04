"""Binary Ninja API wrapper for LLM code execution."""

import re
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
        """Get current binary metadata.

        Returns:
            {filename, architecture, platform, entry_point, function_count, start, end}
        """
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
            [{name, address, size}, ...]
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

            results.append({"name": f.name, "address": f.start, "size": f.total_bytes})

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
            {functions, total_count, batch_size, offset, next_offset, has_more}
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
        """List imported symbols.

        Returns:
            [{name, address, namespace}, ...]
        """
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
        """List exported symbols.

        Returns:
            [{name, address}, ...]
        """
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
        """List memory segments.

        Returns:
            [{start, end, length, readable, writable, executable}, ...]
        """
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
        """List defined data labels.

        Returns:
            [{name, address}, ...]
        """
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

    def get_assembly(self, func: str | int) -> str | None:
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

    def get_xrefs_to(self, func: str | int) -> list[dict]:
        """Get cross-references to function (callers).

        Returns:
            [{from_function, from_address}, ...]
        """
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
        """Get data references to an address: the data that points at it.

        Code references are not included; get_all_xrefs() reports both.

        Returns:
            [{from_address, from_function}, ...]
        """
        results = []
        for ref in self._bv.get_data_refs(addr):
            source = self._bv.get_functions_containing(ref)
            results.append(
                {
                    "from_address": ref,
                    "from_function": source[0].name if source else None,
                }
            )
        return results

    def get_data_xrefs_from(self, addr: int) -> list[dict]:
        """Get data references from an address: what the data there points at.

        Returns:
            [{to_address}, ...]
        """
        return [{"to_address": ref} for ref in self._bv.get_data_refs_from(addr)]

    def get_all_xrefs(
        self, addr: int, include_data: bool = True, include_code: bool = True
    ) -> dict:
        """Get all cross-references (both code and data) to/from an address.

        Args:
            addr: Address to analyze
            include_data: Include data references (default: True)
            include_code: Include code references (default: True)

        Returns:
            {address, xrefs_to: [{type, from_address, from_function}], xrefs_from: [{type, to_address, to_function}]}
        """
        xrefs_to = []
        xrefs_from = []

        # Code that points at this address.
        if include_code:
            for ref in self._bv.get_code_refs(addr):
                caller = self._bv.get_functions_containing(ref.address)
                xrefs_to.append(
                    {
                        "type": "code",
                        "from_address": ref.address,
                        "from_function": caller[0].name if caller else None,
                    }
                )

        if include_data:
            # get_data_refs() points inward and get_data_refs_from() outward, so they belong in
            # different buckets.
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

    def find_xref_chains(
        self, from_addr: int, to_addr: int, max_depth: int = 5
    ) -> list[list[dict]]:
        """Find call chains between two addresses.

        Args:
            from_addr: Starting address/function
            to_addr: Target address/function
            max_depth: Maximum chain depth (default: 5)

        Returns:
            [[{function, address}, ...], ...]
        """
        # Get functions at addresses
        from_funcs = self._bv.get_functions_containing(from_addr)
        to_funcs = self._bv.get_functions_containing(to_addr)

        if not from_funcs or not to_funcs:
            return []

        start_func = from_funcs[0]
        target_func = to_funcs[0]

        # BFS to find paths
        chains = []
        visited = set()
        queue = [
            ([{"function": start_func.name, "address": start_func.start}], start_func)
        ]

        while queue and len(chains) < 100:  # Limit results
            path, current_func = queue.pop(0)

            if len(path) > max_depth:
                continue

            if current_func.start == target_func.start:
                chains.append(path)
                continue

            # Avoid cycles
            if current_func.start in visited:
                continue
            visited.add(current_func.start)

            # Explore callees
            for callee in current_func.callees:
                # Validate that the callee is actually a valid function This prevents Binary Ninja
                # warnings for invalid references (e.g., data misinterpreted as function pointers,
                # or addresses outside valid memory regions in bare metal firmware)
                if not self._bv.get_functions_containing(callee.start):
                    continue

                new_path = path + [{"function": callee.name, "address": callee.start}]
                queue.append((new_path, callee))

        return chains

    def function_at(self, addr: int | str) -> str | None:
        """Get function name containing address.

        Args:
            addr: Address as integer or hex string (e.g., 0x1000 or "0x1000")
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
        """Get data variable info at address.

        Returns:
            {address, type, name}
        """
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
        """Get list of functions called by this function.

        Returns:
            [{to_function, to_address}, ...]
        """
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
        """Get basic block info for function.

        Returns:
            [{start, end, length, instruction_count}, ...]
        """
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
        self,
        pattern: bytes,
        start: int | None = None,
        end: int | None = None,
        limit: int = 100,
    ) -> list[int]:
        """Search for byte pattern in binary.

        Args:
            pattern: Byte sequence to search for
            start: Start address (default: binary start)
            end: End address (default: binary end)
            limit: Maximum results to return (default: 100)
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
            [{address, value, length, type}, ...]
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

    def search_decompiled(
        self, pattern: str, regex: bool = False, limit: int | None = 100
    ) -> list[dict]:
        """Search for pattern in decompiled HLIL code across all functions.

        Args:
            pattern: Text pattern to search for
            regex: If True, treat pattern as regex (default: False)
            limit: Maximum results to return (default: 100, None = unlimited)

        Returns:
            [{function, address, line_number, matched_line}, ...]
        """
        import re as regex_module

        results = []
        pattern_lower = pattern.lower() if not regex else pattern

        try:
            compiled_pattern = (
                regex_module.compile(pattern, regex_module.IGNORECASE)
                if regex
                else None
            )
        except regex_module.error:
            return []

        for func in self._bv.functions:
            if not func.hlil:
                continue

            try:
                # Get HLIL lines
                for line_num, line in enumerate(func.hlil.root.lines, 1):
                    line_text = str(line)

                    # Check for match
                    matched = False
                    if regex and compiled_pattern:
                        matched = compiled_pattern.search(line_text) is not None
                    else:
                        matched = pattern_lower in line_text.lower()

                    if matched:
                        results.append(
                            {
                                "function": func.name,
                                "address": func.start,
                                "line_number": line_num,
                                "matched_line": line_text.strip(),
                            }
                        )

                        if limit is not None and len(results) >= limit:
                            return results
            except Exception:
                continue

        return results

    def get_control_flow_graph(self, func: str | int) -> dict | None:
        """Get control flow graph structure for function.

        Args:
            func: Function name or address

        Returns:
            {function, address, nodes: [{id, start, end, length}], edges: [{from_id, to_id, type}]}
        """
        f = self._resolve_function(func)
        if not f:
            return None

        nodes = []
        edges = []
        block_map = {}

        # Build nodes
        for idx, block in enumerate(f.basic_blocks):
            node_id = idx
            block_map[block.start] = node_id
            nodes.append(
                {
                    "id": node_id,
                    "start": block.start,
                    "end": block.end,
                    "length": block.length,
                }
            )

        # Build edges
        for block in f.basic_blocks:
            from_id = block_map[block.start]
            for edge in block.outgoing_edges:
                to_id = block_map.get(edge.target.start)
                if to_id is not None:
                    edge_type = str(edge.type).split(".")[-1].lower()
                    edges.append(
                        {"from_id": from_id, "to_id": to_id, "type": edge_type}
                    )

        return {
            "function": f.name,
            "address": f.start,
            "nodes": nodes,
            "edges": edges,
        }

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

    def bulk_rename(
        self, mapping: dict[str, str], target_type: str = "function"
    ) -> dict:
        """Rename multiple items at once.

        Args:
            mapping: Dict of {old_name: new_name}
            target_type: Type of items to rename - 'function' or 'data'. Variables are not
                         renameable in bulk: a variable name only identifies one inside a
                         function, so use rename_variable() per function.

        Returns:
            {success_count, failed: [{old_name, new_name, error}], total}
        """
        if target_type not in ("function", "data"):
            # Raised rather than reported per entry: the caller named a mode that does not
            # exist, so every entry would fail for the same reason.
            raise BinjaAPIError(
                f"unsupported target_type {target_type!r}; expected 'function' or 'data'"
            )

        results = {"success_count": 0, "failed": [], "total": len(mapping)}

        for old_name, new_name in mapping.items():
            try:
                if target_type == "function":
                    success = self.rename_function(old_name, new_name)
                else:
                    # Try to parse as address
                    try:
                        addr = (
                            int(old_name, 16)
                            if old_name.startswith("0x")
                            else int(old_name)
                        )
                        success = self.rename_data(addr, new_name)
                    except ValueError:
                        success = False

                if success:
                    results["success_count"] += 1
                else:
                    results["failed"].append(
                        {
                            "old_name": old_name,
                            "new_name": new_name,
                            "error": "Rename failed",
                        }
                    )
            except Exception as e:
                results["failed"].append(
                    {"old_name": old_name, "new_name": new_name, "error": str(e)}
                )

        return results

    def batch_set_types(self, updates: list[dict]) -> dict:
        """Apply multiple type changes at once.

        Args:
            updates: List of type updates, each dict should have:
                     {type: 'function'|'variable', target: str|int, signature|var_type: str, ...}

        Returns:
            {success_count, failed: [{update, error}], total}
        """
        results = {"success_count": 0, "failed": [], "total": len(updates)}

        for update in updates:
            try:
                update_type = update.get("type")
                target = update.get("target")

                if update_type == "function":
                    signature = update.get("signature")
                    if signature:
                        success = self.set_function_signature(target, signature)
                    else:
                        success = False
                elif update_type == "variable":
                    func = update.get("function")
                    var_name = update.get("variable")
                    var_type = update.get("var_type")
                    if func and var_name and var_type:
                        success = self.retype_variable(func, var_name, var_type)
                    else:
                        success = False
                else:
                    success = False

                if success:
                    results["success_count"] += 1
                else:
                    results["failed"].append(
                        {"update": update, "error": "Type update failed"}
                    )
            except Exception as e:
                results["failed"].append({"update": update, "error": str(e)})

        return results

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
        """Set function prototype.

        Args:
            func: Function name or address
            signature: Function signature string (e.g., "int foo(char* bar)")
        """
        f = self._resolve_function(func)
        if not f:
            return False

        try:
            # parse_type_string returns (Type, str) where str is the name or (None, error_string) on
            # failure
            parsed_type, type_name = self._bv.parse_type_string(signature)

            if parsed_type is not None:
                f.type = parsed_type
                self._state.record_change(f"signature on {f.name}: {signature}")
                return True
        except Exception:
            # If parsing fails entirely, fall through to False
            pass

        return False

    def patch_bytes(self, addr: int, data: bytes) -> dict:
        """Patch bytes at address in the binary.

        Args:
            addr: Address to patch
            data: Bytes to write

        Returns:
            {success, address, original_bytes, patched_bytes, length}, or {success: False, error, address}
        """
        try:
            original = self._bv.read(addr, len(data))
            if not original:
                return {
                    "success": False,
                    "error": f"Failed to read at {addr:#x}",
                    "address": addr,
                }

            # Perform the patch
            wrote = self._bv.write(addr, data)
            if wrote != len(data):
                return {
                    "success": False,
                    "error": f"Partial write: {wrote}/{len(data)} bytes",
                    "address": addr,
                }

            self._state.record_change(
                f"patch {len(data)} bytes at {addr:#x}: {data.hex()}"
            )

            return {
                "success": True,
                "address": addr,
                "original_bytes": original.hex(),
                "patched_bytes": data.hex(),
                "length": len(data),
            }
        except Exception as e:
            return {"success": False, "error": str(e), "address": addr}

    def nop_range(self, start: int, end: int) -> dict:
        """NOP out a range of instructions.

        Args:
            start: Start address
            end: End address (exclusive)

        Returns:
            patch_bytes shape plus {bytes_patched, start, end}
        """
        length = end - start
        if length <= 0:
            return {
                "success": False,
                "error": "Invalid range: end must be > start",
                "start": start,
                "end": end,
            }

        # Get architecture-appropriate NOP byte
        arch = self._bv.arch
        if arch:
            # x86/x64 NOP is 0x90
            if "x86" in arch.name.lower():
                nop_byte = b"\x90"
            # ARM NOP is typically mov r0, r0 (0x00 0x00 0xa0 0xe1) but use simple approach
            elif "arm" in arch.name.lower():
                nop_byte = b"\x00"
            else:
                nop_byte = b"\x00"
        else:
            nop_byte = b"\x00"

        nop_data = nop_byte * length
        result = self.patch_bytes(start, nop_data)

        if result["success"]:
            result["bytes_patched"] = length
            result["start"] = start
            result["end"] = end

        return result

    def assemble_at(self, addr: int, asm: str) -> dict:
        """Assemble instructions and patch at address.

        Args:
            addr: Address to patch
            asm: Assembly instruction(s) as string (e.g., "mov eax, 1; ret")

        Returns:
            patch_bytes shape plus {assembly, instructions}
        """
        try:
            arch = self._bv.arch
            if not arch:
                return {
                    "success": False,
                    "error": "No architecture available",
                    "address": addr,
                }

            # Assemble the instruction(s)
            # Note: arch.assemble() returns (bytes, error_msg) where:
            #   - On success: (bytes_object, None or '')
            #   - On failure: (None, error_code_int) or (empty_bytes, error_code)
            assembled_bytes, error_msg = arch.assemble(asm, addr)

            # Check if assembly produced valid bytes. assembled_bytes could be None, empty bytes, or
            # (incorrectly) an int
            if not assembled_bytes:
                error_detail = error_msg if error_msg else "Assembly produced no bytes"
                return {
                    "success": False,
                    "error": f"Assembly failed: {error_detail}",
                    "address": addr,
                    "assembly": asm,
                }

            # Patch the bytes
            patch_result = self.patch_bytes(addr, assembled_bytes)

            if patch_result["success"]:
                patch_result["assembly"] = asm
                patch_result["instructions"] = asm.split(";")

            return patch_result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "address": addr,
                "assembly": asm,
            }

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
        """List workspace files.

        Returns:
            [{name, size, modified}, ...]
        """
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
        """Load a skill.

        Returns:
            {name, description, code}
        """
        skill = self._skills.load(name)
        if skill:
            return {
                "name": skill.name,
                "description": skill.description,
                "code": skill.code,
            }
        return None

    def list_skills(self) -> list[dict]:
        """List available skills.

        Returns:
            [{name, description}, ...]
        """
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
            [{function_name, address, unsafe_calls}, ...]
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
            {name, address, size, basic_blocks, cyclomatic_complexity, callers_count, callees_count, instruction_count}
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
    # Discovery
    # =========================================================================

    def list_methods(self) -> str:
        """List every method callable here, with signatures and summaries."""
        from . import tools

        return tools.build_api_reference(tools.api_surface(self))

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
            if all(
                term in name.lower() or term in entry["summary"].lower() for term in terms
            )
        ]
        matches.sort(key=lambda entry: entry["name"])
        return matches[:limit]

    def describe(self, name: str) -> dict:
        """Full signature and docstring for one Binary Ninja API member.

        Returns:
            {name, kind, signature, doc}
        """
        members = _binaryninja_members()
        if name not in members:
            name = _resolve_member_name(name, members)
        return _describe_member(name, members[name], summary_only=False)


# Where search_api() and describe() look. Binary Ninja's API is large; these are the types the
# analysis code above actually threads through, plus the module's own top-level functions.
_DISCOVERY_ROOTS = (
    "BinaryView",
    "Function",
    "BasicBlock",
    "Type",
    "Symbol",
    "Architecture",
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


def _resolve_member_name(name: str, members: dict) -> str:
    """Accept a bare member name, so describe('get_functions_containing') works."""
    candidates = [key for key in members if key.split(".")[-1] == name]
    if len(candidates) == 1:
        return candidates[0]
    if candidates:
        raise BinjaAPIError(
            f"{name!r} exists on several types: {', '.join(sorted(candidates))}. "
            f"Pass the qualified name."
        )
    raise BinjaAPIError(
        f"No Binary Ninja API member named {name!r}. Use search_api() to find one."
    )
