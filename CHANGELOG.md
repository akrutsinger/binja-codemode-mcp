# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The API reference the LLM reads is now generated from `BinjaAPI` by introspection and delivered
  in the `execute` tool description, where it is always in context. Previously it was hand-written
  in `stubs.py` and offered as an MCP resource that most clients never read. Adding a method to
  `BinjaAPI` now advertises it automatically, and signatures cannot drift from the code
- Output is now capped on a token budget (`max_output_tokens`, default 6,000) rather than
  `max_output_bytes` (100,000, roughly 25,000 tokens). An over-budget result says what the whole
  result would have cost and how to narrow it, instead of just "(output truncated)"
- `print()` no longer stamps `[0.0s]` on every line, which taxed every printed row
- The MCP bridge fetches its tool definitions and version from the plugin rather than hardcoding
  them, so the plugin is the only place a tool is defined. With Binary Ninja not running, the
  bridge advertises `execute` with a description saying how to start the server

### Added

- The value of a trailing bare expression is returned alongside anything printed, so a result no
  longer has to be wrapped in `print()`
- `bv` and `bn` are now in scope for executed code, alongside `binja` - the raw `BinaryView` and
  the `binaryninja` module. The wrapper methods are a convenience layer, not a limit
- `list_methods()` - Re-emit the API reference from inside the execution namespace, for when the
  tool description reaches the model truncated
- `search_decompiled()` - Search for patterns in HLIL decompiled code with regex support
- `get_control_flow_graph()` - Export CFG structure with nodes and edges for graph analysis
- `get_all_xrefs()` - Unified view of all code/data cross-references to/from an address
- `find_xref_chains()` - BFS-based call chain discovery between two functions
- `bulk_rename()` - Batch rename multiple functions/data items
- `batch_set_types()` - Apply multiple type changes atomically
- `patch_bytes()` - Patch bytes at address with original/patched byte tracking
- `nop_range()` - NOP out instruction ranges
- `assemble_at()` - Assemble instructions and patch in-place

### Removed

- The AST validator that rejected imports of `os`, `sys` and friends, and the "safe builtins"
  allowlist. Neither was a security boundary: `exec()` with a globals dict that has no
  `__builtins__` key gets the real builtins module injected by CPython, so `open()` and every
  import already worked, and the AST check was syntax-only (`getattr(f, "__globals__")` walked
  straight past it). The code runs in Binary Ninja's process with its privileges; localhost
  binding and the API key are the boundary, and the docs now say so

### Fixed

- `set_function_signature()` now correctly validates parsed types with explicit None check
- `find_bytes()` and `list_strings()` now default their optional arguments, matching how they have
  always been documented. `find_bytes(b"\x90")` and `list_strings()` previously raised `TypeError`
- `get_all_xrefs()` documented its result keys as `to`/`from`; they are `xrefs_to`/`xrefs_from`
- `analyze_functions_batch()` returns a `next_offset` key that was undocumented
- Functions defined by executed code could not see variables that code had assigned, raising
  `NameError`. Globals and locals were separate dicts, so a function body resolving a global
  never found names bound at the top level of the submitted script
- The status widget's headless guard caught only `ImportError`, but `binaryninjaui` raises
  `UIPluginInHeadlessError`, so importing the plugin outside the GUI crashed

## [0.1.3] - 2026-01-08

### Added

- Status indicator for MCP server running state

### Fixed

- Plugin not running properly in headless mode

## [0.1.2] - 2025-12-18

### Added

- This changelog

### Changed

- Cleaned up the README and included community plugin installation information

### Fixed

- Fix `mcp_bridge.py` variables to initialize before use

## [0.1.1] - 2025-12-09

### Fixed

- Update `plugin.json` with correct key name so Vector35's `generate_plugininfo.py -v plugin.json` succeeds

## [0.1.0] - 2025-12-02

### Added

- Initial release
