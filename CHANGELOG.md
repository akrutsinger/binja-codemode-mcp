# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- There is one MCP tool, `execute`. `checkpoint` and `rollback` were separate tools; they are now
  `binja.checkpoint(name)` and `binja.rollback(name)`, callable from the code the model is already
  writing, alongside a new `binja.list_checkpoints()`. A code-mode server that also ships bespoke
  tools for individual operations is arguing with itself
- The plugin now speaks MCP directly over Streamable HTTP at `http://127.0.0.1:42069/mcp`, so
  there is no bridge process. Clients register the URL and a bearer token instead of a path to a
  script, which means the configuration no longer depends on how the plugin was installed. The
  plugin's own REST API (`/execute`, `/checkpoint`, `/rollback`, `/status`, `/tools`, `/skills`,
  `/files`, `/checkpoints`) is gone with it: there is one endpoint, and it speaks the protocol the
  client already speaks
- JSON-RPC handling gained what the bridge never had: protocol version negotiation, the specified
  error codes, notifications answered with `202` rather than a response, and a handler crash
  reported as `-32603` instead of taking the connection down
- Requests carrying a non-localhost `Origin` are refused, the DNS-rebinding guard the MCP spec
  asks of local servers. Clients send no `Origin` at all, so only a browser sees this
- The API reference the LLM reads is now generated from `BinjaAPI` by introspection and delivered
  in the `execute` tool description, where it is always in context. Previously it was hand-written
  in `stubs.py` and offered as an MCP resource that most clients never read. Adding a method to
  `BinjaAPI` now advertises it automatically, and signatures cannot drift from the code
- Output is now capped on a token budget (`max_output_tokens`, default 6,000) rather than
  `max_output_bytes` (100,000, roughly 25,000 tokens). An over-budget result says what the whole
  result would have cost and how to narrow it, instead of just "(output truncated)"
- `print()` no longer stamps `[0.0s]` on every line, which taxed every printed row

### Added

- `binja.checkpoint(name)`, `binja.rollback(name)` and `binja.list_checkpoints()` - checkpointing
  from inside executed code, so a script can take one before mutating and roll itself back
- `scripts/generate_docs.py` rewrites the README's API section from `plugin/api.py`, and
  `scripts/check_api.py` fails when a public method lacks a docstring summary or a documented
  return shape, or (with `--check`) when that README section is stale. Both run under Binary
  Ninja's Python and print the tool description's token cost, so growth stays visible
- The value of a trailing bare expression is returned alongside anything printed, so a result no
  longer has to be wrapped in `print()`
- `bv` and `bn` are now in scope for executed code, alongside `binja` - the raw `BinaryView` and
  the `binaryninja` module. The wrapper methods are a convenience layer, not a limit
- `search_api(query)` and `describe(name)` - Find and read Binary Ninja's own API by keyword,
  introspected from the installed module rather than a checked-in list, so they describe whichever
  version is running and never need regenerating. Together with `bv` they make a missing wrapper
  method something the model can route around instead of a dead end
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

- The four MCP resources (`binja://api-reference`, `status`, `skills`, `files`). Three restated
  what `binja.get_binary_status()`, `binja.list_skills()` and `binja.list_files()` already return,
  and the fourth restated the `execute` tool description that `binja.list_methods()` re-emits from
  inside the namespace. Most clients never read resources, and three ways to ask one question is
  two too many
- `StateTracker.record_change()` and the `pending_changes` list it fed. Twelve mutation methods
  appended a description apiece to produce one line of the tool description's header, and the
  count was wrong by construction: mutations made through `bv` directly never called it. The
  header now counts the undo stack, which sees every change however it was made
- `bridge/mcp_bridge.py`, and with it `BINJA_MCP_URL`, `BINJA_MCP_KEY` and `BINJA_MCP_LOG_LEVEL`.
  The bridge existed to translate stdio to HTTP because MCP had no HTTP transport when the plugin
  was written; it has had one since protocol 2025-03-26. Clients that still speak only stdio can
  front the server with `mcp-remote` (see the README)
- The placeholder `execute` tool the bridge advertised when Binary Ninja was not running. With no
  bridge process there is nothing to answer when the server is down, which is the honest signal
- The AST validator that rejected imports of `os`, `sys` and friends, and the "safe builtins"
  allowlist. Neither was a security boundary: `exec()` with a globals dict that has no
  `__builtins__` key gets the real builtins module injected by CPython, so `open()` and every
  import already worked, and the AST check was syntax-only (`getattr(f, "__globals__")` walked
  straight past it). The code runs in Binary Ninja's process with its privileges; localhost
  binding and the API key are the boundary, and the docs now say so

### Fixed

- Checkpoint and rollback never worked. `StateTracker` read the undo stack through
  `bv.undoable_actions()`, which is not a `BinaryView` method; `create_checkpoint()` swallowed the
  `AttributeError` and recorded a depth of 0 while reporting success, and `rollback()` swallowed
  the same error and reported "checkpoint not found". Both now read `bv.file.undo_entries`, and
  neither hides a failure to do so. Binary Ninja commits every API mutation as its own undo entry,
  so a rollback reverts changes made through `bv` directly as well as those made through `binja`
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
