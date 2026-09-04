# Binary Ninja Code Mode MCP

A Model Context Protocol (MCP) server for [Binary Ninja](https://binary.ninja/) that enables LLM-assisted reverse engineering through code execution.

## Overview

This plugin implements [Anthropic's Code Execution pattern](https://www.anthropic.com/engineering/code-execution-with-mcp). Instead of accessing the typical MCP "tools", the LLM writes Python code that executes directly against Binary Ninja's API. This approach ([described by Cloudflare as "Code Mode"](https://blog.cloudflare.com/code-mode/)) is more token-efficient and enables more complex multi-step analyses in a single execution.

## Key Features

- Write Python that runs directly against Binary Ninja's API
- Query and mutate the binary database
- Checkpoint/rollback, persistent workspace files, and reusable analysis patterns
- The API reference is generated from the code and rides in the tool description, so the model
  always has it and it can never drift from what the plugin actually exposes
- `search_api()` and `describe()` read Binary Ninja's own API, so a missing wrapper method is
  something the model routes around rather than a dead end

## Installation

### Method 1: Plugin Manager (Recommended)

1. In Binary Ninja, open the Plugin Manager (`Plugins > Manage Plugins`)
2. Search for `Code Mode MCP` or `binja_codemode_mcp`
3. Click `Install`
4. Restart Binary Ninja

After installation, the plugin will be located in the community [plugins](https://docs.binary.ninja/guide/plugins.html) folder:

```bash
# Linux
~/.binaryninja/repositories/community/plugins/binja_codemode_mcp/

# macOS
~/Library/Application Support/Binary Ninja/repositories/community/plugins/binja_codemode_mcp/

# Windows
%APPDATA%\Binary Ninja\repositories\community\plugins\binja_codemode_mcp\
```

### Method 2: Manual Installation

Clone or download this repository and copy to your Binary Ninja [plugins](https://docs.binary.ninja/guide/plugins.html) folder:

```bash
# Linux
cp -r plugin/ ~/.binaryninja/plugins/binja_codemode_mcp/

# macOS
cp -r plugin/ ~/Library/Application\ Support/Binary\ Ninja/plugins/binja_codemode_mcp/

# Windows
copy plugin\ %APPDATA%\Binary Ninja\plugins\binja_codemode_mcp\
```

## MCP Client Configuration

The plugin serves MCP over HTTP at `http://127.0.0.1:42069/mcp`, authenticated with a bearer
token. There is no bridge script to launch, so the configuration no longer depends on where the
plugin was installed: point your client at the URL.

[**Claude Code**](https://claude.com/claude-code) — one command, no config file to edit:

```bash
claude mcp add binja-codemode-mcp -s user --transport http \
  http://127.0.0.1:42069/mcp \
  --header "Authorization: Bearer binja-codemode-local"
```

- `-s user` registers the server for every project. Omit it to scope the server to the current project only, or use `-s project` to write a shared `.mcp.json` you can commit.
- Verify with `claude mcp list`, or `/mcp` inside a session. Remove with `claude mcp remove binja-codemode-mcp`.

**Clients configured by JSON** (`.mcp.json`, Claude Desktop, Zed and others) take the same three
values. Check your client's docs for the exact key names; the shape is usually:

```json
{
  "mcpServers": {
    "binja-codemode-mcp": {
      "type": "http",
      "url": "http://127.0.0.1:42069/mcp",
      "headers": {
        "Authorization": "Bearer binja-codemode-local"
      }
    }
  }
}
```

**Clients that only speak stdio** can front the server with
[`mcp-remote`](https://www.npmjs.com/package/mcp-remote):

```json
{
  "mcpServers": {
    "binja-codemode-mcp": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote", "http://127.0.0.1:42069/mcp",
        "--header", "Authorization: Bearer binja-codemode-local"
      ]
    }
  }
}
```

### Custom API Key (Optional)

To use a custom API key instead of the default API key, create `~/.binaryninja/codemode_mcp/config.json`:

```json
{
  "api_key": "your-custom-key"
}
```

Then use the same key in your client's `Authorization: Bearer ...` header. `Plugins > Code Mode
MCP > Show API Key` prints the key the running server expects.

### Logging (Optional)

The server logs to Binary Ninja's own log window; there is no separate process to configure. Raise
Binary Ninja's log level to see more.

## Usage

1. Open Binary Ninja and load a binary
2. Start the server: `Plugins > MCP Code Mode > Start Server`
3. In your MCP client (Claude, Zed, etc.), start prompting!

Start the server before connecting the client. Clients ask for the tool list once, at startup, and
that response is what carries the API reference, so a client that connected first will not see the
binary or the methods until it reconnects.

### Example Prompts

```
"List all functions that reference memcpy and check if they validate buffer sizes"

"Decompile main() and identify potential security issues"

"Search all decompiled code for malloc calls without corresponding free"

"Find all call chains from main to a suspicious function at 0x401234"

"Create a checkpoint, then rename all sub_* functions based on their behavior"

"Get the control flow graph for the authentication function and identify loops"

"Patch the license check at 0x403000 to always return true"

"Find and categorize all string references by type (URL, file path, error message, etc.)"

"Analyze the binary's attack surface by examining input validation in network-facing functions"
```

## API Overview

Executed code has three names in scope: `binja` for the methods below, `bv` for the raw
`BinaryView`, and `bn` for the `binaryninja` module. The wrappers return plain JSON-friendly
values; anything they do not cover is reachable through `bv`, and `binja.search_api()` /
`binja.describe()` look it up in the Binary Ninja that is actually running.

<!-- BEGIN GENERATED API -->

_Generated by `scripts/generate_docs.py` from `plugin/api.py`._

### Query Operations (read-only)

- `binja.get_binary_status() -> dict[str, Any]` — Get current binary metadata. Returns {filename, architecture, platform, entry_point, function_count, start, end}
- `binja.list_functions(limit: int | None = None, min_size: int | None = None, max_size: int | None = None, name_contains: str | None = None, has_calls_to: str | None = None, offset: int = 0) -> list[dict[str, Any]]` — List functions with optional filtering and pagination. Returns [{name, address, size}, ...]
- `binja.analyze_functions_batch(batch_size: int = 100, offset: int = 0, include_calls: bool = False, include_xrefs: bool = False, min_size: int | None = None, max_size: int | None = None, name_contains: str | None = None, has_calls_to: str | None = None) -> dict` — Analyze functions in batches to avoid timeouts. Returns {functions, total_count, batch_size, offset, next_offset, has_more}
- `binja.list_imports(limit: int | None = None, offset: int = 0) -> list[dict]` — List imported symbols. Returns [{name, address, namespace}, ...]
- `binja.list_exports(limit: int | None = None, offset: int = 0) -> list[dict]` — List exported symbols. Returns [{name, address}, ...]
- `binja.list_segments(limit: int | None = None, offset: int = 0) -> list[dict]` — List memory segments. Returns [{start, end, length, readable, writable, executable}, ...]
- `binja.list_classes(limit: int | None = None, offset: int = 0) -> list[str]` — List class/namespace names.
- `binja.list_namespaces(limit: int | None = None, offset: int = 0) -> list[str]` — List non-global namespaces.
- `binja.list_data_items() -> list[dict]` — List defined data labels. Returns [{name, address}, ...]
- `binja.decompile(func: str | int, il_level: str = 'hlil') -> str | None` — Decompile function to C-like pseudocode.
- `binja.get_assembly(func: str | int) -> str | None` — Get disassembly for function.
- `binja.get_xrefs_to(func: str | int) -> list[dict]` — Get cross-references to function (callers). Returns [{from_function, from_address}, ...]
- `binja.get_data_xrefs_to(addr: int) -> list[dict]` — Get data references to an address: the data that points at it. Returns [{from_address, from_function}, ...]
- `binja.get_data_xrefs_from(addr: int) -> list[dict]` — Get data references from an address: what the data there points at. Returns [{to_address}, ...]
- `binja.get_all_xrefs(addr: int, include_data: bool = True, include_code: bool = True) -> dict` — Get all cross-references (both code and data) to/from an address. Returns {address, xrefs_to: [{type, from_address, from_function}], xrefs_from: [{type, to_address, to_function}]}
- `binja.find_xref_chains(from_addr: int, to_addr: int, max_depth: int = 5) -> list[list[dict]]` — Find call chains between two addresses. Returns [[{function, address}, ...], ...]
- `binja.function_at(addr: int | str) -> str | None` — Get function name containing address.
- `binja.get_comment(addr: int) -> str | None` — Get comment at address.
- `binja.get_function_comment(func: str | int) -> str | None` — Get function-level comment.
- `binja.get_type(name: str) -> str | None` — Get user-defined type definition.
- `binja.read_bytes(addr: int, length: int) -> bytes | None` — Read raw bytes from address.
- `binja.read_string(addr: int, max_length: int = 256) -> str | None` — Read null-terminated string from address.
- `binja.get_data_var_at(addr: int) -> dict | None` — Get data variable info at address. Returns {address, type, name}
- `binja.get_string_at(addr: int) -> str | None` — Get string defined at address (if any).
- `binja.get_function_calls(func: str | int) -> list[dict]` — Get list of functions called by this function. Returns [{to_function, to_address}, ...]
- `binja.get_basic_blocks(func: str | int) -> list[dict]` — Get basic block info for function. Returns [{start, end, length, instruction_count}, ...]
- `binja.find_bytes(pattern: bytes, start: int | None = None, end: int | None = None, limit: int = 100) -> list[int]` — Search for byte pattern in binary.
- `binja.list_strings(limit: int | None = None, min_length: int = 4, offset: int = 0) -> list[dict]` — List strings in binary with pagination. Returns [{address, value, length, type}, ...]
- `binja.search_decompiled(pattern: str, regex: bool = False, limit: int | None = 100) -> list[dict]` — Search for pattern in decompiled HLIL code across all functions. Returns [{function, address, line_number, matched_line}, ...]
- `binja.get_control_flow_graph(func: str | int) -> dict | None` — Get control flow graph structure for function. Returns {function, address, nodes: [{id, start, end, length}], edges: [{from_id, to_id, type}]}

### Mutation Operations (tracked)

- `binja.rename_function(func: str | int, new_name: str) -> bool` — Rename a function.
- `binja.rename_data(addr: int, new_name: str) -> bool` — Rename data label at address.
- `binja.rename_variable(func: str | int, old_name: str, new_name: str) -> bool` — Rename variable within function.
- `binja.retype_variable(func: str | int, var_name: str, new_type: str) -> bool` — Change variable type within function.
- `binja.set_comment(addr: int, comment: str) -> bool` — Set comment at address.
- `binja.set_function_comment(func: str | int, comment: str) -> bool` — Set function-level comment.
- `binja.delete_comment(addr: int) -> bool` — Delete comment at address.
- `binja.delete_function_comment(func: str | int) -> bool` — Delete function comment.
- `binja.bulk_rename(mapping: dict[str, str], target_type: str = 'function') -> dict` — Rename multiple items at once. Returns {success_count, failed: [{old_name, new_name, error}], total}
- `binja.batch_set_types(updates: list[dict]) -> dict` — Apply multiple type changes at once. Returns {success_count, failed: [{update, error}], total}
- `binja.define_type(c_definition: str) -> bool` — Define type from C syntax.
- `binja.set_function_signature(func: str | int, signature: str) -> bool` — Set function prototype.
- `binja.patch_bytes(addr: int, data: bytes) -> dict` — Patch bytes at address in the binary. Returns {success, address, original_bytes, patched_bytes, length}, or {success: False, error, address}
- `binja.nop_range(start: int, end: int) -> dict` — NOP out a range of instructions. Returns patch_bytes shape plus {bytes_patched, start, end}
- `binja.assemble_at(addr: int, asm: str) -> dict` — Assemble instructions and patch at address. Returns patch_bytes shape plus {assembly, instructions}

### Checkpoints

- `binja.checkpoint(name: str) -> bool` — Name the current state of the database so a later rollback can return to it. Returns True, or False if a checkpoint of that name already exists
- `binja.rollback(name: str) -> bool` — Undo every change made since the named checkpoint, discarding later checkpoints. Returns True, or False if no checkpoint of that name exists
- `binja.list_checkpoints() -> list[dict]` — List saved checkpoints, oldest first. Returns [{name, undo_depth}, ...]

### Workspace Operations

- `binja.write_file(name: str, content: str) -> bool` — Write content to workspace file.
- `binja.read_file(name: str) -> str | None` — Read content from workspace file.
- `binja.list_files() -> list[dict]` — List workspace files. Returns [{name, size, modified}, ...]
- `binja.delete_file(name: str) -> bool` — Delete a workspace file.

### Skills Operations

- `binja.save_skill(name: str, code: str, description: str) -> bool` — Save reusable analysis code as a skill.
- `binja.load_skill(name: str) -> dict | None` — Load a skill. Returns {name, description, code}
- `binja.list_skills() -> list[dict]` — List available skills. Returns [{name, description}, ...]
- `binja.delete_skill(name: str) -> bool` — Delete a skill.

### Common analysis patterns

- `binja.find_functions_calling_unsafe(unsafe_patterns: list[str] | None = None) -> list[dict[str, Any]]` — Find all functions calling potentially unsafe functions. Returns [{function_name, address, unsafe_calls}, ...]
- `binja.get_function_complexity(func: str | int) -> dict | None` — Get complexity metrics for a function. Returns {name, address, size, basic_blocks, cyclomatic_complexity, callers_count, callees_count, instruction_count}

### Discovery

- `binja.list_methods() -> str` — List every method callable here, with signatures and summaries.
- `binja.search_api(query: str, limit: int = 40) -> list[dict]` — Search Binary Ninja's own API by keyword, for what the methods above do not cover. Returns [{name, kind, signature, summary}, ...] where name is what describe() accepts
- `binja.describe(name: str) -> dict` — Full signature and docstring for one Binary Ninja API member. Returns {name, kind, signature, doc}

<!-- END GENERATED API -->

## Regenerating the docs

The API surface is a hand-written class, not something generated from a spec, but everything the
LLM and the README say about it is generated from that class. Nothing describing the API is
maintained by hand.

```sh
export PYTHONPATH=/path/to/binaryninja/python   # the dir holding the `binaryninja` module

python3 scripts/check_api.py --check   # every method documented? README current?
python3 scripts/generate_docs.py       # rewrite the README's API section
```

Adding a method to `BinjaAPI` is enough to advertise it: `check_api.py` will insist it carries a
docstring summary and, if it returns a dict, a `Returns:` line giving the shape, since both are
rendered verbatim into the tool description. Put it under an existing `# ===`-fenced section
comment and it is grouped automatically.

`check_api.py` also prints what the tool description costs, which is worth watching - it is in
the model's context on every request.

## Security

**The LLM's code runs inside Binary Ninja, unsandboxed, with the same access as Binary Ninja
itself.** It can read and write your files and reach the network. A plugin that takes no
dependencies has no way to sandbox Python, and `bv` alone reaches enough of the process that
restricting the rest would buy nothing, so the plugin does not pretend otherwise.

What actually limits exposure:

- The server binds to localhost (127.0.0.1) only
- Every request needs the API key, as an `Authorization: Bearer` header
- Requests carrying a non-localhost `Origin` are refused, so a web page cannot reach it
- Execution is capped at 30 seconds and output at ~6,000 tokens
- Mutations are tracked, so a checkpoint can be rolled back

Earlier versions advertised an AST validator that rejected `import os` and similar. It was not a
boundary: `exec()` with a globals dict lacking `__builtins__` gets the real builtins injected by
CPython, so `open()` and every import already worked, and the check matched syntax only. It has
been removed rather than left to imply protection it never gave.

Only point this at MCP clients and models you trust, and prefer working on a copy of any binary
you care about.

## License

[MIT](LICENSE)
