# Binary Ninja Code Mode MCP

A Model Context Protocol (MCP) server for [Binary Ninja](https://binary.ninja/) that enables LLM-assisted reverse engineering through code execution.

## Overview

Instead of exposing discrete tools to the LLM, this server implements 
[Anthropic's Code Execution pattern](https://www.anthropic.com/engineering/code-execution-with-mcp):
the LLM writes Python code that executes against Binary Ninja's API.

Cloudflare published a [blog post](https://blog.cloudflare.com/code-mode/) referring to their implementation as "Code Mode" hence the naming for this plugin.

According to Anthropic and Cloudflare, this approach is more token and context efficient and allows complex multi-step analyses in a single execution. I haven't benchmarked this myself, but it does feel more intuitive to write code than to issue discrete commands.

## Features

- **Code Execution**: Write Python that runs directly against Binary Ninja's API
- **BINJA API Functions**: Query and mutate the binary database
- **State Management**: Checkpoints and rollback available from the MCP client
- **Workspace Files**: Persist intermediate results across executions
- **Reusable Skills**: Save and load analysis code patterns
- **Security**: Basic checks with API key authentication and some code validation

## Installation

### Binary Ninja Plugin

Copy to your Binary Ninja [plugins](https://docs.binary.ninja/guide/plugins.html) folder:

```bash
# Linux
cp -r plugin/ ~/.binaryninja/plugins/binja_codemode_mcp/

# macOS
cp -r plugin/ ~/Library/Application\ Support/Binary\ Ninja/plugins/binja_codemode_mcp/

# Windows
copy plugin\ %APPDATA%\Binary Ninja\plugins\binja_codemode_mcp\
```

### MCP Bridge Configuration (Quick Setup)

Configure [Zed](https://zed.dev/)'s Custom MCP Server (`Agent Panel > ... > Add Custom Server...`):

```json
{
  /// The name of your MCP server
  "binja-codemode-mcp": {
    /// The command which runs the MCP server
    "command": "python3",
    /// The arguments to pass to the MCP server
    "args": ["~/.binaryninja/plugins/binja_codemode_mcp/bridge/mcp_bridge.py"],
    /// The environment variables to set
    "env": {
      "BINJA_MCP_URL": "http://127.0.0.1:42069",
      "BINJA_MCP_KEY": "binja-codemode-local"
    }
  }
}
```

Configure [Claude Desktop](https://www.claude.com/download) (`Settings > Developer > Edit Config`):

```json
{
  "mcpServers": {
    "binja-codemode-mcp": {
      "command": "python3",
      "args": ["~/Library/Application Support/Binary Ninja/plugins/binja_codemode_mcp/bridge/mcp_bridge.py"],
      "env": {
        "BINJA_MCP_URL": "http://127.0.0.1:42069",
        "BINJA_MCP_KEY": "binja-codemode-local"
      }
    }
  }
}
```

If running `bridge/mcp_bridge.py` directly (e.g., from the commandline instead of an MCP client), you will see some logging. These log messages are explicitly printed on `stderr` since the MCP bridge uses `stdout` for communication.

To change the logging output level, set the environment variable `BINJA_MCP_LOG_LEVEL` to one of: `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`.

Example:
```bash
# Enable debug logging
export BINJA_MCP_LOG_LEVEL=DEBUG

# Or just info (default)
export BINJA_MCP_LOG_LEVEL=INFO

# Or warnings only
export BINJA_MCP_LOG_LEVEL=WARNING
```

### MCP Bridge Configuration (Custom API Key)

If you want a custom API key, create `~/.binaryninja/codemode_mcp/config.json`:

```json
{
  "api_key": "your-custom-key"
}
```

Then set the same key in your MCP client:

```json
{
  /// The name of your MCP server
  "binja-codemode-mcp": {
    /// The command which runs the MCP server
    "command": "python3",
    /// The arguments to pass to the MCP server
    "args": ["~/.binaryninja/plugins/binja_codemode_mcp/bridge/mcp_bridge.py"],
    /// The environment variables to set
    "env": {
      "BINJA_MCP_URL": "http://127.0.0.1:42069",
      "BINJA_MCP_KEY": "your-custom-key"
    }
  }
}
```

## Usage

1. Open Binary Ninja and load a binary
2. Start the server: `Plugins > MCP Code Mode > Start Server`
3. Start prompting!

### Example Prompts
```
"List all functions that reference memcpy and check if they validate sizes"

"Decompile the main function and identify potential buffer overflows"

"Create a checkpoint, then rename all sub_* functions based on their behavior"

"Find all string references and categorize them by type"
```

## API Overview

### Query
**Binary Info**
- `binja.get_binary_status()` - Binary metadata
- `binja.list_functions()` - All functions
- `binja.analyze_function_batch()` - Batched function alaysis
- `binja.list_imports()` - Imported symbols
- `binja.list_exports()` - Exported symbols
- `binja.list_segments()` - Memory segments
- `binja.list_classes()` - Classes
- `binja.list_namespaces()` - Namespaces
- `binja.list_data_items()` - Data items

**Code Analysis**
- `binja.decompile()` - Get pseudocode
- `binja.get_assembly()` - Get disassembly
- `binja.get_basic_blocks()` - Basic function info

**Cross References**
- `binja.get_xrefs_to()` - Find callers
- `binja.get_function_calls()` - Find callees
- `binja.get_data_xrefs_to()` - Data references to address
- `binja.get_data_xrefs_from()` - Data references from address

**Data Reading**
- `binja.read_bytes()` - Read raw bytes
- `binja.read_string()` - Read string
- `binja.get_string_at()` - Get string info
- `binja.get_data_var_at()` - Get data variable info
- `binja.list_strings()` - List all strings

**Search & Lookup**
- `binja.find_bytes()` - Search for byte pattern
- `binja.function_at()` - Get function by address or name
- `binja.get_comment()` - Get comment
- `binja.get_function_comment()` - Get function comment
- `binja.get_type()` - Get User-defined struct/type info

### Mutations

**Renaming**
- `binja.rename_function(func, name)` - Rename function
- `binja.rename_data()` - Rename data
- `binja.rename_variable(func, old, new)` - Rename variable

**Typing**
- `binja.retype_variable()` - Retype variable
- `binja.define_type()` - Define struct/type
- `binja.set_function_signature()` - Set prototype

**Comments**
- `binja.set_comment()` - Add comment
- `binja.set_function_comment()` - Add function comment
- `binja.delete_comment()` - Delete comment
- `binja.delete_function_comment()` - Delete function comment

### Workspace

**File Persistence**
- `binja.write_file()` - Save to workspace
- `binja.read_file()` - Read from workspace
- `binja.list_files()` - List workspace files
- `binja.delete_file()` - Delete workspace 

### Skills

**Reusable Code**
- `binja.save_skill(name, code, desc)` - Save reusable code
- `binja.load_skill(name)` - Load a skill
- `binja.list_skills()` - List saved skills
- `binja.delete_skill()` - Delete a skill

### Helpers
- `binja.find_functions_calling_unsafe()` - Find functions calling potentially unsafe functions
- `binja.get_function_complexity()` - Get cyclomatic complexity

## Security

A basic level of security in attempt to prevent some misuse:

- Binds to localhost only (127.0.0.1)
- Requires API key for all requests (can be set manually in `config.json`)
- Simple command validation blocks potentially dangerous operations
- Execution timeout (30s default)

## License

MIT License - see [LICENSE](LICENSE) for details.
