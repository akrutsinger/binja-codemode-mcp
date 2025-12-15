# Binary Ninja Code Mode MCP

A Model Context Protocol (MCP) server for [Binary Ninja](https://binary.ninja/) that enables LLM-assisted reverse engineering through code execution.

## Overview

This plugin implements [Anthropic's Code Execution pattern](https://www.anthropic.com/engineering/code-execution-with-mcp). Instead of accessing the typical MCP "tools", the LLM writes Python code that executes directly against Binary Ninja's API. This approach ([described by Cloudflare as "Code Mode"](https://blog.cloudflare.com/code-mode/)) is more token-efficient and enables more complex multi-step analyses in a single execution.

## Key Features

- Write Python that runs directly against Binary Ninja's API
- Query and mutate the binary database
- Checkpoint/rollback, persistent workspace files, and reusable analysis patterns
- Basic security with API key authentication and some code validation

## Installation

### Method 1: Plugin Manager (Recommended)

1. In Binary Ninja, open the Plugin Manager (`Plugins > Manage Plugins`)
2. Search for `Code Mode MCP` or `binja_codemode_mcp`
3. Click `Install`
4. Restart Binary Ninja

After installation, the plugin will be located in the community [plugins](https://docs.binary.ninja/guide/plugins.html) folder:

```bash
# Linux
~/.binaryninja/plugins/repositories/community/plugins/akrutsinger_binja_codemode_mcp/

# macOS
~/Library/Application Support/Binary Ninja/plugins/repositories/community/plugins/akrutsinger_binja_codemode_mcp/

# Windows
%APPDATA%\Binary Ninja\plugins\repositories\community\plugins\akrutsinger_binja_codemode_mcp\
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

Configure your MCP client to communicate with the plugin. The path to `mcp_bridge.py` depends on your installation method.

### For Plugin Manager Installation 

[**Zed**](https://zed.dev/) (`Agent Panel > ... > Add Custom Server...`):
```json
{
  /// The name of your MCP server
  "binja-codemode-mcp": {
    /// The command which runs the MCP server
    "command": "python3",
    /// The arguments to pass to the MCP server
    "args": ["~/.binaryninja/plugins/repositories/community/plugins/akrutsinger_binja_codemode_mcp/bridge/mcp_bridge.py"],
    /// The environment variables to set
    "env": {
      "BINJA_MCP_URL": "http://127.0.0.1:42069",
      "BINJA_MCP_KEY": "binja-codemode-local"
    }
  }
}
```

[**Claude Desktop**](https://www.claude.com/download) (`Settings > Developer > Edit Config`):
```json
{
  "mcpServers": {
    "binja-codemode-mcp": {
      "command": "python3",
      "args": ["~/Library/Application Support/Binary Ninja/plugins/repositories/community/plugins/akrutsinger_binja_codemode_mcp/bridge/mcp_bridge.py"],
      "env": {
        "BINJA_MCP_URL": "http://127.0.0.1:42069",
        "BINJA_MCP_KEY": "binja-codemode-local"
      }
    }
  }
}
```

**Note:** Use absolute paths. Replace `~` with your home directory path if needed, and adjust for your OS.

### For Manual Installation

Use these paths instead:
- Linux: `~/.binaryninja/plugins/binja_codemode_mcp/bridge/mcp_bridge.py`
- macOS: `~/Library/Application Support/Binary Ninja/plugins/binja_codemode_mcp/bridge/mcp_bridge.py`
- Windows: `%APPDATA%\Binary Ninja\plugins\binja_codemode_mcp\bridge\mcp_bridge.py`

### Custom API Key (Optional)

To use a custom API key instead of the default API key, create `~/.binaryninja/codemode_mcp/config.json`:
```json
{
  "api_key": "your-custom-key"
}
```

Then update your MCP client config to use the same key in `BINJA_MCP_KEY`.

### Logging Configuration (Optional)

Set `BINJA_MCP_LOG_LEVEL` environment variable to control logging output (stderr):
```bash
# Options: DEBUG, INFO (default), WARNING, ERROR, CRITICAL
export BINJA_MCP_LOG_LEVEL=DEBUG
```

Or add to your MCP client config:
```json
"env": {
  "BINJA_MCP_URL": "http://127.0.0.1:42069",
  "BINJA_MCP_KEY": "binja-codemode-local",
  "BINJA_MCP_LOG_LEVEL": "DEBUG"
}
```

## Usage

1. Open Binary Ninja and load a binary
2. Start the server: `Plugins > MCP Code Mode > Start Server`
3. In your MCP client (Claude, Zed, etc.), start prompting!

### Example Prompts
```
"List all functions that reference memcpy and check if they validate buffer sizes"

"Decompile main() and identify potential security issues"

"Create a checkpoint, then rename all sub_* functions based on their behavior"

"Find and categhorize all string references by type (URL, file path, error message, etc.)"

"Analyze the binary's attack surface by examining input validation in network-facing functions"
```

## API Overview

The Python code written by the LLM has access to the `binja` object with these methods:

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

- Localhost-only binding (127.0.0.1)
- API key authentication required
- Simple code validation blocks potentially dangerous operations
- 30-second execution timeout

**Note:** This plugin does execute arbitrary Python code. Only use with trusted MCP clients and LLMs.

## License

MIT License - see [LICENSE](LICENSE) for details.
