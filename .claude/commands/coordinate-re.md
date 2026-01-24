# Coordinate Reverse Engineering

You are orchestrating a multi-agent reverse engineering effort.

## Target
$ARGUMENTS

## Workflow

### Phase 1: Triage
For each target binary, spawn a parallel agent to perform quick triage:

```
Task(
    subagent_type="general-purpose",
    description="Triage {binary_name}",
    prompt="""Triage this binary using Binary Ninja MCP.

1. Load the binary with mcp__binja-codemode-mcp__load_binary
2. Run: summary = binja.get_triage_summary()
3. Report:
   - What is this binary? (daemon, CLI tool, library?)
   - Key imports by category (network, file, memory, crypto)
   - Top 5 complex functions worth analyzing
   - Recommended focus areas

Target: {binary_path}
""",
    allowed_tools=["mcp__binja-codemode-mcp__load_binary", "mcp__binja-codemode-mcp__execute"]
)
```

### Phase 2: Deep Analysis
Based on triage results, spawn analyzer agents for high-value functions:

```
Task(
    subagent_type="general-purpose",
    description="Analyze {function_name}",
    prompt="""Deeply analyze this function and propose annotations.

1. Load binary and decompile the target function
2. Understand what it does - trace data flow, identify purpose
3. Propose meaningful names for the function and its variables
4. Write annotation proposals as JSON:

{
  "annotations": [
    {"type": "rename_function", "address": "0x...", "proposed_name": "...", "confidence": "high", "reason": "..."},
    {"type": "comment", "address": "0x...", "comment": "..."}
  ]
}

Save with: binja.write_file("annotations_{func}.json", json.dumps(data))

Target binary: {binary_path}
Target function: {function_addr}
""",
    allowed_tools=["mcp__binja-codemode-mcp__load_binary", "mcp__binja-codemode-mcp__execute"]
)
```

### Phase 3: Apply & Document
After analysis completes:
1. Review annotation proposals from workspace files
2. Apply approved annotations: `binja.apply_annotations("file.json")`
3. Generate summary documentation

## Instructions

1. Parse the targets from $ARGUMENTS (can be paths, globs, or descriptions)
2. Spawn triage agents in parallel for all targets
3. Review triage results and identify high-value analysis targets
4. Spawn analyzer agents for interesting functions
5. Review and apply annotations
6. Report findings

Use `mcp__binja-codemode-mcp__*` tools for all Binary Ninja operations.
