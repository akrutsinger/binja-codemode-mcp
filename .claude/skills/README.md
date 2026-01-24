# RE Coordination Skills

This directory contains skills for coordinated reverse engineering at scale.

## Quick Start

### 1. Initialize Workspace
```python
# In any agent session
binja.init_coordination_workspace()
```

This creates:
```
workspace/
├── triage/       # Quick scan results
├── annotations/  # Proposed changes
├── types/        # Recovered structs
├── docs/         # Documentation
└── tasks/        # Work queue
```

### 2. Triage a Binary
```python
# Get quick triage summary
summary = binja.get_triage_summary()
print(f"Binary: {summary['binary']}")
print(f"Functions: {summary['function_count']}")
print(f"Network imports: {summary['imports_by_category'].get('network', [])}")
print(f"Complex functions: {summary['high_complexity_functions'][:5]}")

# Save to workspace
import json
binary_name = Path(binja.filename).stem
binja.workspace.write(f"triage/{binary_name}.json", json.dumps(summary, indent=2))
```

### 3. Propose Annotations
Agents write proposals without applying directly:
```python
annotations = {
    "binary": binja.filename,
    "proposed_by": "analyzer-agent",
    "annotations": [
        {
            "type": "rename_function",
            "address": "0x401234",
            "proposed_name": "parse_request",
            "confidence": "high",
            "reason": "Parses HTTP request headers"
        }
    ]
}
binja.workspace.write("annotations/binary_parsing.json", json.dumps(annotations, indent=2))
```

### 4. Apply Approved Annotations
Coordinator reviews and applies:
```python
# Dry run first
results = binja.apply_annotations("annotations/binary_parsing.json", dry_run=True)
print(f"Would apply: {len(results['applied'])}")
print(f"Would skip: {len(results['skipped'])}")

# Apply for real
results = binja.apply_annotations("annotations/binary_parsing.json")
print(f"Applied: {len(results['applied'])}")
```

## Agent Roles

### Triage Agent (`prompts/triage-agent.md`)
- Quick assessment of binary purpose
- Identify attack surface and key functions
- Categorize functions by type

### Analyzer Agent (`prompts/analyzer-agent.md`)
- Deep dive on specific functions
- Propose meaningful names and comments
- Document what functions do

### Coordinator Agent (`prompts/coordinator-agent.md`)
- Orchestrate other agents
- Review and approve annotations
- Generate final documentation

## Workflow Example

```
User: "Reverse engineer these firmware binaries"

Coordinator:
  1. Spawn triage agents (parallel) for each binary
  2. Review triage results, identify high-value targets
  3. Spawn analyzer agents for interesting functions
  4. Review annotation proposals
  5. Apply approved changes
  6. Generate documentation
```

## API Reference

### `binja.init_coordination_workspace()`
Initialize the workspace directory structure.

### `binja.get_triage_summary()`
Quick triage of current binary - imports, complexity, function count.

### `binja.apply_annotations(file, dry_run=False)`
Apply annotations from a workspace JSON file. Only applies high/medium confidence.

### `binja.write_file(path, content)`
Write content to workspace file.

### `binja.read_file(path)`
Read content from workspace file.

### `binja.list_files()`
List all workspace files.

### `binja.get_binary_status()`
Get current binary metadata (use `['entry_point']` for entry point).
