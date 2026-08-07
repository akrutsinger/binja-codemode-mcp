# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] - 2026-08-07

### Added

- `binja.list_open_views()` to enumerate every binary open in the GUI tabs,
  returning filename, address range, function count, and which view the API is
  pinned to. Replaces the manual `UIContext` incantation agents previously had
  to paste to discover open binaries (distinct from `list_files()`, which lists
  workspace files).

### Fixed

- The `execute` sandbox no longer raises `NameError` for comprehensions,
  generator expressions, helper `def`s referencing top-level variables, and
  `import` statements used inside helpers. The root cause was a two-namespace
  `exec(code, globals, {})` that stranded top-level names in an isolated locals
  dict nested scopes couldn't see; switched to a single namespace.
- Tightened the sandbox by setting `__builtins__` to a curated dict. Previously
  `exec` silently injected the full builtins (including `open`, `eval`, `exec`,
  `__import__`) into globals, so the two-namespace form bought no security. The
  AST validator already blocked direct dangerous calls; this closes the
  reach-via-dict gap too. Legitimate `import struct` / `class` statements now
  work because the curated builtins include `__import__` and `__build_class__`.

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
