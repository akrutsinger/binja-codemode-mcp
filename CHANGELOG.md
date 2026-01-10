# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-01-10

### Added

- **Headless server mode** with Textual TUI for running without Binary Ninja GUI
- Multi-binary session management - load, switch between, and close multiple binaries
- New MCP tools: `load_binary`, `switch_binary`, `close_binary`
- New MCP resource: `binja://binaries` for listing loaded binaries
- Section filtering in `list_functions()` with `exclude_sections` parameter

### Changed

- MCPServer constructor now uses keyword arguments for optional components
- Server can start without a binary loaded (headless mode)

### Fixed

- File descriptor leak in output suppression context manager
- Missing thread ID initialization in TUI app
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
