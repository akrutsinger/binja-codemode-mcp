"""
BinjaCodeModeMCP - Main plugin class for Code Mode MCP Server.
"""

from binaryninja import PluginCommand
from binaryninja.log import log_debug, log_error, log_info

from .widget import update_status


class BinjaCodeModeMCP:
    """
    Code Mode MCP Server plugin for Binary Ninja.

    Provides an HTTP server that exposes Binary Ninja's API for
    LLM-assisted reverse engineering through code execution.
    """

    def __init__(self):
        self._config = None
        self._server = None
        self._components = None
        self._workspace_dir = None

    def _lazy_import(self):
        """Lazily import components to avoid loading at registration time."""
        if self._components is not None:
            return self._components

        from ..config import Config
        from . import tools
        from .api import BinjaAPI
        from .executor import CodeExecutor
        from .server import MCPServer
        from .workspace import SkillsManager, WorkspaceManager

        self._components = {
            "BinjaAPI": BinjaAPI,
            "CodeExecutor": CodeExecutor,
            "WorkspaceManager": WorkspaceManager,
            "SkillsManager": SkillsManager,
            "MCPServer": MCPServer,
            "Config": Config,
            "tools": tools,
        }
        return self._components

    def start_server(self, bv):
        """Start MCP server for current BinaryView."""
        try:
            # Require active BinaryView to start the server
            if bv is None:
                log_debug("No active BinaryView. Open a file to start the MCP server.")
                return

            if self._server is not None:
                log_error("Code Mode MCP server already running. Stop it first.")
                return

            components = self._lazy_import()

            self._config = components["Config"]()
            self._config.ensure_dirs()
            self._workspace_dir = self._config.workspace_dir_for(bv)

            # What the executed code gets as globals, and what the tool description is rendered
            # from. One mapping feeds both, so the two cannot disagree.
            namespaces = {
                "binja": components["BinjaAPI"](bv),
                "workspace": components["WorkspaceManager"](self._workspace_dir),
                "skills": components["SkillsManager"](self._config.skills_dir),
            }
            executor = components["CodeExecutor"](
                namespaces,
                bv,
                max_output_tokens=self._config.max_output_tokens,
                timeout=self._config.execution_timeout_s,
            )

            def get_tools():
                return [components["tools"].build_tool_definition(namespaces)]

            self._server = components["MCPServer"](executor, self._config, get_tools)
            url = self._server.start()

            log_info("=" * 42)
            log_info("Code Mode MCP Server Started")
            log_info(f"  URL: {url}")
            log_info(f"  Workspace: {self._workspace_dir}")
            self._report_unclaimed_workspace_files()
            log_info(f"  API Key: {self._config.api_key}")
            log_info("=" * 42)
            log_info("Register it with an MCP client that speaks HTTP, for example:")
            log_info(
                f"  claude mcp add binja-codemode-mcp -s user --transport http {url} "
                f'--header "Authorization: Bearer {self._config.api_key}"'
            )
            update_status(True)
        except Exception as e:
            log_error(f"Failed to start Code Mode MCP server: {e}")
            self._server = None
            self._config = None
            self._workspace_dir = None
            update_status(False)

    def stop_server(self, bv):
        """Stop MCP server."""
        try:
            if self._server is None:
                log_error("Code Mode MCP server is not running.")
                return

            self._server.stop()
            self._server = None
            self._config = None
            self._workspace_dir = None
            log_info("Code Mode MCP server stopped.")
            update_status(False)
        except Exception as e:
            log_error(f"Failed to stop Code Mode MCP server: {e}")

    def show_api_key(self, bv):
        """Display the current API key."""
        if self._config is None:
            log_error("Code Mode MCP server is not running.")
            return

        log_info(f"API Key: {self._config.api_key}")

    def show_status(self, bv):
        """Show server status."""
        if self._server is None:
            log_info("Code Mode MCP server: NOT RUNNING")
            return

        log_info("Code Mode MCP server: RUNNING")
        log_info(f"  URL: {self._server.url}")
        log_info(f"  Workspace: {self._workspace_dir}")
        log_info(f"  Skills: {self._config.skills_dir}")

    def _report_unclaimed_workspace_files(self) -> None:
        """Point at files left in the workspace root by the versions before it was per-binary.

        They are not deleted or moved: which binary each belongs to is not recoverable, and
        guessing wrong would file someone's report under the wrong binary. Naming the directory
        once at startup is enough for them to be moved by hand.
        """
        root = self._config.workspace_dir
        stranded = [path for path in root.iterdir() if path.is_file()] if root.is_dir() else []
        if stranded:
            log_info(
                f"  {len(stranded)} workspace file(s) predate per-binary workspaces and belong to "
                f"no binary: {root}. Move them into a binary's folder to use them."
            )

    @property
    def is_running(self) -> bool:
        """Check if server is currently running."""
        return self._server is not None

    def register_commands(self) -> None:
        """Register plugin commands with Binary Ninja."""
        PluginCommand.register(
            "Code Mode MCP\\Start Server",
            "Start Code Mode MCP server",
            self.start_server,
        )

        PluginCommand.register(
            "Code Mode MCP\\Stop Server",
            "Stop the Code Mode MCP server",
            self.stop_server,
        )

        PluginCommand.register(
            "Code Mode MCP\\Show API Key",
            "Display the current API key",
            self.show_api_key,
        )

        PluginCommand.register(
            "Code Mode MCP\\Show Status",
            "Show server status and configuration",
            self.show_status,
        )
