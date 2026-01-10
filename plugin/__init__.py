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

    def _lazy_import(self):
        """Lazily import components to avoid loading at registration time."""
        if self._components is not None:
            return self._components

        from ..config import Config
        from ..stubs import generate_api_stubs
        from .api import BinjaAPI
        from .executor import CodeExecutor
        from .server import MCPServer
        from .state import StateTracker
        from .workspace import SkillsManager, WorkspaceManager

        self._components = {
            "BinjaAPI": BinjaAPI,
            "StateTracker": StateTracker,
            "CodeExecutor": CodeExecutor,
            "WorkspaceManager": WorkspaceManager,
            "SkillsManager": SkillsManager,
            "MCPServer": MCPServer,
            "Config": Config,
            "generate_api_stubs": generate_api_stubs,
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

            # Initialize components
            state = components["StateTracker"](bv, self._config.enable_state_tracking)
            workspace = components["WorkspaceManager"](self._config.workspace_dir)
            skills = components["SkillsManager"](self._config.skills_dir)
            api = components["BinjaAPI"](bv, state, workspace, skills)
            executor = components["CodeExecutor"](
                api,
                max_output_bytes=self._config.max_output_bytes,
                timeout=self._config.execution_timeout_s,
            )

            def get_stubs(self=None):
                return components["generate_api_stubs"](bv, state, workspace, skills)

            self._server = components["MCPServer"](
                self._config,
                api=api,
                state=state,
                executor=executor,
                workspace=workspace,
                skills=skills,
                get_stubs=get_stubs,
            )
            url = self._server.start()

            log_info("=" * 42)
            log_info("Code Mode MCP Server Started")
            log_info(f"  URL: {url}")
            log_info(f"  API Key: {self._config.api_key}")
            log_info("=" * 42)
            log_info("Configure your MCP client with the above credentials.")
            update_status(True)
        except Exception as e:
            log_error(f"Failed to start Code Mode MCP server: {e}")
            self._server = None
            self._config = None
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
        log_info(f"  URL: http://{self._config.host}:{self._config.port}")
        log_info(f"  Workspace: {self._config.workspace_dir}")
        log_info(f"  Skills: {self._config.skills_dir}")

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
