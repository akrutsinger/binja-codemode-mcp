"""Session manager for headless multi-binary support."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    import binaryninja


class BinaryLoadError(Exception):
    """Raised when a binary fails to load."""

    pass


@contextlib.contextmanager
def _suppress_output(enabled: bool = True):
    """Suppress stdout/stderr during Binary Ninja operations.

    Only works when enabled=True and not running under a TUI that captures stderr.
    """
    if not enabled:
        yield
        return

    # Save original file descriptors
    try:
        stdout_fd = sys.stdout.fileno()
        stderr_fd = sys.stderr.fileno()
    except (io.UnsupportedOperation, ValueError):
        # stdout/stderr may not have file descriptors (e.g., under TUI capture)
        yield
        return

    saved_stdout_fd = None
    saved_stderr_fd = None

    try:
        saved_stdout_fd = os.dup(stdout_fd)
        saved_stderr_fd = os.dup(stderr_fd)

        # Redirect to /dev/null
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, stdout_fd)
            os.dup2(devnull, stderr_fd)
        finally:
            os.close(devnull)
        yield
    finally:
        # Restore original file descriptors
        if saved_stdout_fd is not None:
            os.dup2(saved_stdout_fd, stdout_fd)
            os.close(saved_stdout_fd)
        if saved_stderr_fd is not None:
            os.dup2(saved_stderr_fd, stderr_fd)
            os.close(saved_stderr_fd)


def _import_plugin_module(name: str):
    """Import a module from plugin/ without triggering plugin/__init__.py (which imports UI)."""
    full_name = f"plugin.{name}"
    if full_name in sys.modules:
        return sys.modules[full_name]

    plugin_dir = Path(__file__).parent.parent / "plugin"

    # Ensure the 'plugin' package exists in sys.modules for relative imports to work
    if "plugin" not in sys.modules:
        import types
        plugin_pkg = types.ModuleType("plugin")
        plugin_pkg.__path__ = [str(plugin_dir)]
        plugin_pkg.__package__ = "plugin"
        sys.modules["plugin"] = plugin_pkg

    # Handle dependencies: server.py imports from .sessions
    if name == "server" and "plugin.sessions" not in sys.modules:
        _import_plugin_module("sessions")

    spec = importlib.util.spec_from_file_location(full_name, plugin_dir / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = module
    spec.loader.exec_module(module)

    # Also register on the package for attribute access
    setattr(sys.modules["plugin"], name, module)

    return module


@dataclass
class BinarySession:
    """Represents a loaded binary with its analysis components."""

    path: Path
    bv: "binaryninja.BinaryView"
    api: object  # BinjaAPI
    state: object  # StateTracker
    executor: object  # CodeExecutor

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def status(self) -> dict:
        return self.api.get_binary_status()


class SessionManager:
    """Manages multiple binary sessions and the MCP server.

    Supports two modes:
    - Legacy mode: Single-client, direct api/state/executor (TUI compatible)
    - Multi-agent mode: Concurrent sessions with isolated state via SessionRegistry
    """

    def __init__(self, config: Optional[object] = None, multi_agent: bool = False):
        # Lazy import to avoid loading binaryninja at import time
        from config import Config

        self.config = config if config is not None else Config()
        self.config.ensure_dirs()

        self._sessions: dict[str, BinarySession] = {}
        self._active_key: Optional[str] = None
        self._server: Optional[object] = None  # MCPServer

        # Multi-agent mode components
        self._multi_agent = multi_agent
        self._binary_pool: Optional[object] = None  # BinaryPool
        self._session_registry: Optional[object] = None  # SessionRegistry

        # Shared persistence managers (initialized lazily)
        self._workspace: Optional[object] = None
        self._skills: Optional[object] = None

        # Whether to suppress BN output (disable when using TUI which captures stderr)
        self.suppress_bn_output: bool = True

        # Event callbacks for TUI updates
        self.on_binary_loaded: Optional[Callable[[BinarySession], None]] = None
        self.on_binary_closed: Optional[Callable[[BinarySession], None]] = None
        self.on_active_changed: Optional[Callable[[BinarySession], None]] = None
        self.on_request: Optional[Callable[[str, str, bool], None]] = None
        self.on_server_changed: Optional[Callable[[bool], None]] = None
        self.on_bn_log: Optional[Callable[[str, str], None]] = None  # (message, level)
        self.on_operation: Optional[Callable[[str], None]] = None  # (description)
        self.on_session_created: Optional[Callable[[object], None]] = None  # (AgentSession)
        self.on_session_closed: Optional[Callable[[object], None]] = None  # (AgentSession)

    def _ensure_managers(self):
        """Ensure workspace and skills managers are initialized."""
        if self._workspace is None:
            workspace_mod = _import_plugin_module("workspace")
            self._workspace = workspace_mod.WorkspaceManager(self.config.workspace_dir)
            self._skills = workspace_mod.SkillsManager(self.config.skills_dir)

    def _ensure_multi_agent(self):
        """Initialize multi-agent mode components."""
        if not self._multi_agent:
            return

        if self._binary_pool is None:
            sessions_mod = _import_plugin_module("sessions")
            BinaryPool = sessions_mod.BinaryPool
            SessionRegistry = sessions_mod.SessionRegistry

            self._ensure_managers()

            self._binary_pool = BinaryPool(suppress_output=self.suppress_bn_output)

            # Wire callbacks
            if self.on_binary_loaded:
                def on_loaded(loaded):
                    # Create a minimal BinarySession for callback
                    session = BinarySession(
                        path=loaded.path,
                        bv=loaded.bv,
                        api=None,
                        state=None,
                        executor=None,
                    )
                    self.on_binary_loaded(session)
                self._binary_pool.on_binary_loaded = on_loaded

            if self.on_binary_closed:
                def on_closed(loaded):
                    session = BinarySession(
                        path=loaded.path,
                        bv=loaded.bv,
                        api=None,
                        state=None,
                        executor=None,
                    )
                    self.on_binary_closed(session)
                self._binary_pool.on_binary_closed = on_closed

            self._session_registry = SessionRegistry(
                binary_pool=self._binary_pool,
                workspace=self._workspace,
                skills=self._skills,
                config=self.config,
                session_timeout_s=self.config.session_timeout_s,
                max_sessions=self.config.max_sessions,
            )

            # Wire operation callback
            self._session_registry.on_operation = self._handle_operation

            # Wire session callbacks
            if self.on_session_created:
                self._session_registry.on_session_created = self.on_session_created
            if self.on_session_closed:
                self._session_registry.on_session_closed = self.on_session_closed

    def load_binary(self, path: str | Path) -> Optional[BinarySession]:
        """Load a binary file for analysis.

        Args:
            path: Path to the binary file to load.

        Returns:
            BinarySession for the loaded binary (returns existing session if already loaded).

        Raises:
            BinaryLoadError: If the file doesn't exist, isn't a file, or fails to load.
        """
        import binaryninja

        api_mod = _import_plugin_module("api")
        executor_mod = _import_plugin_module("executor")
        state_mod = _import_plugin_module("state")

        BinjaAPI = api_mod.BinjaAPI
        CodeExecutor = executor_mod.CodeExecutor
        StateTracker = state_mod.StateTracker

        # Validate and normalize path
        try:
            path = Path(path).expanduser().resolve()
        except (OSError, RuntimeError) as e:
            raise BinaryLoadError(f"Invalid path: {e}")

        key = str(path)

        if key in self._sessions:
            return self._sessions[key]

        # Check file exists and is a regular file
        if not path.exists():
            raise BinaryLoadError(f"File not found: {path}")
        if not path.is_file():
            raise BinaryLoadError(f"Not a file: {path}")

        # Load in headless mode with output suppressed (unless TUI captures it)
        try:
            with _suppress_output(self.suppress_bn_output):
                bv = binaryninja.load(str(path))
                if bv:
                    bv.update_analysis_and_wait()
        except Exception as e:
            raise BinaryLoadError(f"Binary Ninja error: {e}")

        if bv is None:
            raise BinaryLoadError(
                f"Unsupported binary format or architecture: {path.name}"
            )

        self._ensure_managers()

        # Create analysis components
        state = StateTracker(bv, self.config.enable_state_tracking)

        # Wire state operation callback to forward to TUI
        state.on_operation = self._handle_operation

        api = BinjaAPI(bv, state, self._workspace, self._skills)
        executor = CodeExecutor(
            api,
            max_output_bytes=self.config.max_output_bytes,
            timeout=self.config.execution_timeout_s,
        )

        session = BinarySession(
            path=path,
            bv=bv,
            api=api,
            state=state,
            executor=executor,
        )

        self._sessions[key] = session

        # Set as active if first binary (or always if loading via API)
        if self._active_key is None or self._server is not None:
            self._active_key = key
            # Update server in-place to avoid deadlock when called from request handler
            self._update_server_session()

        if self.on_binary_loaded:
            self.on_binary_loaded(session)

        return session

    def close_binary(self, path: str | Path) -> bool:
        """Close a loaded binary."""
        try:
            key = str(Path(path).resolve())
        except (OSError, RuntimeError):
            return False

        if key not in self._sessions:
            return False

        session = self._sessions.pop(key)
        with _suppress_output(self.suppress_bn_output):
            session.bv.file.close()

        # Switch active if needed
        if self._active_key == key:
            self._active_key = next(iter(self._sessions), None)
            # Update server in-place to avoid deadlock
            self._update_server_session()

        if self.on_binary_closed:
            self.on_binary_closed(session)

        return True

    def save_binary(self, path: str | Path) -> bool:
        """Save binary's database to a .bndb file alongside the original.

        Args:
            path: Path to the loaded binary.

        Returns:
            True if saved successfully, False otherwise.
        """
        key = str(Path(path).resolve())
        session = self._sessions.get(key)

        if not session:
            return False

        # If already a .bndb, save in place; otherwise create new .bndb
        if session.path.suffix.lower() == ".bndb":
            db_path = str(session.path)
        else:
            db_path = str(session.path) + ".bndb"

        try:
            return session.bv.create_database(db_path)
        except Exception:
            return False

    def save_binary_as(self, path: str | Path, dest: str | Path) -> bool:
        """Save binary's database to a specified location.

        Args:
            path: Path to the loaded binary.
            dest: Destination path for the .bndb file.

        Returns:
            True if saved successfully, False otherwise.
        """
        key = str(Path(path).resolve())
        session = self._sessions.get(key)

        if not session:
            return False

        dest_str = str(dest)
        if not dest_str.endswith(".bndb"):
            dest_str += ".bndb"

        try:
            return session.bv.create_database(dest_str)
        except Exception:
            return False

    def set_active(self, path: str | Path) -> bool:
        """Set the active binary for MCP operations."""
        key = str(Path(path).resolve())

        if key not in self._sessions:
            return False

        if self._active_key != key:
            self._active_key = key
            # Update server in-place to avoid deadlock
            self._update_server_session()

            if self.on_active_changed:
                self.on_active_changed(self._sessions[key])

        return True

    @property
    def active(self) -> Optional[BinarySession]:
        """Get the currently active session."""
        if self._active_key:
            return self._sessions.get(self._active_key)
        return None

    @property
    def sessions(self) -> list[BinarySession]:
        """Get all loaded sessions."""
        return list(self._sessions.values())

    def _update_server_session(self):
        """Update the running server's session components without restarting.

        This avoids deadlocks when called from within a request handler.
        """
        if not self._server:
            return

        from stubs import generate_api_stubs
        server_mod = _import_plugin_module("server")
        MCPRequestHandler = server_mod.MCPRequestHandler

        session = self._sessions.get(self._active_key) if self._active_key else None

        if session:
            def get_stubs():
                return generate_api_stubs(
                    session.bv, session.state, self._workspace, self._skills
                )

            # Update handler class attributes in-place
            MCPRequestHandler.api = session.api
            MCPRequestHandler.state = session.state
            MCPRequestHandler.executor = session.executor
            MCPRequestHandler.get_stubs = get_stubs

            # Also update the server instance
            self._server.api = session.api
            self._server.state = session.state
            self._server.executor = session.executor
            self._server.get_stubs = get_stubs
        else:
            MCPRequestHandler.api = None
            MCPRequestHandler.state = None
            MCPRequestHandler.executor = None
            MCPRequestHandler.get_stubs = None

            self._server.api = None
            self._server.state = None
            self._server.executor = None
            self._server.get_stubs = None

    def _restart_server(self):
        """Restart MCP server with current active binary (or no binary)."""
        server_mod = _import_plugin_module("server")
        MCPServer = server_mod.MCPServer

        from stubs import generate_api_stubs

        if self._server:
            self._server.stop()
            self._server = None

        # Multi-agent mode: use SessionRegistry
        if self._multi_agent:
            self._ensure_multi_agent()

            self._server = MCPServer(
                self.config,
                workspace=self._workspace,
                skills=self._skills,
                session_registry=self._session_registry,
            )

            # Wire up request callback
            self._server.on_request = self._handle_request

            self._server.start()

            if self.on_server_changed:
                self.on_server_changed(True)
            return

        # Legacy mode: direct api/state/executor
        session = self._sessions.get(self._active_key) if self._active_key else None

        if session:
            def get_stubs():
                return generate_api_stubs(
                    session.bv, session.state, self._workspace, self._skills
                )

            self._server = MCPServer(
                self.config,
                api=session.api,
                state=session.state,
                executor=session.executor,
                workspace=self._workspace,
                skills=self._skills,
                get_stubs=get_stubs,
            )
        else:
            # Start server with no binary - only binary management endpoints will work
            self._server = MCPServer(
                self.config,
                workspace=self._workspace,
                skills=self._skills,
            )

        # Wire up request callback
        self._server.on_request = self._handle_request

        # Wire up session manager for binary management (legacy mode)
        self._server.session_manager = self

        self._server.start()

        if self.on_server_changed:
            self.on_server_changed(True)

    def _handle_request(self, method: str, path: str, is_error: bool):
        """Forward request events to TUI."""
        if self.on_request:
            self.on_request(method, path, is_error)

    def _handle_operation(self, description: str):
        """Forward operation events to TUI."""
        if self.on_operation:
            self.on_operation(description)

    def start_server(self) -> str:
        """Start the MCP server (works with or without binaries loaded)."""
        self._restart_server()
        return f"http://{self.config.host}:{self.config.port}"

    def stop_server(self):
        """Stop the MCP server."""
        if self._server:
            self._server.stop()
            self._server = None

        if self.on_server_changed:
            self.on_server_changed(False)

    @property
    def server_running(self) -> bool:
        """Check if server is running."""
        return self._server is not None

    def get_binaries_info(self) -> list[dict]:
        """Get info about all loaded binaries for MCP."""
        result = []
        for session in self._sessions.values():
            status = session.status
            result.append({
                "path": str(session.path),
                "name": session.name,
                "active": session == self.active,
                "architecture": status.get("architecture", "unknown"),
                "function_count": status.get("function_count", 0),
            })
        return result

    @property
    def multi_agent_enabled(self) -> bool:
        """Check if multi-agent mode is enabled."""
        return self._multi_agent

    @property
    def binary_pool(self) -> Optional[object]:
        """Get the BinaryPool (multi-agent mode only)."""
        return self._binary_pool

    @property
    def session_registry(self) -> Optional[object]:
        """Get the SessionRegistry (multi-agent mode only)."""
        return self._session_registry

    def get_all_sessions_info(self) -> list[dict]:
        """Get info about all agent sessions (multi-agent mode only)."""
        if self._session_registry:
            return self._session_registry.list_sessions()
        return []

    def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions (multi-agent mode only).

        Returns:
            Number of sessions cleaned up
        """
        if self._session_registry:
            return self._session_registry.cleanup_expired()
        return 0
