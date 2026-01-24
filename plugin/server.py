"""HTTP server for MCP bridge communication with multi-agent session support."""

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any, Callable, Optional

if TYPE_CHECKING:
    from ..config import Config
    from .api import BinjaAPI
    from .executor import CodeExecutor
    from .sessions import SessionRegistry
    from .state import StateTracker
    from .workspace import SkillsManager, WorkspaceManager

from .sessions import DEFAULT_SESSION_ID


class MCPRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler for MCP bridge requests with session support."""

    # Legacy: Direct api/state/executor for single-binary mode (backward compat)
    api: Optional["BinjaAPI"] = None
    state: Optional["StateTracker"] = None
    executor: Optional["CodeExecutor"] = None

    # Shared resources
    workspace: Optional["WorkspaceManager"] = None
    skills: Optional["SkillsManager"] = None
    config: "Config"
    get_stubs: Optional[Callable[[], str]] = None

    # Session support
    session_registry: Optional["SessionRegistry"] = None

    # Callbacks
    on_request: Optional[Callable[[str, str, bool], None]] = None

    # Legacy: SessionManager for headless mode (will be replaced by session_registry)
    session_manager: Optional[Any] = None

    def log_message(self, format, *args):
        """Suppress default HTTP logging."""
        pass

    def _notify_request(self, is_error: bool = False):
        """Notify callback about this request."""
        if self.on_request:
            self.on_request(self.command, self.path, is_error)

    def _check_auth(self) -> bool:
        """Verify API key."""
        auth = self.headers.get("Authorization", "")
        return auth == f"Bearer {self.config.api_key}"

    def _get_session_id(self) -> str:
        """Extract session ID from headers or return default."""
        session_id = self.headers.get("X-Session-Id", "")
        return session_id if session_id else DEFAULT_SESSION_ID

    def _get_client_name(self) -> str:
        """Extract client name from headers."""
        return self.headers.get("X-Client-Name", "")

    def _get_workspace_dir(self) -> Optional[str]:
        """Extract workspace directory from headers."""
        return self.headers.get("X-Workspace-Dir")

    def _get_session_components(
        self,
    ) -> tuple[Optional["BinjaAPI"], Optional["StateTracker"], Optional["CodeExecutor"], str]:
        """Get session-aware components (api, state, executor, session_id).

        If session_registry is available, routes through session.
        Otherwise falls back to legacy direct api/state/executor.
        """
        session_id = self._get_session_id()
        client_name = self._get_client_name()

        if self.session_registry:
            # Ensure session exists (creates if needed)
            workspace_dir = self._get_workspace_dir()
            self.session_registry.get_or_create(session_id, client_name, workspace_dir)

            result = self.session_registry.get_session_components(session_id)
            if result:
                api, state, executor = result
                return api, state, executor, session_id
            # Session exists but no binary loaded
            return None, None, None, session_id

        # Legacy mode: use direct api/state/executor
        return self.api, self.state, self.executor, session_id

    def _send_json(self, data: dict, status: int = 200, session_id: Optional[str] = None):
        """Send JSON response with session header."""
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if session_id:
            self.send_header("X-Session-Id", session_id)
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, message: str, status: int = 400, session_id: Optional[str] = None):
        """Send error response."""
        self._send_json({"error": message}, status, session_id)

    def _read_json(self) -> dict | None:
        """Read JSON body."""
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            return json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return None

    def do_GET(self):
        """Handle GET requests."""
        if not self._check_auth():
            self._send_error("Unauthorized", 401)
            self._notify_request(is_error=True)
            return

        self._notify_request()
        session_id = self._get_session_id()
        api, state, executor, session_id = self._get_session_components()

        if self.path == "/status":
            if api:
                self._send_json(
                    {
                        "status": "running",
                        "binary": api.get_binary_status(),
                        "workspace_files": len(self.workspace.list()) if self.workspace else 0,
                        "skills_count": len(self.skills.list()) if self.skills else 0,
                        "session_id": session_id,
                    },
                    session_id=session_id,
                )
            else:
                self._send_json(
                    {
                        "status": "running",
                        "binary": None,
                        "message": "No binary loaded. Use /binary/load to load one.",
                        "session_id": session_id,
                    },
                    session_id=session_id,
                )

        elif self.path == "/stubs":
            if self.session_registry and api:
                # Generate stubs for session's active binary
                from stubs import generate_api_stubs
                session = self.session_registry.get(session_id)
                if session and session.active_binary:
                    components = session.get_components(session.active_binary)
                    if components:
                        stubs = generate_api_stubs(
                            api._bv, state, self.workspace, self.skills
                        )
                        self._send_json({"stubs": stubs}, session_id=session_id)
                        return
            # Fallback to legacy get_stubs
            if self.get_stubs:
                self._send_json({"stubs": self.get_stubs()}, session_id=session_id)
            else:
                self._send_json(
                    {"stubs": "No binary loaded. Load a binary first."},
                    session_id=session_id,
                )

        elif self.path == "/checkpoints":
            if state:
                self._send_json(
                    {"checkpoints": state.list_checkpoints()},
                    session_id=session_id,
                )
            else:
                self._send_json(
                    {"checkpoints": [], "message": "No binary loaded"},
                    session_id=session_id,
                )

        elif self.path == "/skills":
            if self.skills:
                self._send_json({"skills": self.skills.list()}, session_id=session_id)
            else:
                self._send_json({"skills": []}, session_id=session_id)

        elif self.path == "/files":
            if self.workspace:
                self._send_json({"files": self.workspace.list()}, session_id=session_id)
            else:
                self._send_json({"files": []}, session_id=session_id)

        elif self.path == "/binaries":
            # List loaded binaries for this session
            if self.session_registry:
                binaries = self.session_registry.get_binaries_info_for_session(session_id)
                self._send_json({"binaries": binaries}, session_id=session_id)
            elif self.session_manager:
                # Legacy headless mode
                self._send_json(
                    {"binaries": self.session_manager.get_binaries_info()},
                    session_id=session_id,
                )
            elif api:
                # Single binary mode
                self._send_json(
                    {
                        "binaries": [
                            {
                                "path": str(api._bv.file.filename),
                                "name": api._bv.file.filename.split("/")[-1],
                                "active": True,
                                "architecture": api.get_binary_status().get(
                                    "architecture", "unknown"
                                ),
                                "function_count": api.get_binary_status().get(
                                    "function_count", 0
                                ),
                            }
                        ]
                    },
                    session_id=session_id,
                )
            else:
                self._send_json({"binaries": []}, session_id=session_id)

        elif self.path == "/sessions":
            # List all sessions (admin endpoint)
            if self.session_registry:
                self._send_json(
                    {"sessions": self.session_registry.list_sessions()},
                    session_id=session_id,
                )
            else:
                self._send_json(
                    {"sessions": [], "message": "Session management not enabled"},
                    session_id=session_id,
                )

        elif self.path.startswith("/session/"):
            # Get specific session info
            target_session_id = self.path[9:]  # Remove "/session/"
            if self.session_registry:
                session = self.session_registry.get(target_session_id)
                if session:
                    self._send_json(
                        {
                            "session_id": session.session_id,
                            "client_name": session.client_name,
                            "active_binary": str(session.active_binary)
                            if session.active_binary
                            else None,
                            "binary_count": len(session.binary_paths),
                            "created_at": session.created_at,
                            "last_active": session.last_active,
                        },
                        session_id=session_id,
                    )
                else:
                    self._send_error("Session not found", 404, session_id=session_id)
            else:
                self._send_error(
                    "Session management not enabled", 400, session_id=session_id
                )

        else:
            self._send_error("Not found", 404, session_id=session_id)

    def do_POST(self):
        """Handle POST requests."""
        if not self._check_auth():
            self._send_error("Unauthorized", 401)
            self._notify_request(is_error=True)
            return

        data = self._read_json()
        if data is None:
            self._send_error("Invalid JSON")
            self._notify_request(is_error=True)
            return

        self._notify_request()
        session_id = self._get_session_id()
        client_name = self._get_client_name()

        # Ensure session exists in registry
        if self.session_registry:
            self.session_registry.get_or_create(session_id, client_name)

        api, state, executor, session_id = self._get_session_components()

        if self.path == "/execute":
            if not executor:
                self._send_error(
                    "No binary loaded. Load a binary first.", 400, session_id=session_id
                )
                return

            code = data.get("code")
            if not code:
                self._send_error("Missing 'code' field", session_id=session_id)
                return

            result = executor.execute(code)
            self._send_json(
                {
                    "success": result.success,
                    "output": result.output,
                    "error": result.error,
                    "timed_out": result.timed_out,
                },
                session_id=session_id,
            )

        elif self.path == "/checkpoint":
            if not state:
                self._send_error(
                    "No binary loaded. Load a binary first.", 400, session_id=session_id
                )
                return

            name = data.get("name")
            if not name:
                self._send_error("Missing 'name' field", session_id=session_id)
                return

            success = state.create_checkpoint(name)
            self._send_json(
                {
                    "success": success,
                    "message": f"Checkpoint '{name}' created"
                    if success
                    else "Checkpoint already exists",
                },
                session_id=session_id,
            )

        elif self.path == "/rollback":
            if not state:
                self._send_error(
                    "No binary loaded. Load a binary first.", 400, session_id=session_id
                )
                return

            name = data.get("name")
            if not name:
                self._send_error("Missing 'name' field", session_id=session_id)
                return

            success = state.rollback(name)
            self._send_json(
                {
                    "success": success,
                    "message": f"Rolled back to '{name}'"
                    if success
                    else "Checkpoint not found",
                },
                session_id=session_id,
            )

        elif self.path == "/binary/load":
            # Load a binary for this session
            path = data.get("path")
            if not path:
                self._send_error("Missing 'path' field", session_id=session_id)
                return

            if self.session_registry:
                try:
                    result = self.session_registry.load_binary_for_session(
                        session_id, path
                    )
                    if result:
                        api, state, executor = result
                        self._send_json(
                            {
                                "success": True,
                                "message": f"Loaded {path}",
                                "binary": api.get_binary_status(),
                            },
                            session_id=session_id,
                        )
                    else:
                        self._send_error(
                            f"Failed to load binary: {path}",
                            400,
                            session_id=session_id,
                        )
                except Exception as e:
                    self._send_error(str(e), 400, session_id=session_id)

            elif self.session_manager:
                # Legacy headless mode
                try:
                    session = self.session_manager.load_binary(path)
                    if session:
                        self._send_json(
                            {
                                "success": True,
                                "message": f"Loaded {session.name}",
                                "binary": session.status,
                            },
                            session_id=session_id,
                        )
                    else:
                        self._send_json(
                            {
                                "success": True,
                                "message": f"Binary already loaded: {path}",
                            },
                            session_id=session_id,
                        )
                except Exception as e:
                    self._send_error(str(e), 400, session_id=session_id)
            else:
                self._send_error(
                    "Binary management only available in headless mode",
                    400,
                    session_id=session_id,
                )

        elif self.path == "/binary/switch":
            # Switch active binary for this session
            path = data.get("path")
            if not path:
                self._send_error("Missing 'path' field", session_id=session_id)
                return

            if self.session_registry:
                success = self.session_registry.switch_binary_for_session(
                    session_id, path
                )
                if success:
                    self._send_json(
                        {"success": True, "message": f"Switched to {path}"},
                        session_id=session_id,
                    )
                else:
                    self._send_error(
                        f"Binary not loaded in this session: {path}",
                        400,
                        session_id=session_id,
                    )

            elif self.session_manager:
                # Legacy headless mode
                success = self.session_manager.set_active(path)
                if success:
                    self._send_json(
                        {"success": True, "message": f"Switched to {path}"},
                        session_id=session_id,
                    )
                else:
                    self._send_error(
                        f"Binary not loaded: {path}", 400, session_id=session_id
                    )
            else:
                self._send_error(
                    "Binary management only available in headless mode",
                    400,
                    session_id=session_id,
                )

        elif self.path == "/binary/close":
            # Close a binary for this session
            path = data.get("path")

            if self.session_registry:
                success = self.session_registry.close_binary_for_session(
                    session_id, path
                )
                if success:
                    self._send_json(
                        {"success": True, "message": f"Closed {path or 'active binary'}"},
                        session_id=session_id,
                    )
                else:
                    self._send_error(
                        f"Binary not loaded in this session: {path or 'none active'}",
                        400,
                        session_id=session_id,
                    )

            elif self.session_manager:
                # Legacy headless mode
                if not path:
                    if not self.session_manager.active:
                        self._send_error(
                            "No active binary to close", 400, session_id=session_id
                        )
                        return
                    path = str(self.session_manager.active.path)

                success = self.session_manager.close_binary(path)
                if success:
                    self._send_json(
                        {"success": True, "message": f"Closed {path}"},
                        session_id=session_id,
                    )
                else:
                    self._send_error(
                        f"Binary not loaded: {path}", 400, session_id=session_id
                    )
            else:
                self._send_error(
                    "Binary management only available in headless mode",
                    400,
                    session_id=session_id,
                )

        else:
            self._send_error("Not found", 404, session_id=session_id)

    def do_DELETE(self):
        """Handle DELETE requests."""
        if not self._check_auth():
            self._send_error("Unauthorized", 401)
            self._notify_request(is_error=True)
            return

        self._notify_request()
        session_id = self._get_session_id()

        # Match /session/{id} pattern
        match = re.match(r"^/session/(.+)$", self.path)
        if match:
            target_session_id = match.group(1)

            if self.session_registry:
                success = self.session_registry.close_session(target_session_id)
                if success:
                    self._send_json(
                        {
                            "success": True,
                            "message": f"Session '{target_session_id}' closed",
                        },
                        session_id=session_id,
                    )
                else:
                    self._send_error(
                        f"Session not found: {target_session_id}",
                        404,
                        session_id=session_id,
                    )
            else:
                self._send_error(
                    "Session management not enabled", 400, session_id=session_id
                )
        else:
            self._send_error("Not found", 404, session_id=session_id)


class MCPServer:
    """HTTP server for MCP bridge communication."""

    def __init__(
        self,
        config: "Config",
        api: Optional["BinjaAPI"] = None,
        state: Optional["StateTracker"] = None,
        executor: Optional["CodeExecutor"] = None,
        workspace: Optional["WorkspaceManager"] = None,
        skills: Optional["SkillsManager"] = None,
        get_stubs: Optional[Callable[[], str]] = None,
        session_registry: Optional["SessionRegistry"] = None,
    ):
        self.api = api
        self.state = state
        self.executor = executor
        self.workspace = workspace
        self.skills = skills
        self.config = config
        self.get_stubs = get_stubs
        self.session_registry = session_registry
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

        # Callbacks and legacy headless mode support
        self.on_request: Optional[Callable[[str, str, bool], None]] = None
        self.session_manager: Optional[Any] = None

    def start(self) -> str:
        """Start server in background thread. Returns URL."""
        # Configure handler
        MCPRequestHandler.api = self.api
        MCPRequestHandler.state = self.state
        MCPRequestHandler.executor = self.executor
        MCPRequestHandler.workspace = self.workspace
        MCPRequestHandler.skills = self.skills
        MCPRequestHandler.config = self.config
        MCPRequestHandler.get_stubs = self.get_stubs
        MCPRequestHandler.on_request = self.on_request
        MCPRequestHandler.session_manager = self.session_manager
        MCPRequestHandler.session_registry = self.session_registry

        self._server = HTTPServer(
            (self.config.host, self.config.port), MCPRequestHandler
        )

        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

        return f"http://{self.config.host}:{self.config.port}"

    def stop(self):
        """Stop the server."""
        if self._server:
            self._server.shutdown()
            self._server = None
            self._thread = None
