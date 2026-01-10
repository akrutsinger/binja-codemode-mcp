"""HTTP server for MCP bridge communication."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any, Callable, Optional

if TYPE_CHECKING:
    from ..config import Config
    from .api import BinjaAPI
    from .executor import CodeExecutor
    from .state import StateTracker
    from .workspace import SkillsManager, WorkspaceManager


class MCPRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler for MCP bridge requests."""

    # These are set by MCPServer before starting
    api: "BinjaAPI"
    state: "StateTracker"
    executor: "CodeExecutor"
    workspace: "WorkspaceManager"
    skills: "SkillsManager"
    config: "Config"
    get_stubs: Callable[[], str]
    on_request: Optional[Callable[[str, str, bool], None]] = None
    session_manager: Optional[Any] = None  # SessionManager for headless mode

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

    def _send_json(self, data: dict, status: int = 200):
        """Send JSON response."""
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, message: str, status: int = 400):
        """Send error response."""
        self._send_json({"error": message}, status)

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

        if self.path == "/status":
            if self.api:
                self._send_json(
                    {
                        "status": "running",
                        "binary": self.api.get_binary_status(),
                        "workspace_files": len(self.workspace.list()) if self.workspace else 0,
                        "skills_count": len(self.skills.list()) if self.skills else 0,
                    }
                )
            else:
                self._send_json(
                    {
                        "status": "running",
                        "binary": None,
                        "message": "No binary loaded. Use /binary/load to load one.",
                    }
                )
        elif self.path == "/stubs":
            if self.get_stubs:
                self._send_json({"stubs": self.get_stubs()})
            else:
                self._send_json({"stubs": "No binary loaded. Load a binary first."})
        elif self.path == "/checkpoints":
            if self.state:
                self._send_json({"checkpoints": self.state.list_checkpoints()})
            else:
                self._send_json({"checkpoints": [], "message": "No binary loaded"})
        elif self.path == "/skills":
            if self.skills:
                self._send_json({"skills": self.skills.list()})
            else:
                self._send_json({"skills": []})
        elif self.path == "/files":
            if self.workspace:
                self._send_json({"files": self.workspace.list()})
            else:
                self._send_json({"files": []})
        elif self.path == "/binaries":
            # List loaded binaries (headless mode only)
            if self.session_manager:
                self._send_json({"binaries": self.session_manager.get_binaries_info()})
            elif self.api:
                # Single binary mode - return current binary info
                self._send_json({
                    "binaries": [{
                        "path": str(self.api.bv.file.filename),
                        "name": self.api.bv.file.filename.split("/")[-1],
                        "active": True,
                        "architecture": self.api.get_binary_status().get("architecture", "unknown"),
                        "function_count": self.api.get_binary_status().get("function_count", 0),
                    }]
                })
            else:
                self._send_json({"binaries": []})
        else:
            self._send_error("Not found", 404)

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

        if self.path == "/execute":
            if not self.executor:
                self._send_error("No binary loaded. Load a binary first.", 400)
                return

            code = data.get("code")
            if not code:
                self._send_error("Missing 'code' field")
                return

            result = self.executor.execute(code)
            self._send_json(
                {
                    "success": result.success,
                    "output": result.output,
                    "error": result.error,
                    "timed_out": result.timed_out,
                }
            )

        elif self.path == "/checkpoint":
            if not self.state:
                self._send_error("No binary loaded. Load a binary first.", 400)
                return

            name = data.get("name")
            if not name:
                self._send_error("Missing 'name' field")
                return

            success = self.state.create_checkpoint(name)
            self._send_json(
                {
                    "success": success,
                    "message": f"Checkpoint '{name}' created"
                    if success
                    else "Checkpoint already exists",
                }
            )

        elif self.path == "/rollback":
            if not self.state:
                self._send_error("No binary loaded. Load a binary first.", 400)
                return

            name = data.get("name")
            if not name:
                self._send_error("Missing 'name' field")
                return

            success = self.state.rollback(name)
            self._send_json(
                {
                    "success": success,
                    "message": f"Rolled back to '{name}'"
                    if success
                    else "Checkpoint not found",
                }
            )

        elif self.path == "/binary/load":
            # Load a new binary (headless mode only)
            if not self.session_manager:
                self._send_error("Binary management only available in headless mode", 400)
                return

            path = data.get("path")
            if not path:
                self._send_error("Missing 'path' field")
                return

            try:
                session = self.session_manager.load_binary(path)
                if session:
                    self._send_json({
                        "success": True,
                        "message": f"Loaded {session.name}",
                        "binary": session.status,
                    })
                else:
                    # Already loaded - return existing session info
                    self._send_json({
                        "success": True,
                        "message": f"Binary already loaded: {path}",
                    })
            except Exception as e:
                self._send_error(str(e), 400)

        elif self.path == "/binary/switch":
            # Switch active binary (headless mode only)
            if not self.session_manager:
                self._send_error("Binary management only available in headless mode", 400)
                return

            path = data.get("path")
            if not path:
                self._send_error("Missing 'path' field")
                return

            success = self.session_manager.set_active(path)
            if success:
                self._send_json({
                    "success": True,
                    "message": f"Switched to {path}",
                })
            else:
                self._send_error(f"Binary not loaded: {path}", 400)

        elif self.path == "/binary/close":
            # Close a binary (headless mode only)
            if not self.session_manager:
                self._send_error("Binary management only available in headless mode", 400)
                return

            path = data.get("path")
            if not path:
                # Default to active binary if no path specified
                if not self.session_manager.active:
                    self._send_error("No active binary to close", 400)
                    return
                path = str(self.session_manager.active.path)

            success = self.session_manager.close_binary(path)
            if success:
                self._send_json({
                    "success": True,
                    "message": f"Closed {path}",
                })
            else:
                self._send_error(f"Binary not loaded: {path}", 400)

        else:
            self._send_error("Not found", 404)


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
    ):
        self.api = api
        self.state = state
        self.executor = executor
        self.workspace = workspace
        self.skills = skills
        self.config = config
        self.get_stubs = get_stubs
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

        # Callbacks and headless mode support
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
