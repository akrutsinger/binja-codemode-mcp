"""HTTP server for MCP bridge communication."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Callable

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

    def log_message(self, format, *args):
        """Suppress default HTTP logging."""
        pass

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
            return

        if self.path == "/status":
            self._send_json(
                {
                    "status": "running",
                    "binary": self.api.get_binary_status(),
                    "workspace_files": len(self.workspace.list()),
                    "skills_count": len(self.skills.list()),
                }
            )
        elif self.path == "/stubs":
            self._send_json({"stubs": self.get_stubs()})
        elif self.path == "/checkpoints":
            self._send_json({"checkpoints": self.state.list_checkpoints()})
        elif self.path == "/skills":
            self._send_json({"skills": self.skills.list()})
        elif self.path == "/files":
            self._send_json({"files": self.workspace.list()})
        else:
            self._send_error("Not found", 404)

    def do_POST(self):
        """Handle POST requests."""
        if not self._check_auth():
            self._send_error("Unauthorized", 401)
            return

        data = self._read_json()
        if data is None:
            self._send_error("Invalid JSON")
            return

        if self.path == "/execute":
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

        else:
            self._send_error("Not found", 404)


class MCPServer:
    """HTTP server for MCP bridge communication."""

    def __init__(
        self,
        api: "BinjaAPI",
        state: "StateTracker",
        executor: "CodeExecutor",
        workspace: "WorkspaceManager",
        skills: "SkillsManager",
        config: "Config",
        get_stubs: Callable[[], str],
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
