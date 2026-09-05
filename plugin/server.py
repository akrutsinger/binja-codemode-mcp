"""MCP over Streamable HTTP: the transport loop and JSON-RPC dispatch.

Binary Ninja's API only exists inside Binary Ninja's own process, so the server has to run here.
Clients speak MCP to it directly over HTTP; there is no separate bridge process translating stdio
to a REST API of our own invention.

Connections are served on their own threads, but `execute` is serialised behind a lock. Executed
code mutates the BinaryView, so two overlapping executions must not race on the database - but
serialising the transport to achieve that, as this server used to, means one client holding an
idle keep-alive connection blocks every other client for as long as it stays connected. The
guarantee belongs on the execution, which is the thing that touches the database.
"""

import json
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from ..config import plugin_version
from . import tools

if TYPE_CHECKING:
    from ..config import Config
    from .executor import CodeExecutor

SERVER_INFO = {"name": "binja-codemode-mcp", "version": plugin_version()}

# Streamable HTTP arrived in 2025-03-26, so that is the oldest version reachable over this
# transport and the one to fall back on when a client asks for something we do not know.
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26")
DEFAULT_PROTOCOL_VERSION = "2025-03-26"

# JSON-RPC 2.0 error codes, per https://www.jsonrpc.org/specification#error_object
# Adding these manually so the plugin does not take a dependency just for the constants.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# How much longer than one execution's own budget to wait for the lock before giving up, so a
# queued caller outlasts a call that is timing out and being interrupted rather than failing
# alongside it.
LOCK_WAIT_MARGIN_S = 15.0


class JsonRpcError(Exception):
    """A handler failure that maps onto a JSON-RPC error response."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class MCPServer:
    """Serves MCP to any number of clients over Streamable HTTP."""

    def __init__(
        self,
        executor: "CodeExecutor",
        config: "Config",
        get_tools: Callable[[], list[dict]],
    ):
        self.executor = executor
        self.config = config
        self.get_tools = get_tools
        # One execution at a time. The transport no longer provides this, and the database needs
        # it: two scripts mutating the same BinaryView concurrently is the race the old
        # single-threaded server was really guarding against.
        self._execution_lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._handlers = {
            "initialize": self._initialize,
            "tools/list": self._tools_list,
            "tools/call": self._tools_call,
            "ping": lambda params: {},
        }

    #
    # Transport
    #
    def start(self) -> str:
        """Start the server in a background thread. Returns the client-facing URL."""
        self._server = _BoundHTTPServer((self.config.host, self.config.port), MCPRequestHandler)
        self._server.mcp = self
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def stop(self):
        """Stop the server."""
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
            self._thread = None

    @property
    def url(self) -> str:
        return f"http://{self.config.host}:{self.config.port}/mcp"

    def authorized(self, headers) -> bool:
        return headers.get("Authorization", "") == f"Bearer {self.config.api_key}"

    def same_origin(self, headers) -> bool:
        """Reject cross-origin requests, so a page in a browser cannot reach the server.

        A client that sends no Origin at all is not a browser, and every MCP client is in that
        group; the header only shows up on the attack this guards against.
        """
        origin = headers.get("Origin")
        if origin is None:
            return True
        return urlparse(origin).hostname in ("127.0.0.1", "localhost", "::1")

    #
    # JSON-RPC dispatch
    #
    def handle(self, payload: bytes) -> dict | None:
        """Dispatch one JSON-RPC message. Returns the response, or None for a notification."""
        try:
            request = json.loads(payload)
        except json.JSONDecodeError:
            return _error(None, PARSE_ERROR, "Parse error")

        if not isinstance(request, dict):
            # Batching was removed in protocol 2025-06-18 and this server never supported it.
            return _error(None, INVALID_REQUEST, "Request must be a JSON object")

        method = request.get("method")
        # A notification has no id and takes no response, per JSON-RPC.
        if "id" not in request:
            return None

        req_id = request["id"]
        handler = self._handlers.get(method)
        if handler is None:
            return _error(req_id, METHOD_NOT_FOUND, f"Method not found: {method}")

        params = request.get("params")
        if not isinstance(params, dict):
            params = {}

        try:
            result = handler(params)
        except JsonRpcError as exc:
            return _error(req_id, exc.code, str(exc))
        except Exception as exc:
            # A bug in one handler must not take down the server.
            return _error(req_id, INTERNAL_ERROR, f"Internal server error: {exc}")
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    #
    # MCP methods
    #
    def _initialize(self, params):
        requested = params.get("protocolVersion")
        return {
            "protocolVersion": (
                requested if requested in SUPPORTED_PROTOCOL_VERSIONS else DEFAULT_PROTOCOL_VERSION
            ),
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": SERVER_INFO,
        }

    def _tools_list(self, params):
        return {"tools": self.get_tools()}

    def _tools_call(self, params):
        name = params.get("name")
        if name != tools.TOOL_NAME:
            raise JsonRpcError(INVALID_PARAMS, f"Tool not found: {name}")

        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            raise JsonRpcError(INVALID_PARAMS, "'arguments' must be an object")

        code = arguments.get("code")
        if not isinstance(code, str) or not code.strip():
            # Checked rather than assumed: the schema says a string, but nothing enforces it, and
            # letting a number reach .strip() reported a bad argument as a server bug.
            raise JsonRpcError(INVALID_PARAMS, "Argument 'code' is required, as a string")

        # Wait out a call already in flight rather than racing it. The bound is the executor's own
        # timeout plus its interrupt grace, so the only way to miss the lock is a thread that
        # overran and could not be stopped - which the executor reports on its own.
        budget = self.config.execution_timeout_s + LOCK_WAIT_MARGIN_S
        if not self._execution_lock.acquire(timeout=budget):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "Another execution has held this BinaryView for more than "
                        f"{budget:.0f}s and has not finished. Nothing was run.",
                    }
                ],
                "isError": True,
            }
        try:
            result = self.executor.execute(code)
        finally:
            self._execution_lock.release()
        parts = []
        if result.output:
            parts.append(result.output)
        if result.error:
            parts.append(f"\nError: {result.error}")
        if result.timed_out:
            parts.append("\n(Execution timed out)")
        # Execution failures ride back as tool results, not protocol errors, so the model sees the
        # traceback and can retry.
        return {
            "content": [{"type": "text", "text": "".join(parts) if parts else "(no output)"}],
            "isError": not result.success,
        }


class _BoundHTTPServer(ThreadingHTTPServer):
    """A ThreadingHTTPServer carrying the MCPServer, so handlers reach it without class globals."""

    daemon_threads = True
    mcp: MCPServer


class MCPRequestHandler(BaseHTTPRequestHandler):
    """Speaks Streamable HTTP: one endpoint, POST only, JSON responses."""

    server: _BoundHTTPServer
    protocol_version = "HTTP/1.1"
    # Without this a socket read blocks forever, so a request declaring more body than it sends
    # parks a handler thread inside Binary Ninja for the life of the process. It also bounds an
    # idle keep-alive, which a client reopens as it would against any other HTTP server.
    timeout = 60

    def log_message(self, format, *args):
        """Suppress the default stderr logging, which Binary Ninja has no console for."""

    def do_POST(self):
        mcp = self.server.mcp
        if not mcp.same_origin(self.headers):
            self._send_status(403, "Forbidden: cross-origin request")
            return
        if not mcp.authorized(self.headers):
            self._send_status(401, "Unauthorized")
            return
        if urlparse(self.path).path not in ("/", "/mcp"):
            self._send_status(404, "Not found: the MCP endpoint is /mcp")
            return

        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            # Not decoded here, and reading Content-Length instead saw a body of zero and answered
            # a parse error for a request that was well formed.
            self._send_status(411, "Send the body with a Content-Length; chunked is not read")
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self._send_status(400, "Bad Content-Length")
            return

        response = mcp.handle(self.rfile.read(length))
        if response is None:
            # Nothing to answer a notification with, so acknowledge and close.
            self._send_status(202, "")
            return
        self._send_json(response)

    def do_GET(self):
        # A GET opens a server-to-client SSE stream. Nothing here pushes messages, so decline it;
        # the spec has clients fall back to plain request/response on 405.
        self._send_status(405, "This server does not offer an SSE stream; POST to /mcp")

    def _send_json(self, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_status(self, status: int, message: str):
        body = message.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _error(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}
