#!/usr/bin/env python3
"""
MCP Bridge: Connects MCP protocol (stdio) to Binary Ninja HTTP server.
"""

import json
import logging
import os
import sys
import urllib.error
import urllib.request

# Logging configuration (use stderr to avoid interfering with JSON-RPC on stdout)
log_level = os.environ.get("BINJA_MCP_LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, log_level.upper(), logging.INFO),
    format="%(asctime)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)


def excepthook(exc_type, exc_value, exc_traceback):
    """Custom exception handler that logs to stderr."""
    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))


# Install custom exception handler
sys.excepthook = excepthook

# Configuration
SERVER_URL = os.environ.get("BINJA_MCP_URL", "http://127.0.0.1:42069")
API_KEY = os.environ.get("BINJA_MCP_KEY", "binja-codemode-local")

# Clients ask for the tool list once, at startup, which is usually before Binary Ninja is running.
# Advertising the tool anyway keeps it visible, and says how to bring the real one up.
OFFLINE_TOOLS = [
    {
        "name": "execute",
        "description": (
            "Execute Python against the binary open in Binary Ninja. Binary Ninja is not "
            "reachable right now, so the API reference is unavailable. Open a binary, run "
            "Plugins > MCP Code Mode > Start Server, then reconnect this MCP server to get "
            "the full method list."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"code": {"type": "string", "description": "Python code."}},
            "required": ["code"],
        },
    }
]


def make_request(method: str, path: str, data: dict | None = None) -> dict:
    """Make HTTP request to Binary Ninja server."""
    url = f"{SERVER_URL}{path}"
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }

    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.reason}"}
    except urllib.error.URLError as e:
        return {"error": f"Connection failed: {e.reason}"}


def read_message() -> dict | None:
    """Read JSON-RPC message from stdin."""
    line = ""
    try:
        line = sys.stdin.readline()
        if not line:
            return None
        logger.debug("Raw input: %s", line.strip())
        msg = json.loads(line)
        return msg
    except json.JSONDecodeError as e:
        logger.error("Failed to parse JSON: %s (input: %s)", e, line.strip())
        return None


def write_message(msg: dict):
    """Write JSON-RPC message to stdout."""
    output = json.dumps(msg)
    logger.debug("Sending: %s", output)
    sys.stdout.write(output + "\n")
    sys.stdout.flush()


def handle_initialize(params: dict) -> dict:
    """Handle MCP initialize request."""
    status = make_request("GET", "/status")

    return {
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {},
            "resources": {},
        },
        "serverInfo": {
            "name": "binja-codemode-mcp",
            "version": status.get("version", "unknown"),
        },
        "_meta": {
            "description": "Binary Ninja Code Mode MCP Server for LLM-assisted reverse engineering",
            "binary": status.get("binary", {}),
        },
    }


def handle_list_tools(params: dict) -> dict:
    """Return the tools the plugin advertises, which it generates from its own API."""
    resp = make_request("GET", "/tools")
    tools = resp.get("tools")
    if not tools:
        logger.warning("Could not fetch tools from %s: %s", SERVER_URL, resp.get("error"))
        return {"tools": OFFLINE_TOOLS}
    return {"tools": tools}


def handle_list_resources(params: dict) -> dict:
    """Return available resources."""
    return {
        "resources": [
            {
                "uri": "binja://api-reference",
                "name": "Binary Ninja API Reference",
                "description": (
                    "The same API documentation the execute tool already carries in its "
                    "description. Read it here only if that arrived truncated."
                ),
                "mimeType": "text/plain",
            },
            {
                "uri": "binja://status",
                "name": "Binary Status",
                "description": (
                    "Current binary information and session state: "
                    "filename, architecture, platform, entry point, function count, address range"
                ),
                "mimeType": "application/json",
            },
            {
                "uri": "binja://skills",
                "name": "Available Skills",
                "description": (
                    "List of saved reusable analysis skills with descriptions. "
                    "Skills can be loaded and executed to perform complex analyses."
                ),
                "mimeType": "application/json",
            },
            {
                "uri": "binja://files",
                "name": "Workspace Files",
                "description": (
                    "Files in the current workspace for persistence within this session. "
                    "Use to save analysis results, notes, or intermediate data."
                ),
                "mimeType": "application/json",
            },
        ]
    }


def handle_read_resource(params: dict) -> dict:
    """Read a resource."""
    uri = params.get("uri", "")

    endpoints = {
        "binja://api-reference": "/tools",
        "binja://status": "/status",
        "binja://skills": "/skills",
        "binja://files": "/files",
    }

    if uri not in endpoints:
        return {"contents": [{"uri": uri, "text": "Resource not found"}]}

    resp = make_request("GET", endpoints[uri])
    if "error" in resp:
        text = f"Error: {resp['error']}"
    elif uri == "binja://api-reference":
        text = "\n\n".join(tool["description"] for tool in resp.get("tools", []))
    else:
        text = json.dumps(resp, indent=2)
    return {"contents": [{"uri": uri, "text": text}]}


def handle_call_tool(params: dict) -> dict:
    """Handle tool invocation."""
    name = params.get("name")
    args = params.get("arguments", {})

    if name == "execute":
        resp = make_request(
            "POST",
            "/execute",
            {"code": args.get("code", ""), "description": args.get("description", "")},
        )

        parts = []
        if resp.get("output"):
            parts.append(resp["output"])
        if resp.get("error"):
            parts.append(f"\nError: {resp['error']}")
        if resp.get("timed_out"):
            parts.append("\n(Execution timed out)")

        text = "".join(parts) if parts else "(no output)"
        return {
            "content": [{"type": "text", "text": text}],
            "isError": not resp.get("success", False),
        }

    elif name == "checkpoint":
        resp = make_request("POST", "/checkpoint", {"name": args.get("name", "")})
        return {"content": [{"type": "text", "text": resp.get("message", str(resp))}]}

    elif name == "rollback":
        resp = make_request("POST", "/rollback", {"name": args.get("name", "")})
        return {"content": [{"type": "text", "text": resp.get("message", str(resp))}]}

    return {
        "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
        "isError": True,
    }


def load_config():
    """Load configuration from file if exists."""
    global SERVER_URL, API_KEY

    config_paths = [
        os.path.expanduser("~/.config/binja-codemode-mcp/config.json"),
        os.path.expanduser("~/.binaryninja/codemode_mcp/bridge_config.json"),
    ]

    for path in config_paths:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    config = json.load(f)
                    SERVER_URL = config.get("url", SERVER_URL)
                    API_KEY = config.get("api_key", API_KEY)
                    return
            except (OSError, json.JSONDecodeError):
                continue


def main():
    """Main MCP bridge loop."""
    try:
        load_config()
        logger.info("MCP bridge started (server: %s)", SERVER_URL)

        # Health check: verify Binary Ninja server is reachable
        try:
            resp = make_request("GET", "/status")
            if "error" in resp:
                logger.warning("Binary Ninja server health check: %s", resp["error"])
            else:
                logger.info("Binary Ninja server is reachable")
        except Exception as health_error:
            logger.warning("Binary Ninja server health check failed: %s", health_error)
    except Exception:
        logger.exception("Failed to load config")

    handlers = {
        "initialize": handle_initialize,
        "tools/list": handle_list_tools,
        "resources/list": handle_list_resources,
        "resources/read": handle_read_resource,
        "tools/call": handle_call_tool,
    }

    while True:
        msg = None
        try:
            msg = read_message()
            if msg is None:
                logger.debug("No message received, exiting")
                break

            method = msg.get("method")
            msg_id = msg.get("id")
            params = msg.get("params", {})

            logger.debug("Received method: %s (id: %s)", method, msg_id)

            if method in handlers:
                result = handlers[method](params)
                write_message({"jsonrpc": "2.0", "id": msg_id, "result": result})
            elif method == "notifications/initialized":
                logger.debug("Received initialized notification")
            else:
                logger.warning("Unknown method: %s", method)
                write_message(
                    {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32601,
                            "message": f"Method not found: {method}",
                        },
                    }
                )
        except Exception as e:
            logger.exception("Error processing message")
            # Try to send error response if we have a message ID
            if msg and msg.get("id"):
                try:
                    write_message(
                        {
                            "jsonrpc": "2.0",
                            "id": msg.get("id"),
                            "error": {
                                "code": -32603,
                                "message": f"Internal error: {e!s}",
                            },
                        }
                    )
                except Exception as write_error:
                    logger.error("Failed to write error response: %s", write_error)


if __name__ == "__main__":
    main()
