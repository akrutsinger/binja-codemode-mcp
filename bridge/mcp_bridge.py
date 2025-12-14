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
from typing import Optional

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


def make_request(method: str, path: str, data: Optional[dict] = None) -> dict:
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


def read_message() -> Optional[dict]:
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
    # Fetch binary status to include in initialization
    try:
        status = make_request("GET", "/status")
        binary_info = status.get("binary", {})
    except Exception:
        binary_info = {}

    return {
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {},
            "resources": {},
        },
        "serverInfo": {
            "name": "binja-codemode-mcp",
            "version": "0.1.1",
        },
        "_meta": {
            "description": "Binary Ninja Code Mode MCP Server for LLM-assisted reverse engineering",
            "binary": binary_info,
            "note": "Read the 'binja://api-reference' resource immediately to get full API documentation",
        },
    }


def handle_list_tools(params: dict) -> dict:
    """Return available tools."""
    return {
        "tools": [
            {
                "name": "execute",
                "description": (
                    "Execute Python analysis code against the current binary. "
                    "Use the `binja` object for all operations. "
                    "Output via print() is captured and returned. "
                    "See the 'Binary Ninja API Reference' resource for complete API documentation."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "Python code to execute",
                        },
                        "description": {
                            "type": "string",
                            "description": "What this code does",
                        },
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "checkpoint",
                "description": "Create a named checkpoint for potential rollback",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Checkpoint name"}
                    },
                    "required": ["name"],
                },
            },
            {
                "name": "rollback",
                "description": "Rollback to a previous checkpoint",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Checkpoint name"}
                    },
                    "required": ["name"],
                },
            },
        ]
    }


def handle_list_resources(params: dict) -> dict:
    """Return available resources."""
    return {
        "resources": [
            {
                "uri": "binja://api-reference",
                "name": "Binary Ninja API Reference",
                "description": (
                    "Complete Python API documentation for analyzing the binary. "
                    "Includes all available binja object methods with examples. "
                    "READ THIS FIRST to understand the full API."
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
        "binja://api-reference": ("GET", "/stubs", "stubs"),
        "binja://status": ("GET", "/status", None),
        "binja://skills": ("GET", "/skills", None),
        "binja://files": ("GET", "/files", None),
    }

    if uri in endpoints:
        method, path, key = endpoints[uri]
        resp = make_request(method, path)
        if "error" in resp:
            text = f"Error: {resp['error']}"
        elif key:
            text = resp.get(key, "")
        else:
            text = json.dumps(resp, indent=2)
        return {"contents": [{"uri": uri, "text": text}]}

    return {"contents": [{"uri": uri, "text": "Resource not found"}]}


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
            except (json.JSONDecodeError, IOError):
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
    except Exception as e:
        logger.error("Failed to load config: %s", e, exc_info=True)

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
                pass
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
            logger.error("Error processing message: %s", e, exc_info=True)
            # Try to send error response if we have a message ID
            if msg and msg.get("id"):
                try:
                    write_message(
                        {
                            "jsonrpc": "2.0",
                            "id": msg.get("id"),
                            "error": {
                                "code": -32603,
                                "message": f"Internal error: {str(e)}",
                            },
                        }
                    )
                except Exception as write_error:
                    logger.error("Failed to write error response: %s", write_error)


if __name__ == "__main__":
    main()
