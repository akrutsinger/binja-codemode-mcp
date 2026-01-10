#!/usr/bin/env python3
"""
Headless Binary Ninja MCP Server with TUI.

Usage:
    uv run binja-codemode-server [OPTIONS] [BINARIES...]

Examples:
    uv run binja-codemode-server                      # Start with no binaries
    uv run binja-codemode-server /path/to/binary      # Start with binary loaded
    uv run binja-codemode-server --no-tui binary.exe  # Simple mode without TUI
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path




def _setup_path():
    """Add plugin directory to path for absolute imports."""
    plugin_dir = Path(__file__).parent.parent
    if str(plugin_dir) not in sys.path:
        sys.path.insert(0, str(plugin_dir))


# Set up path immediately so imports work
_setup_path()


def main() -> int:
    """Main entry point for headless server."""
    parser = argparse.ArgumentParser(
        description="Binary Ninja Code Mode MCP Server (Headless)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           Start interactive TUI
  %(prog)s /path/to/binary           Start with binary pre-loaded
  %(prog)s --no-tui firmware.bin     Run without TUI (simple logging)
  %(prog)s --port 8080 binary.exe    Use custom port
        """,
    )
    parser.add_argument(
        "binaries",
        nargs="*",
        help="Binary files to load on startup",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Server bind address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=42069,
        help="Server port (default: 42069)",
    )
    parser.add_argument(
        "--no-tui",
        action="store_true",
        help="Run without TUI (logging only)",
    )
    parser.add_argument(
        "--api-key",
        help="Custom API key (default: binja-codemode-local)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose Binary Ninja logging (default: errors only)",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress all Binary Ninja logging",
    )

    args = parser.parse_args()

    # Import after argparse for faster --help response
    try:
        import binaryninja
        from binaryninja import log
    except ImportError:
        print("Error: Binary Ninja Python API not found.", file=sys.stderr)
        print("", file=sys.stderr)
        print("Make sure you're running from Binary Ninja's Python environment.", file=sys.stderr)
        print("", file=sys.stderr)
        print("Options:", file=sys.stderr)
        print("  1. Use Binary Ninja's bundled Python:", file=sys.stderr)
        print("     /path/to/binaryninja/python3 -m headless.server", file=sys.stderr)
        print("", file=sys.stderr)
        print("  2. Set PYTHONPATH to include Binary Ninja:", file=sys.stderr)
        print("     export PYTHONPATH=/path/to/binaryninja/python", file=sys.stderr)
        return 1

    # Configure Binary Ninja logging based on verbosity flags
    bn_log_file = None
    if args.quiet:
        # Suppress all logging completely
        binaryninja.disable_default_log()
    elif not args.no_tui:
        # TUI mode: redirect logs to a temp file that TUI will tail
        bn_log_file = tempfile.NamedTemporaryFile(
            mode='w', prefix='binja_logs_', suffix='.log', delete=False
        )
        log_level = log.LogLevel.InfoLog if args.verbose else log.LogLevel.WarningLog
        log.log_to_file(log_level, bn_log_file.name)
        binaryninja.disable_default_log()  # Prevent BN from also writing to stderr
        bn_log_file.close()  # Close our handle, BN will write to it
    elif args.verbose:
        # Verbose non-TUI: show all BN logs (info level and above)
        log.log_to_stderr(log.LogLevel.InfoLog)
    else:
        # Default non-TUI: show warnings and errors only
        log.log_to_stderr(log.LogLevel.WarningLog)

    # Print startup message
    if not binaryninja.core_ui_enabled():
        print("Running in headless mode...", file=sys.stderr)
    else:
        print("Note: Binary Ninja UI is available but running headless server.", file=sys.stderr)

    # Import our modules after binaryninja is confirmed available
    from config import Config
    from headless.session import SessionManager

    # Create config with CLI overrides
    config_kwargs = {"host": args.host, "port": args.port}
    if args.api_key:
        config_kwargs["api_key"] = args.api_key

    config = Config(**config_kwargs)
    session_manager = SessionManager(config)

    # Load initial binaries
    for binary_path in args.binaries:
        path = Path(binary_path).expanduser()
        if not path.exists():
            print(f"Warning: Binary not found: {path}", file=sys.stderr)
            continue

        print(f"Loading: {path}")
        session = session_manager.load_binary(path)
        if session:
            status = session.status
            print(f"  Architecture: {status.get('architecture', 'unknown')}")
            print(f"  Functions: {status.get('function_count', 0)}")
        else:
            print(f"  Failed to load: {path}", file=sys.stderr)

    if args.no_tui:
        return _run_simple_mode(session_manager, config)
    else:
        log_path = bn_log_file.name if bn_log_file else None
        return _run_tui_mode(session_manager, log_path)


def _run_simple_mode(session_manager, config) -> int:
    """Run in simple mode without TUI."""
    import signal

    # Always start the server (can load binaries via MCP later)
    url = session_manager.start_server()
    print(f"\nMCP Server started at {url}")
    print(f"API Key: {config.api_key}")
    if not session_manager.active:
        print("No binaries loaded. Use load_binary tool to load one.")

    print("\nPress Ctrl+C to stop...")

    # Set up request logging
    def log_request(method: str, path: str, is_error: bool) -> None:
        from datetime import datetime

        timestamp = datetime.now().strftime("%H:%M:%S")
        status = "ERR" if is_error else "OK"
        print(f"[{timestamp}] {method:4} {path} [{status}]")

    session_manager.on_request = log_request

    def signal_handler(sig, frame):
        print("\nShutting down...")
        session_manager.stop_server()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Keep running
    try:
        signal.pause()
    except AttributeError:
        # Windows doesn't have signal.pause()
        import time

        while True:
            time.sleep(1)

    return 0


def _run_tui_mode(session_manager, bn_log_path: str | None) -> int:
    """Run with full TUI."""
    try:
        from headless.app import HeadlessApp
    except ImportError as e:
        print(f"Error: TUI dependencies not installed: {e}", file=sys.stderr)
        print("", file=sys.stderr)
        print("Install with: uv pip install textual", file=sys.stderr)
        print("Or run with --no-tui for simple mode.", file=sys.stderr)
        return 1

    try:
        app = HeadlessApp(session_manager, bn_log_path)
        app.run()
    finally:
        # Clean up temp log file
        if bn_log_path:
            try:
                os.unlink(bn_log_path)
            except OSError:
                pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
