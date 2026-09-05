"""
MCP Status Widget for Binary Ninja status bar.

Provides a clickable status indicator showing MCP server state.
"""

import threading
import time
from pathlib import Path

from binaryninja import UIPluginInHeadlessError, execute_on_main_thread
from binaryninja.log import log_debug, log_error, log_info

try:
    from binaryninjaui import UIContext, UIContextNotification
    from PySide6.QtCore import Qt, QTimer
    from PySide6.QtWidgets import QHBoxLayout, QPushButton, QWidget

    _HAS_UI = True
except (ImportError, UIPluginInHeadlessError):
    # binaryninjaui raises UIPluginInHeadlessError, which is not an ImportError.
    _HAS_UI = False

# Module-level state. The indicators themselves are not held here: Binary Ninja opens more than
# one main window in a single process, each with its own status bar, and one shared widget can only
# be parented to one of them. Each window gets its own, found again by object name.
_INDICATOR = "mcpStatusContainer"
_BUTTON = "mcpStatusButton"

_indicator_timer = None
_ui_notification = None
_plugin_instance = None


def _indicator_text(binary_view) -> str:
    """What the indicator should say in a window showing `binary_view`.

    A server serves the one BinaryView it was started against, so "Running" in a window showing a
    different binary was true of the process and misleading about the window. Naming the binary
    says which of the two it is.
    """
    served = _plugin_instance.served_view if _plugin_instance else None
    if served is None:
        return "🔴 MCP: Stopped"
    if binary_view is not None and binary_view.file.session_id == served.file.session_id:
        return f"🟢 MCP: {_binary_name(served)}"
    # Not "other binary": a window with nothing open is in this branch too, and either way what
    # the reader needs is that the server is up and not serving here. The tooltip names where.
    return "⚪ MCP: elsewhere"


def _indicator_tooltip() -> str:
    """The hover text, which has room to name the served binary in full."""
    served = _plugin_instance.served_view if _plugin_instance else None
    if served is None:
        return "Click to start the MCP server"
    return f"Serving {served.file.filename}\nClick to stop the MCP server"


def _binary_name(binary_view) -> str:
    """The served binary's filename, short enough to sit in a status bar."""
    name = Path(binary_view.file.filename).name.removesuffix(".bndb")
    return name if len(name) <= 28 else f"{name[:27]}…"


def _create_status_indicator(binary_view):
    """Build one status indicator, for the window showing `binary_view`."""
    button = QPushButton()
    button.setObjectName(_BUTTON)
    button.setFlat(True)
    button.setCursor(Qt.PointingHandCursor)
    button.setToolTip(_indicator_tooltip())
    button.setContentsMargins(0, 0, 0, 0)
    button.setStyleSheet("margin:0; padding:0 6px; border:0; border-radius:1px;")
    button.setText(_indicator_text(binary_view))
    button.clicked.connect(_on_button_click)

    # Wrap in container with margins
    container = QWidget()
    container.setObjectName(_INDICATOR)
    layout = QHBoxLayout(container)
    layout.setContentsMargins(8, 0, 3, 0)
    layout.setSpacing(0)
    layout.addWidget(button)

    return container


def _windows():
    """Every open main window, as the context it belongs to and its status bar."""
    for ctx in UIContext.allContexts():
        main_window = ctx.mainWindow()
        status_bar = main_window.statusBar() if main_window else None
        if status_bar is not None:
            yield ctx, status_bar


def _on_button_click():
    """Handle status button click to toggle server state."""
    if _plugin_instance is None:
        log_error("MCP Status: Plugin instance not set")
        return

    try:
        if _plugin_instance.is_running:
            _plugin_instance.stop_server(None)
        else:
            bv = _get_active_binary_view()
            if bv is None:
                log_debug("MCP Status: No active BinaryView. Open a file first.")
                return
            _plugin_instance.start_server(bv)
    except Exception as e:
        log_error(f"MCP Status: Error toggling server: {e}")


def _view_of(ctx):
    """The BinaryView a UI context is showing, or None."""
    view_frame = ctx.getCurrentViewFrame() if ctx else None
    return view_frame.getCurrentBinaryView() if view_frame else None


def _get_active_binary_view():
    """Get the currently active BinaryView from the UI context."""
    return _view_of(UIContext.activeContext())


def _update_status_indicator():
    """Update every window's status button, each for the binary that window shows."""
    if _plugin_instance is None:
        return

    tooltip = _indicator_tooltip()
    for ctx, status_bar in _windows():
        indicator = status_bar.findChild(QWidget, _INDICATOR)
        if indicator is None:
            continue
        button = indicator.findChild(QPushButton, _BUTTON)
        button.setText(_indicator_text(_view_of(ctx)))
        button.setToolTip(tooltip)


def _on_file_closed(context, frame):
    """Stop the server when the binary it was serving is the one that closed.

    Closing a file does not free its BinaryView while the server holds a reference to it, so the
    server went on answering and the model went on reading, renaming and patching a database
    nobody had open. This used to ask whether any view remained, which a second window satisfies.
    """
    if _plugin_instance is None or not _plugin_instance.is_running:
        return

    def delayed_check():
        # Binary Ninja closes the file after this notification, so let the UI settle before asking
        # what is still open.
        time.sleep(0.3)
        execute_on_main_thread(_stop_if_served_binary_closed)

    # Run the check in a background thread to avoid blocking
    threading.Thread(target=delayed_check, daemon=True).start()


def _served_binary_is_open() -> bool:
    """Whether the binary the server serves still has a tab in some window.

    By session id over every context's tabs rather than the view each window currently shows: the
    served binary may sit in a background tab, and stopping the server over that would be wrong.
    """
    served = _plugin_instance.served_view if _plugin_instance else None
    if served is None:
        return False
    session_id = served.file.session_id
    return any(ctx.getTabForSessionId(session_id) is not None for ctx in UIContext.allContexts())


def _stop_if_served_binary_closed():
    """Stop the server if its binary has gone, and bring the indicators up to date either way."""
    if _plugin_instance is None or not _plugin_instance.is_running:
        return

    if _served_binary_is_open():
        log_debug("MCP: the served binary is still open, keeping the server running")
        _update_status_indicator()
        return

    log_info("Code Mode MCP: the binary this server was serving was closed. Stopping the server.")
    _plugin_instance.stop_server(None)


def _ensure_indicator_in_status_bar() -> bool:
    """Give every open window its own status indicator. True once at least one has one."""
    placed = False
    for ctx, status_bar in _windows():
        if status_bar.findChild(QWidget, _INDICATOR) is None:
            # Insert at position 1 (after the first default widget)
            status_bar.insertWidget(1, _create_status_indicator(_view_of(ctx)), 0)
            log_debug("MCP Status: Added status indicator to status bar")
        placed = True
    return placed


def _timer_tick():
    """Timer callback for periodic UI updates."""
    execute_on_main_thread(lambda: _do_timer_tick())


def _do_timer_tick():
    """Install the indicator once the status bar exists, then stand down.

    The status bar does not exist yet when the plugin loads, so something has to wait for it. This
    timer was that something and then went on polling twice a second for the rest of the session,
    although every change the indicator can show already arrives through update_status() or a UI
    notification.
    """
    if _ensure_indicator_in_status_bar() and _indicator_timer is not None:
        _indicator_timer.stop()
    _update_status_indicator()


class MCPUINotification(UIContextNotification if _HAS_UI else object):
    """UI notification handler for MCP status updates."""

    def OnContextOpen(self, context):
        """Called when a UI context is opened."""
        execute_on_main_thread(lambda: _ensure_indicator_in_status_bar())

    def OnViewChange(self, context, frame, type_name):
        """Called when the view changes."""
        execute_on_main_thread(lambda: _on_view_change())

    def OnAfterCloseFile(self, context, file, frame):
        """Called after a file is closed - stop MCP server if no views remain."""
        log_debug("MCP Status: File closed, checking for remaining views")
        execute_on_main_thread(lambda: _on_file_closed(context, frame))


def _on_view_change():
    """A window that opened without a status bar yet gets its indicator here."""
    _ensure_indicator_in_status_bar()
    _update_status_indicator()


def init_status_indicator(plugin_instance):
    """Initialize the status indicator system.

    Args:
        plugin_instance: The BinjaCodeModeMCP plugin instance
    """
    global _indicator_timer, _ui_notification, _plugin_instance

    if not _HAS_UI:
        log_debug("MCP Status: UI not available (headless mode)")
        return

    _plugin_instance = plugin_instance

    # Register UI notification
    _ui_notification = MCPUINotification()
    UIContext.registerNotification(_ui_notification)

    # Start periodic timer for UI updates
    _indicator_timer = QTimer()
    _indicator_timer.setInterval(500)
    _indicator_timer.timeout.connect(_timer_tick)
    _indicator_timer.start()

    log_debug("MCP Status: Status indicator initialized")


def update_status():
    """Bring every window's status indicator in line with the server state."""
    if not _HAS_UI:
        return

    execute_on_main_thread(_update_status_indicator)
