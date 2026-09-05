"""
MCP Status Widget for Binary Ninja status bar.

Provides a clickable status indicator showing MCP server state.
"""

from binaryninja import UIPluginInHeadlessError, execute_on_main_thread
from binaryninja.log import log_debug, log_error

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


def _get_status_text(running: bool) -> str:
    """Get the status text for the button."""
    if running:
        return "🟢 MCP: Running"
    return "🔴 MCP: Stopped"


def _create_status_indicator():
    """Build one status indicator, for one window's status bar."""
    button = QPushButton()
    button.setObjectName(_BUTTON)
    button.setFlat(True)
    button.setCursor(Qt.PointingHandCursor)
    button.setToolTip("Click to start/stop MCP server")
    button.setContentsMargins(0, 0, 0, 0)
    button.setStyleSheet("margin:0; padding:0 6px; border:0; border-radius:1px;")
    button.setText(_get_status_text(_plugin_instance.is_running if _plugin_instance else False))
    button.clicked.connect(_on_button_click)

    # Wrap in container with margins
    container = QWidget()
    container.setObjectName(_INDICATOR)
    layout = QHBoxLayout(container)
    layout.setContentsMargins(8, 0, 3, 0)
    layout.setSpacing(0)
    layout.addWidget(button)

    return container


def _status_bars():
    """The status bar of every open main window."""
    for ctx in UIContext.allContexts():
        main_window = ctx.mainWindow()
        status_bar = main_window.statusBar() if main_window else None
        if status_bar is not None:
            yield status_bar


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


def _get_active_binary_view():
    """Get the currently active BinaryView from the UI context."""
    ctx = UIContext.activeContext()
    if ctx is None:
        return None

    view_frame = ctx.getCurrentViewFrame()
    if view_frame is None:
        return None

    return view_frame.getCurrentBinaryView()


def _update_status_indicator():
    """Update every window's status button to match the server state."""
    if _plugin_instance is None:
        return

    text = _get_status_text(_plugin_instance.is_running)
    for status_bar in _status_bars():
        indicator = status_bar.findChild(QWidget, _INDICATOR)
        if indicator is not None:
            indicator.findChild(QPushButton, _BUTTON).setText(text)


def _on_file_closed(context, frame):
    """Handle file closed by stopping MCP server if no binary views remain."""
    if _plugin_instance is None or not _plugin_instance.is_running:
        return

    # Check if there are any binary views still open after a delay
    # This gives Binary Ninja time to switch to another tab if one exists
    def delayed_check():
        import time

        time.sleep(0.3)  # Give the UI some time to update

        active_bv = _get_active_binary_view()

        if active_bv is None:
            log_debug("MCP: No binary views remain, stopping server")
            _plugin_instance.stop_server(None)
        else:
            log_debug("MCP: Binary views still open, keeping server running")

    # Run the check in a background thread to avoid blocking
    import threading

    threading.Thread(target=delayed_check, daemon=True).start()


def _ensure_indicator_in_status_bar() -> bool:
    """Give every open window its own status indicator. True once at least one has one."""
    placed = False
    for status_bar in _status_bars():
        if status_bar.findChild(QWidget, _INDICATOR) is None:
            # Insert at position 1 (after the first default widget)
            status_bar.insertWidget(1, _create_status_indicator(), 0)
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
