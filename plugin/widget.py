"""
MCP Status Widget for Binary Ninja status bar.

Provides a clickable status indicator showing MCP server state.
"""

from binaryninja import execute_on_main_thread
from binaryninja.log import log_debug, log_error, log_info

try:
    from binaryninjaui import UIContext, UIContextNotification
    from PySide6.QtCore import Qt, QTimer
    from PySide6.QtWidgets import QHBoxLayout, QPushButton, QWidget

    _HAS_UI = True
except ImportError:
    _HAS_UI = False

# Module-level state
_status_button = None
_status_container = None
_indicator_timer = None
_ui_notification = None
_plugin_instance = None


def _get_status_text(running: bool) -> str:
    """Get the status text for the button."""
    if running:
        return "🟢 MCP: Running"
    return "🔴 MCP: Stopped"


def _create_status_button():
    """Create and configure the status button widget."""
    global _status_button, _status_container

    if _status_button is not None:
        return _status_container

    _status_button = QPushButton()
    _status_button.setObjectName("mcpStatusButton")
    _status_button.setFlat(True)
    _status_button.setCursor(Qt.PointingHandCursor)
    _status_button.setToolTip("Click to start/stop MCP server")
    _status_button.setContentsMargins(0, 0, 0, 0)
    _status_button.setStyleSheet(
        "margin:0; padding:0 6px; border:0; border-radius:1px;"
    )
    _status_button.setText(_get_status_text(False))
    _status_button.clicked.connect(_on_button_click)

    # Wrap in container with margins
    _status_container = QWidget()
    _status_container.setObjectName("mcpStatusContainer")
    layout = QHBoxLayout(_status_container)
    layout.setContentsMargins(8, 0, 3, 0)
    layout.setSpacing(0)
    layout.addWidget(_status_button)

    return _status_container


def _on_button_click():
    """Handle status button click to toggle server state."""
    global _plugin_instance

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
    """Update the status button text based on server state."""
    global _status_button, _plugin_instance

    if _status_button is None or _plugin_instance is None:
        return

    running = _plugin_instance.is_running
    _status_button.setText(_get_status_text(running))


def _on_file_closed(context, frame):
    """Handle file closed by stopping MCP server if no binary views remain."""
    global _plugin_instance

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


def _ensure_indicator_in_status_bar():
    """Ensure the status indicator is present in the status bar."""
    global _status_container

    ctx = UIContext.activeContext()
    if ctx is None:
        return

    # Get the main window, which has the status bar
    main_window = ctx.mainWindow()
    if main_window is None:
        return

    # Create button if needed
    container = _create_status_button()

    # Get status bar from main window
    status_bar = main_window.statusBar()
    if status_bar is None:
        return

    # Check if container is already in the status bar
    if container.parent() == status_bar:
        return

    # Insert at position 1 (after the first default widget)
    status_bar.insertWidget(1, container, 0)
    log_debug("MCP Status: Added status indicator to status bar")


def _timer_tick():
    """Timer callback for periodic UI updates."""
    execute_on_main_thread(lambda: _do_timer_tick())


def _do_timer_tick():
    """Perform timer tick on main thread."""
    _ensure_indicator_in_status_bar()
    _update_status_indicator()


class MCPUINotification(UIContextNotification):
    """UI notification handler for MCP status updates."""

    def OnContextOpen(self, context):
        """Called when a UI context is opened."""
        execute_on_main_thread(lambda: _ensure_indicator_in_status_bar())

    def OnViewChange(self, context, frame, type_name):
        """Called when the view changes."""
        execute_on_main_thread(lambda: _update_status_indicator())

    def OnAfterCloseFile(self, context, file, frame):
        """Called after a file is closed - stop MCP server if no views remain."""
        log_debug("MCP Status: File closed, checking for remaining views")
        execute_on_main_thread(lambda: _on_file_closed(context, frame))


def init_status_indicator(plugin_instance):
    """Initialize the status indicator system.

    Args:
        plugin_instance: The BinjaCodeModeMCP plugin instance
    """
    global _indicator_timer, _ui_notification, _plugin_instance, _HAS_UI

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


def update_status(running: bool):
    """Update the status indicator.

    Args:
        running: Whether the server is running
    """
    global _status_button, _HAS_UI

    if not _HAS_UI or _status_button is None:
        return

    execute_on_main_thread(lambda: _status_button.setText(_get_status_text(running)))


def cleanup_status_indicator():
    """Clean up the status indicator resources."""
    global _indicator_timer, _ui_notification, _status_button, _status_container

    if _indicator_timer is not None:
        _indicator_timer.stop()
        _indicator_timer = None

    if _ui_notification is not None:
        UIContext.unregisterNotification(_ui_notification)
        _ui_notification = None

    _status_button = None
    _status_container = None
