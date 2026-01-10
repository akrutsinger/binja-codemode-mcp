"""Textual TUI application for headless Binary Ninja MCP server."""

from __future__ import annotations

import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.events import Click
from textual.message import Message
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    DirectoryTree,
    Footer,
    Header,
    Input,
    Label,
    Log,
    Static,
    TabbedContent,
    TabPane,
)
from textual.worker import Worker, WorkerState

if TYPE_CHECKING:
    from .session import SessionManager


class BinaryPanel(Static):
    """Panel showing loaded binaries."""

    class ContextMenuRequested(Message):
        """Posted when context menu is requested for a binary."""

        def __init__(self, binary_path: str) -> None:
            super().__init__()
            self.binary_path = binary_path

    def __init__(self, session_manager: SessionManager) -> None:
        super().__init__()
        self.session_manager = session_manager

    def compose(self) -> ComposeResult:
        yield Static("Loaded Binaries", classes="panel-title")
        yield DataTable(id="binary-table", cursor_type="row")

    def on_mount(self) -> None:
        table = self.query_one("#binary-table", DataTable)
        table.add_columns("", "Name", "Arch", "Functions")
        self.refresh_table()

    def refresh_table(self) -> None:
        table = self.query_one("#binary-table", DataTable)
        table.clear()

        for session in self.session_manager.sessions:
            status = session.status
            is_active = session == self.session_manager.active
            table.add_row(
                "*" if is_active else " ",
                session.name[:30],
                status.get("architecture", "?")[:10],
                str(status.get("function_count", 0)),
                key=str(session.path),
            )

    def on_click(self, event: Click) -> None:
        """Handle right-click to show context menu."""
        if event.button == 3:  # Right mouse button
            table = self.query_one("#binary-table", DataTable)
            # Check if click is within table bounds
            if table.region.contains(event.x, event.y):
                # Get the row at click position
                row_key = table.cursor_row
                if row_key is not None and row_key < len(self.session_manager.sessions):
                    session = self.session_manager.sessions[row_key]
                    self.post_message(self.ContextMenuRequested(str(session.path)))

    def get_selected_binary_path(self) -> str | None:
        """Get path of currently selected binary in table."""
        table = self.query_one("#binary-table", DataTable)
        if table.cursor_row is not None and table.cursor_row < len(
            self.session_manager.sessions
        ):
            return str(self.session_manager.sessions[table.cursor_row].path)
        return None


class LogTabs(Vertical):
    """Tabbed panel showing MCP requests and Binary Ninja logs."""

    def compose(self) -> ComposeResult:
        with TabbedContent(initial="requests"):
            with TabPane("MCP Logs", id="requests"):
                yield Log(id="request-log", highlight=True, max_lines=1000)
            with TabPane("BN Logs", id="bn-logs"):
                yield Log(id="bn-log", highlight=True, max_lines=2000)

    def add_request(self, method: str, path: str, is_error: bool = False) -> None:
        # NoMatches: widget may not be mounted yet when callbacks fire from other threads
        try:
            log = self.query_one("#request-log", Log)
            timestamp = datetime.now().strftime("%H:%M:%S")
            status = "ERR" if is_error else "OK "
            log.write_line(f"{timestamp} {method:4} {path} [{status}]")
        except NoMatches:
            pass

    def add_bn_log(self, message: str, level: str = "INFO") -> None:
        # NoMatches: widget may not be mounted yet when callbacks fire from other threads
        try:
            log = self.query_one("#bn-log", Log)
            timestamp = datetime.now().strftime("%H:%M:%S")
            log.write_line(f"{timestamp} [{level:5}] {message}")
        except NoMatches:
            pass


class OperationsPanel(Vertical):
    """Panel showing operations log (renames, comments, type changes, etc.)."""

    def compose(self) -> ComposeResult:
        yield Static("Operations", classes="panel-title")
        yield Log(id="operations-log", highlight=True, max_lines=1000)

    def add_operation(self, description: str) -> None:
        # NoMatches: widget may not be mounted yet when callbacks fire from other threads
        try:
            log = self.query_one("#operations-log", Log)
            timestamp = datetime.now().strftime("%H:%M:%S")
            log.write_line(f"{timestamp} {description}")
        except NoMatches:
            pass


class ServerStatus(Static):
    """Status bar showing server information."""

    running = reactive(False)
    url = reactive("")
    binary_count = reactive(0)
    active_name = reactive("")

    def render(self) -> str:
        if self.running:
            status = f"[green bold]SERVER RUNNING[/green bold] | {self.url}"
            if self.active_name:
                status += f" | Active: [cyan]{self.active_name}[/cyan]"
            status += f" | Binaries: {self.binary_count}"
            return status
        return "[red bold]SERVER STOPPED[/red bold] | Press [bold]s[/bold] to start"


class FileSelectModal(ModalScreen[str | None]):
    """Modal dialog for selecting a binary file to load."""

    BINDINGS = [("escape", "cancel", "Cancel")]

    DEFAULT_CSS = """
    FileSelectModal {
        align: center middle;
    }

    #file-dialog {
        width: 80%;
        height: 80%;
        border: thick $primary-darken-2;
        background: $surface;
        padding: 1 2;
    }

    #dialog-title {
        text-style: bold;
        background: $primary;
        color: $text;
        padding: 0 1;
        margin-bottom: 1;
    }

    #tree-container {
        height: 1fr;
        border: solid $primary-darken-2;
        margin-bottom: 1;
    }

    #path-input-container {
        height: auto;
        margin-bottom: 1;
    }

    #file-path-input {
        width: 100%;
    }

    #button-container {
        height: 3;
        align: right middle;
    }

    #button-container Button {
        margin-left: 1;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="file-dialog"):
            yield Label("Select Binary File", id="dialog-title")
            with Vertical(id="tree-container"):
                yield DirectoryTree(str(Path.home()), id="file-tree")
            with Vertical(id="path-input-container"):
                yield Static("Path (type or paste):")
                yield Input(placeholder="Enter file path...", id="file-path-input")
            with Horizontal(id="button-container"):
                yield Button("Cancel", variant="default", id="cancel-btn")
                yield Button("Load", variant="primary", id="load-btn")

    def on_mount(self) -> None:
        self.query_one("#file-path-input", Input).focus()

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        event.stop()
        self.query_one("#file-path-input", Input).value = str(event.path)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "load-btn":
            self._submit_path()
        elif event.button.id == "cancel-btn":
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "file-path-input":
            self._submit_path()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _submit_path(self) -> None:
        path_str = self.query_one("#file-path-input", Input).value.strip()
        if not path_str:
            return
        path = Path(path_str).expanduser()
        if not path.exists():
            self.notify(f"File not found: {path}", severity="error")
            return
        if path.is_dir():
            self.notify("Please select a file, not a directory", severity="warning")
            return
        self.dismiss(str(path.resolve()))


class BinaryContextMenu(ModalScreen[str | None]):
    """Context menu for binary operations (Save, Save As, Close)."""

    BINDINGS = [("escape", "cancel", "Cancel")]

    DEFAULT_CSS = """
    BinaryContextMenu {
        align: center middle;
    }

    #context-menu {
        width: 24;
        height: auto;
        border: solid $primary;
        background: $surface;
        padding: 0 1;
    }

    #context-menu Button {
        width: 100%;
        margin: 0;
        min-width: 20;
    }

    #context-menu .separator {
        height: 1;
        margin: 0;
        color: $primary-darken-2;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="context-menu"):
            yield Button("Save", id="save")
            yield Button("Save As...", id="save-as")
            yield Static("─" * 20, classes="separator")
            yield Button("Close", id="close", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id)

    def action_cancel(self) -> None:
        self.dismiss(None)


class FileSaveModal(ModalScreen[str | None]):
    """Modal dialog for selecting save location."""

    BINDINGS = [("escape", "cancel", "Cancel")]

    DEFAULT_CSS = """
    FileSaveModal {
        align: center middle;
    }

    #save-dialog {
        width: 80%;
        height: 80%;
        border: thick $primary-darken-2;
        background: $surface;
        padding: 1 2;
    }

    #save-dialog-title {
        text-style: bold;
        background: $primary;
        color: $text;
        padding: 0 1;
        margin-bottom: 1;
    }

    #save-tree-container {
        height: 1fr;
        border: solid $primary-darken-2;
        margin-bottom: 1;
    }

    #save-path-container {
        height: auto;
        margin-bottom: 1;
    }

    #save-path-input {
        width: 100%;
    }

    #save-button-container {
        height: 3;
        align: right middle;
    }

    #save-button-container Button {
        margin-left: 1;
    }
    """

    def __init__(self, default_path: str = "") -> None:
        super().__init__()
        if default_path:
            self.default_path = Path(default_path)
        else:
            self.default_path = Path.home() / "analysis.bndb"

    def compose(self) -> ComposeResult:
        with Vertical(id="save-dialog"):
            yield Label("Save Database As", id="save-dialog-title")
            with Vertical(id="save-tree-container"):
                yield DirectoryTree(str(self.default_path.parent), id="save-tree")
            with Vertical(id="save-path-container"):
                yield Static("Save path:")
                yield Input(
                    placeholder="Enter save path...",
                    value=str(self.default_path),
                    id="save-path-input",
                )
            with Horizontal(id="save-button-container"):
                yield Button("Cancel", variant="default", id="save-cancel-btn")
                yield Button("Save", variant="primary", id="save-confirm-btn")

    def on_mount(self) -> None:
        self.query_one("#save-path-input", Input).focus()

    def on_directory_tree_directory_selected(
        self, event: DirectoryTree.DirectorySelected
    ) -> None:
        event.stop()
        # Update path to selected directory + filename
        current = self.query_one("#save-path-input", Input).value
        filename = Path(current).name or self.default_path.name
        self.query_one("#save-path-input", Input).value = str(event.path / filename)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save-confirm-btn":
            self._submit_path()
        elif event.button.id == "save-cancel-btn":
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "save-path-input":
            self._submit_path()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _submit_path(self) -> None:
        path_str = self.query_one("#save-path-input", Input).value.strip()
        if not path_str:
            return
        path = Path(path_str).expanduser()
        # Ensure .bndb extension
        if not path.suffix.lower() == ".bndb":
            path = path.with_suffix(".bndb")
        # Check parent directory exists
        if not path.parent.exists():
            self.notify(f"Directory not found: {path.parent}", severity="error")
            return
        self.dismiss(str(path.resolve()))


class HeadlessApp(App):
    """Main TUI application for headless MCP server."""

    TITLE = "Binary Ninja Code Mode MCP Server"
    SUB_TITLE = "Server: Stopped"

    CSS = """
    /* General Theme */
    Screen {
        background: $surface-darken-1;
    }

    .panel-title {
        background: $primary-darken-2;
        color: $text;
        padding: 0 1;
        text-style: bold;
        height: 1;
    }

    /* Layout */
    #main-container {
        height: 1fr;
    }

    #binary-panel {
        width: 40%;
        height: 100%;
        border-right: solid $primary-darken-2;
        background: $surface;
    }

    #logs-panel {
        width: 60%;
        height: 100%;
        background: $surface-darken-1;
    }

    LogTabs {
        height: 60%;
    }

    OperationsPanel {
        height: 40%;
        border-top: solid $primary-darken-2;
    }

    /* Widgets */
    DataTable {
        height: 1fr;
        background: $surface;
        border: none;
    }
    
    DataTable > .datatable--header {
        background: $primary-darken-3;
        color: $text;
        text-style: bold;
    }

    Log {
        height: 1fr;
        background: $surface-darken-1;
        border: none;
    }

    TabbedContent {
        height: 100%;
    }

    TabPane {
        height: 1fr;
        padding: 0;
    }
    
    Tabs {
        background: $surface;
    }

    #status-bar {
        dock: bottom;
        height: 1;
        background: $primary-darken-3;
        color: $text;
        padding: 0 1;
    }

    /* Scrollbars */
    ScrollBar {
        background: $surface-darken-1;
        color: $primary;
        width: 1;
    }
    """

    BINDINGS = [
        Binding("q", "request_quit", "Quit"),
        Binding("l", "load_binary", "Load"),
        Binding("c", "close_binary", "Close"),
        Binding("s", "toggle_server", "Server"),
        Binding("tab", "cycle_active", "Cycle"),
        Binding("m", "show_binary_menu", "Menu"),
    ]

    QUIT_CONFIRM_TIMEOUT = 2.0

    def __init__(
        self,
        session_manager: "SessionManager",
        bn_log_path: str | None = None,
    ) -> None:
        super().__init__()
        self.session_manager = session_manager
        self._bn_log_path = bn_log_path
        self._log_tail_running = False
        self._quit_pending_time: float | None = None
        self._thread_id = threading.get_ident()

        # Wire up callbacks
        self.session_manager.on_binary_loaded = self._on_binary_loaded
        self.session_manager.on_binary_closed = self._on_binary_closed
        self.session_manager.on_active_changed = self._on_active_changed
        self.session_manager.on_request = self._on_request
        self.session_manager.on_server_changed = self._on_server_changed
        self.session_manager.on_bn_log = self._on_bn_log
        self.session_manager.on_operation = self._on_operation

        # Don't suppress BN output in TUI mode
        self.session_manager.suppress_bn_output = False

    def on_mount(self) -> None:
        self._update_status()
        if self._bn_log_path:
            self._start_log_tail()
        self._auto_start_server()

    def _auto_start_server(self) -> None:
        try:
            url = self.session_manager.start_server()
            self._log_info(f"Server started at {url}")
        except Exception as e:
            self._log_info(f"ERROR: {e}")

    def _start_log_tail(self) -> None:
        import time
        self._log_tail_running = True

        def tailer():
            try:
                with open(self._bn_log_path, "r") as f:
                    f.seek(0, 2)
                    while self._log_tail_running:
                        line = f.readline()
                        if line:
                            self.call_from_thread(self._add_bn_log, line.rstrip(), "LOG")
                        else:
                            time.sleep(0.1)
            except (OSError, IOError):
                # Log file may be deleted or inaccessible - stop tailing silently
                pass

        thread = threading.Thread(target=tailer, daemon=True)
        thread.start()

    def on_unmount(self) -> None:
        self._log_tail_running = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main-container"):
            with Vertical(id="binary-panel"):
                yield BinaryPanel(self.session_manager)
            with Vertical(id="logs-panel"):
                yield LogTabs()
                yield OperationsPanel()
        yield ServerStatus(id="status-bar")
        yield Footer()

    def _safe_call(self, callback: Callable, *args, **kwargs) -> None:
        if self._thread_id == threading.get_ident():
            callback(*args, **kwargs)
        else:
            self.call_from_thread(callback, *args, **kwargs)

    def _on_binary_loaded(self, session) -> None:
        self._safe_call(self._refresh_binary_panel)
        self._safe_call(self._update_status)
        self._safe_call(self._log_info, f"Loaded: {session.name}")

    def _on_binary_closed(self, session) -> None:
        self._safe_call(self._refresh_binary_panel)
        self._safe_call(self._update_status)
        self._safe_call(self._log_info, f"Closed: {session.name}")

    def _on_active_changed(self, session) -> None:
        self._safe_call(self._refresh_binary_panel)
        self._safe_call(self._update_status)
        self._safe_call(self._log_info, f"Switched to: {session.name}")

    def _on_request(self, method: str, path: str, is_error: bool) -> None:
        self.call_from_thread(self._add_request_entry, method, path, is_error)

    def _on_server_changed(self, running: bool) -> None:
        self._safe_call(self._update_status)

    def _on_bn_log(self, message: str, level: str) -> None:
        self.call_from_thread(self._add_bn_log, message, level)

    def _on_operation(self, description: str) -> None:
        self.call_from_thread(self._add_operation_entry, description)

    def _refresh_binary_panel(self) -> None:
        # NoMatches: widget may not be mounted yet
        try:
            self.query_one(BinaryPanel).refresh_table()
        except NoMatches:
            pass

    def _update_status(self) -> None:
        # NoMatches: widget may not be mounted yet
        try:
            status = self.query_one(ServerStatus)
            status.running = self.session_manager.server_running
            status.binary_count = len(self.session_manager.sessions)
            if status.running:
                url = f"http://{self.session_manager.config.host}:{self.session_manager.config.port}"
                status.url = url
                self.sub_title = f"Server: Running @ {url}"
            else:
                self.sub_title = "Server: Stopped"

            if self.session_manager.active:
                status.active_name = self.session_manager.active.name
            else:
                status.active_name = ""
        except NoMatches:
            pass

    def _add_request_entry(self, method: str, path: str, is_error: bool) -> None:
        # NoMatches: widget may not be mounted yet
        try:
            self.query_one(LogTabs).add_request(method, path, is_error)
        except NoMatches:
            pass

    def _log_info(self, message: str) -> None:
        # NoMatches: widget may not be mounted yet
        try:
            self.query_one(LogTabs).add_request("INFO", message, False)
        except NoMatches:
            pass

    def _add_bn_log(self, message: str, level: str = "INFO") -> None:
        # NoMatches: widget may not be mounted yet
        try:
            self.query_one(LogTabs).add_bn_log(message, level)
        except NoMatches:
            pass

    def _add_operation_entry(self, description: str) -> None:
        # NoMatches: widget may not be mounted yet
        try:
            self.query_one(OperationsPanel).add_operation(description)
        except NoMatches:
            pass

    def action_load_binary(self) -> None:
        def handle_result(path: str | None) -> None:
            if path:
                self._load_binary_async(path)
        self.push_screen(FileSelectModal(), handle_result)

    def _load_binary_async(self, path: str) -> None:
        p = Path(path).expanduser()
        if not p.exists():
            self._log_info(f"ERROR: File not found: {path}")
            return
        self._log_info(f"Loading {p.name}...")
        self.run_worker(
            lambda: self.session_manager.load_binary(p),
            name=f"load:{p.name}",
            thread=True,
        )

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.name and event.worker.name.startswith("load:"):
            if event.state == WorkerState.SUCCESS:
                if event.worker.result is None:
                    name = event.worker.name.removeprefix("load:")
                    self._log_info(f"ERROR: Failed to load: {name}")
            elif event.state == WorkerState.ERROR:
                name = event.worker.name.removeprefix("load:")
                self._log_info(f"ERROR: Failed to load {name}: {event.worker.error}")

    def action_close_binary(self) -> None:
        if self.session_manager.active:
            self.session_manager.close_binary(self.session_manager.active.path)

    def action_toggle_server(self) -> None:
        if self.session_manager.server_running:
            self.session_manager.stop_server()
            self._log_info("Server stopped")
        else:
            try:
                url = self.session_manager.start_server()
                self._log_info(f"Server started at {url}")
            except Exception as e:
                self._log_info(f"ERROR: {e}")

    def action_request_quit(self) -> None:
        import time
        now = time.time()
        if (
            self._quit_pending_time is not None
            and (now - self._quit_pending_time) < self.QUIT_CONFIRM_TIMEOUT
        ):
            self.exit()
        else:
            self._quit_pending_time = now
            self.notify(
                "Press q again to quit",
                severity="warning",
                title="Confirm Quit",
                timeout=self.QUIT_CONFIRM_TIMEOUT,
            )

    def action_cycle_active(self) -> None:
        sessions = self.session_manager.sessions
        if len(sessions) <= 1:
            return
        current = self.session_manager.active
        idx = sessions.index(current) if current in sessions else -1
        next_idx = (idx + 1) % len(sessions)
        self.session_manager.set_active(sessions[next_idx].path)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.control.id == "binary-table":
            if event.row_key:
                self.session_manager.set_active(str(event.row_key.value))

    def on_binary_panel_context_menu_requested(
        self, event: BinaryPanel.ContextMenuRequested
    ) -> None:
        """Handle context menu request from BinaryPanel (right-click)."""
        self._show_binary_context_menu(event.binary_path)

    def action_show_binary_menu(self) -> None:
        """Show context menu for selected binary (keyboard shortcut 'm')."""
        try:
            panel = self.query_one(BinaryPanel)
            binary_path = panel.get_selected_binary_path()
            if binary_path:
                self._show_binary_context_menu(binary_path)
            else:
                self.notify("No binary selected", severity="warning")
        except NoMatches:
            pass

    def _show_binary_context_menu(self, binary_path: str) -> None:
        """Show context menu for a binary."""

        def handle_result(action: str | None) -> None:
            if action == "save":
                self._save_binary(binary_path)
            elif action == "save-as":
                self._save_binary_as(binary_path)
            elif action == "close":
                self.session_manager.close_binary(binary_path)

        self.push_screen(BinaryContextMenu(), handle_result)

    def _save_binary(self, path: str) -> None:
        """Save binary database to default location."""
        name = Path(path).name
        self._log_info(f"Saving {name}...")

        if self.session_manager.save_binary(path):
            self._log_info(f"Saved: {name}.bndb")
        else:
            self._log_info(f"ERROR: Failed to save {name}")

    def _save_binary_as(self, path: str) -> None:
        """Show save dialog and save binary database."""
        source_path = Path(path)
        default_path = source_path.parent / (source_path.stem + ".bndb")

        def handle_dest(dest: str | None) -> None:
            if dest:
                name = source_path.name
                self._log_info(f"Saving {name} to {dest}...")

                if self.session_manager.save_binary_as(path, dest):
                    self._log_info(f"Saved to: {dest}")
                else:
                    self._log_info(f"ERROR: Failed to save to {dest}")

        self.push_screen(FileSaveModal(default_path=str(default_path)), handle_dest)
