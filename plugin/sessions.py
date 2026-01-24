"""Session management for concurrent multi-agent support.

This module provides:
- BinaryPool: Shared BinaryView instances (loaded once, shared across sessions)
- AgentSession: Per-agent isolated state (checkpoints, executors per binary)
- SessionRegistry: Thread-safe session management with ref-counting
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from time import time
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    import binaryninja

    from .api import BinjaAPI
    from .executor import CodeExecutor
    from .state import StateTracker
    from .workspace import SkillsManager, WorkspaceManager


DEFAULT_SESSION_ID = "_default_"


class BinaryLoadError(Exception):
    """Raised when a binary fails to load."""

    pass


@dataclass
class LoadedBinary:
    """A shared binary with reference counting."""

    path: Path
    bv: "binaryninja.BinaryView"
    ref_count: int = 0
    loaded_at: float = field(default_factory=time)

    @property
    def name(self) -> str:
        return self.path.name


class BinaryPool:
    """Manages shared BinaryView instances.

    Binaries are loaded once and shared across all agent sessions.
    Reference counting ensures binaries are only closed when no sessions need them.
    """

    def __init__(self, suppress_output: bool = True):
        self._binaries: dict[str, LoadedBinary] = {}
        self._lock = threading.RLock()
        self.suppress_output = suppress_output

        # Callbacks
        self.on_binary_loaded: Optional[Callable[[LoadedBinary], None]] = None
        self.on_binary_closed: Optional[Callable[[LoadedBinary], None]] = None

    def load(self, path: str | Path) -> LoadedBinary:
        """Load a binary if not already loaded. Returns existing if present.

        Args:
            path: Path to binary file

        Returns:
            LoadedBinary with the BinaryView

        Raises:
            BinaryLoadError: If file doesn't exist or fails to load
        """
        import binaryninja

        from headless.session import _suppress_output

        path = Path(path).expanduser().resolve()
        key = str(path)

        with self._lock:
            if key in self._binaries:
                return self._binaries[key]

            if not path.exists():
                raise BinaryLoadError(f"File not found: {path}")
            if not path.is_file():
                raise BinaryLoadError(f"Not a file: {path}")

            try:
                with _suppress_output(self.suppress_output):
                    bv = binaryninja.load(str(path))
                    if bv:
                        bv.update_analysis_and_wait()
            except Exception as e:
                raise BinaryLoadError(f"Binary Ninja error: {e}")

            if bv is None:
                raise BinaryLoadError(
                    f"Unsupported binary format or architecture: {path.name}"
                )

            loaded = LoadedBinary(path=path, bv=bv)
            self._binaries[key] = loaded

        # Call callback outside the lock to avoid deadlocks
        if self.on_binary_loaded:
            self.on_binary_loaded(loaded)

        return loaded

    def get(self, path: str | Path) -> Optional[LoadedBinary]:
        """Get a loaded binary by path."""
        key = str(Path(path).resolve())
        with self._lock:
            return self._binaries.get(key)

    def acquire(self, path: str | Path) -> Optional[LoadedBinary]:
        """Acquire a reference to a binary (increment ref count)."""
        key = str(Path(path).resolve())
        with self._lock:
            loaded = self._binaries.get(key)
            if loaded:
                loaded.ref_count += 1
            return loaded

    def release(self, path: str | Path) -> bool:
        """Release a reference to a binary (decrement ref count).

        Binary is closed when ref_count reaches 0.

        Returns:
            True if binary was closed, False otherwise
        """
        from headless.session import _suppress_output

        key = str(Path(path).resolve())
        closed_binary = None

        with self._lock:
            loaded = self._binaries.get(key)
            if not loaded:
                return False

            loaded.ref_count -= 1

            if loaded.ref_count <= 0:
                del self._binaries[key]
                closed_binary = loaded

        # Close and callback outside the lock
        if closed_binary:
            if self.on_binary_closed:
                self.on_binary_closed(closed_binary)

            with _suppress_output(self.suppress_output):
                closed_binary.bv.file.close()

            return True

        return False

    def close(self, path: str | Path, force: bool = False) -> bool:
        """Close a binary.

        Args:
            path: Path to binary
            force: If True, close even if ref_count > 0

        Returns:
            True if closed, False if not found or still referenced
        """
        from headless.session import _suppress_output

        key = str(Path(path).resolve())
        closed_binary = None

        with self._lock:
            loaded = self._binaries.get(key)
            if not loaded:
                return False

            if not force and loaded.ref_count > 0:
                return False

            del self._binaries[key]
            closed_binary = loaded

        # Close and callback outside the lock
        if self.on_binary_closed:
            self.on_binary_closed(closed_binary)

        with _suppress_output(self.suppress_output):
            closed_binary.bv.file.close()

        return True

    def list(self) -> list[dict]:
        """List all loaded binaries."""
        with self._lock:
            return [
                {
                    "path": str(loaded.path),
                    "name": loaded.name,
                    "ref_count": loaded.ref_count,
                    "loaded_at": loaded.loaded_at,
                }
                for loaded in self._binaries.values()
            ]

    def close_all(self):
        """Close all binaries."""
        from headless.session import _suppress_output

        with self._lock:
            binaries_to_close = list(self._binaries.values())
            self._binaries.clear()

        # Close and callback outside the lock
        for loaded in binaries_to_close:
            if self.on_binary_closed:
                self.on_binary_closed(loaded)

            with _suppress_output(self.suppress_output):
                loaded.bv.file.close()


@dataclass
class BinaryComponents:
    """Per-session components for a specific binary."""

    api: "BinjaAPI"
    state: "StateTracker"
    executor: "CodeExecutor"


@dataclass
class AgentSession:
    """Represents an agent's isolated session.

    Each session has:
    - Its own active binary selection
    - Isolated StateTracker per binary (separate checkpoints)
    - Isolated CodeExecutor per binary
    - Its own workspace directory (where analysis files are written)
    """

    session_id: str
    client_name: str = ""
    created_at: float = field(default_factory=time)
    last_active: float = field(default_factory=time)

    # Workspace directory for this session (where files are written)
    workspace_dir: Optional[str] = None

    # Current active binary for this session
    active_binary: Optional[Path] = None

    # Per-binary components (isolated per session)
    _components: dict[str, BinaryComponents] = field(default_factory=dict)

    # References to binaries this session is using
    _binary_refs: set[str] = field(default_factory=set)

    def touch(self):
        """Update last_active timestamp."""
        self.last_active = time()

    def get_components(self, path: str | Path) -> Optional[BinaryComponents]:
        """Get components for a binary in this session."""
        key = str(Path(path).resolve())
        return self._components.get(key)

    def set_components(self, path: str | Path, components: BinaryComponents):
        """Set components for a binary in this session."""
        key = str(Path(path).resolve())
        self._components[key] = components
        self._binary_refs.add(key)

    def remove_components(self, path: str | Path) -> bool:
        """Remove components for a binary from this session."""
        key = str(Path(path).resolve())
        if key in self._components:
            del self._components[key]
            self._binary_refs.discard(key)
            if self.active_binary and str(self.active_binary.resolve()) == key:
                self.active_binary = None
            return True
        return False

    @property
    def binary_paths(self) -> list[str]:
        """List of binary paths this session has components for."""
        return list(self._binary_refs)


class SessionRegistry:
    """Thread-safe registry of agent sessions.

    Manages session lifecycle and provides session-aware binary operations.
    """

    def __init__(
        self,
        binary_pool: BinaryPool,
        workspace: Optional["WorkspaceManager"] = None,
        skills: Optional["SkillsManager"] = None,
        config: Optional[object] = None,
        session_timeout_s: float = 3600.0,
        max_sessions: int = 10,
    ):
        self._sessions: dict[str, AgentSession] = {}
        self._lock = threading.RLock()
        self.binary_pool = binary_pool
        self.workspace = workspace
        self.skills = skills
        self.config = config
        self.session_timeout_s = session_timeout_s
        self.max_sessions = max_sessions

        # Callbacks
        self.on_session_created: Optional[Callable[[AgentSession], None]] = None
        self.on_session_closed: Optional[Callable[[AgentSession], None]] = None
        self.on_operation: Optional[Callable[[str], None]] = None

    def get_or_create(
        self, session_id: Optional[str] = None, client_name: str = "", workspace_dir: Optional[str] = None
    ) -> AgentSession:
        """Get existing session or create new one.

        Args:
            session_id: Session ID (generates new if None or empty)
            client_name: Optional client identifier for logging
            workspace_dir: Directory for workspace files (updated on each request)

        Returns:
            AgentSession
        """
        if not session_id:
            session_id = str(uuid.uuid4())

        with self._lock:
            if session_id in self._sessions:
                session = self._sessions[session_id]
                session.touch()
                # Update workspace_dir if provided (user may have changed directories)
                if workspace_dir:
                    session.workspace_dir = workspace_dir
                return session

            # Check max sessions
            if len(self._sessions) >= self.max_sessions:
                self._cleanup_oldest()

            session = AgentSession(
                session_id=session_id,
                client_name=client_name,
                workspace_dir=workspace_dir,
            )
            self._sessions[session_id] = session

        # Call callback outside the lock to avoid deadlocks
        if self.on_session_created:
            self.on_session_created(session)

        return session

    def get(self, session_id: str) -> Optional[AgentSession]:
        """Get session by ID."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.touch()
            return session

    def close_session(self, session_id: str) -> bool:
        """Close a session and release all its binary references.

        Returns:
            True if session was closed, False if not found
        """
        with self._lock:
            session = self._sessions.pop(session_id, None)
            if not session:
                return False

            # Release all binary references
            for binary_path in session.binary_paths:
                self.binary_pool.release(binary_path)

        # Call callback outside the lock to avoid deadlocks
        if self.on_session_closed:
            self.on_session_closed(session)

        return True

    def list_sessions(self) -> list[dict]:
        """List all active sessions."""
        with self._lock:
            return [
                {
                    "session_id": s.session_id,
                    "client_name": s.client_name,
                    "active_binary": str(s.active_binary) if s.active_binary else None,
                    "binary_count": len(s.binary_paths),
                    "created_at": s.created_at,
                    "last_active": s.last_active,
                    "idle_s": time() - s.last_active,
                }
                for s in self._sessions.values()
            ]

    def cleanup_expired(self) -> int:
        """Remove expired sessions.

        Returns:
            Number of sessions cleaned up
        """
        now = time()
        expired = []

        with self._lock:
            for session_id, session in self._sessions.items():
                if session_id == DEFAULT_SESSION_ID:
                    continue  # Never expire default session
                if now - session.last_active > self.session_timeout_s:
                    expired.append(session_id)

        count = 0
        for session_id in expired:
            if self.close_session(session_id):
                count += 1

        return count

    def _cleanup_oldest(self):
        """Remove oldest inactive session to make room for new one."""
        with self._lock:
            if not self._sessions:
                return

            # Find oldest non-default session
            oldest_id = None
            oldest_time = float("inf")

            for session_id, session in self._sessions.items():
                if session_id == DEFAULT_SESSION_ID:
                    continue
                if session.last_active < oldest_time:
                    oldest_time = session.last_active
                    oldest_id = session_id

            if oldest_id:
                self.close_session(oldest_id)

    def get_session_components(
        self, session_id: str, binary_path: Optional[str | Path] = None
    ) -> Optional[tuple["BinjaAPI", "StateTracker", "CodeExecutor"]]:
        """Get (api, state, executor) for a session's active or specified binary.

        Args:
            session_id: Session ID
            binary_path: Specific binary path (uses session's active_binary if None)

        Returns:
            Tuple of (api, state, executor) or None if not found
        """
        session = self.get(session_id)
        if not session:
            return None

        if binary_path:
            path = Path(binary_path).resolve()
        elif session.active_binary:
            path = session.active_binary
        else:
            return None

        components = session.get_components(path)
        if components:
            return (components.api, components.state, components.executor)

        return None

    def load_binary_for_session(
        self, session_id: str, path: str | Path
    ) -> Optional[tuple["BinjaAPI", "StateTracker", "CodeExecutor"]]:
        """Load a binary for a session, creating session-specific components.

        Args:
            session_id: Session ID
            path: Path to binary

        Returns:
            Tuple of (api, state, executor) or None if load failed
        """
        from .api import BinjaAPI
        from .executor import CodeExecutor
        from .state import StateTracker

        session = self.get(session_id)
        if not session:
            return None

        path = Path(path).resolve()
        key = str(path)

        # Check if session already has components for this binary
        existing = session.get_components(path)
        if existing:
            session.active_binary = path
            return (existing.api, existing.state, existing.executor)

        # Load binary into pool (or get existing)
        loaded = self.binary_pool.load(path)
        if not loaded:
            return None

        # Acquire reference for this session
        self.binary_pool.acquire(path)

        # Create session-specific components
        state = StateTracker(loaded.bv, enabled=True)
        if self.on_operation:
            state.on_operation = self.on_operation

        # Use session's workspace directory if set, otherwise fall back to default
        from .workspace import WorkspaceManager
        if session.workspace_dir:
            workspace = WorkspaceManager(Path(session.workspace_dir))
        else:
            workspace = self.workspace

        api = BinjaAPI(loaded.bv, state, workspace, self.skills)

        timeout = 30.0
        max_output = 100_000
        if self.config:
            timeout = getattr(self.config, "execution_timeout_s", 30.0)
            max_output = getattr(self.config, "max_output_bytes", 100_000)

        executor = CodeExecutor(api, max_output_bytes=max_output, timeout=timeout)

        components = BinaryComponents(api=api, state=state, executor=executor)
        session.set_components(path, components)
        session.active_binary = path

        return (api, state, executor)

    def switch_binary_for_session(
        self, session_id: str, path: str | Path
    ) -> bool:
        """Switch a session's active binary.

        Returns:
            True if switched, False if binary not loaded in session
        """
        session = self.get(session_id)
        if not session:
            return False

        path = Path(path).resolve()
        components = session.get_components(path)

        if not components:
            return False

        session.active_binary = path
        return True

    def close_binary_for_session(
        self, session_id: str, path: Optional[str | Path] = None
    ) -> bool:
        """Close a binary for a session (releases session's reference).

        Args:
            session_id: Session ID
            path: Binary path (uses active_binary if None)

        Returns:
            True if closed, False if not found
        """
        session = self.get(session_id)
        if not session:
            return False

        if path:
            path = Path(path).resolve()
        elif session.active_binary:
            path = session.active_binary
        else:
            return False

        if not session.remove_components(path):
            return False

        # Release reference to binary pool
        self.binary_pool.release(path)

        return True

    def get_binaries_info_for_session(self, session_id: str) -> list[dict]:
        """Get info about binaries accessible to a session."""
        session = self.get(session_id)
        if not session:
            return []

        result = []
        for binary_path in session.binary_paths:
            loaded = self.binary_pool.get(binary_path)
            if not loaded:
                continue

            components = session.get_components(binary_path)
            if not components:
                continue

            status = components.api.get_binary_status()
            is_active = (
                session.active_binary
                and str(session.active_binary.resolve()) == binary_path
            )

            result.append(
                {
                    "path": binary_path,
                    "name": loaded.name,
                    "active": is_active,
                    "architecture": status.get("architecture", "unknown"),
                    "function_count": status.get("function_count", 0),
                }
            )

        return result
