"""State tracking with checkpoint/rollback support."""

from dataclasses import dataclass
from time import time
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from binaryninja import BinaryView


@dataclass
class Checkpoint:
    """Represents a saved analysis state."""

    name: str
    timestamp: float
    undo_action_count: int


class StateTracker:
    """Tracks analysis state for checkpoint/rollback support."""

    def __init__(self, bv: "BinaryView", enabled: bool = True):
        self._bv = bv
        self._enabled = enabled
        self.checkpoints: list[Checkpoint] = []
        self.pending_changes: list[str] = []

        # Callback for operation logging (used by TUI)
        self.on_operation: Optional[Callable[[str], None]] = None

    def record_change(self, description: str) -> None:
        """Record a mutation for tracking."""
        if self._enabled:
            self.pending_changes.append(description)
            if self.on_operation:
                self.on_operation(description)

    def create_checkpoint(self, name: str) -> bool:
        """Create named checkpoint at current state."""
        if any(cp.name == name for cp in self.checkpoints):
            return False

        # Get current undo stack depth
        undo_count = 0
        try:
            undo_count = len(list(self._bv.undoable_actions()))
        except (AttributeError, TypeError):
            pass

        self.checkpoints.append(
            Checkpoint(name=name, timestamp=time(), undo_action_count=undo_count)
        )
        self.pending_changes.clear()
        return True

    def rollback(self, name: str) -> bool:
        """Rollback to named checkpoint."""
        checkpoint = next((cp for cp in self.checkpoints if cp.name == name), None)
        if not checkpoint:
            return False

        try:
            current_count = len(list(self._bv.undoable_actions()))
            undo_count = current_count - checkpoint.undo_action_count

            for _ in range(undo_count):
                self._bv.undo()
        except (AttributeError, TypeError):
            return False

        # Remove checkpoints created after this one
        self.checkpoints = [
            cp for cp in self.checkpoints if cp.timestamp <= checkpoint.timestamp
        ]
        self.pending_changes.clear()
        return True

    def get_summary(self) -> str:
        """Generate context summary for LLM."""
        if not self._enabled:
            return "# State tracking: disabled"

        lines = ["# Session state:"]

        if self.checkpoints:
            latest = self.checkpoints[-1]
            age = int(time() - latest.timestamp)
            age_str = f"{age}s ago" if age < 60 else f"{age // 60}m ago"
            lines.append(f'#   Checkpoint: "{latest.name}" ({age_str})')
        else:
            lines.append("#   Checkpoint: none")

        if self.pending_changes:
            lines.append(f"#   Pending changes: {len(self.pending_changes)}")

        lines.append(f"#   Rollback available: {'yes' if self.checkpoints else 'no'}")

        return "\n".join(lines)

    def list_checkpoints(self) -> list[dict]:
        """List all checkpoints."""
        return [{"name": cp.name, "timestamp": cp.timestamp} for cp in self.checkpoints]
