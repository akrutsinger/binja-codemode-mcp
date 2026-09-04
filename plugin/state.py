"""State tracking with checkpoint/rollback support."""

from dataclasses import dataclass
from time import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from binaryninja import BinaryView


@dataclass
class Checkpoint:
    """Represents a saved analysis state."""

    name: str
    timestamp: float
    undo_depth: int


class StateTracker:
    """Tracks analysis state for checkpoint/rollback support."""

    def __init__(self, bv: "BinaryView", enabled: bool = True):
        self._bv = bv
        self._enabled = enabled
        self.checkpoints: list[Checkpoint] = []

    def _undo_depth(self) -> int:
        """How many committed transactions deep the database currently is.

        Binary Ninja commits every mutation made through the API as its own undo entry, whether or
        not the caller opened a transaction, so this counts changes made through `bv` directly just
        as well as those made through BinjaAPI.
        """
        return len(self._bv.file.undo_entries)

    def create_checkpoint(self, name: str) -> bool:
        """Create named checkpoint at current state."""
        if any(cp.name == name for cp in self.checkpoints):
            return False

        self.checkpoints.append(
            Checkpoint(name=name, timestamp=time(), undo_depth=self._undo_depth())
        )
        return True

    def rollback(self, name: str) -> bool:
        """Rollback to named checkpoint."""
        checkpoint = next((cp for cp in self.checkpoints if cp.name == name), None)
        if not checkpoint:
            return False

        # Undoing back down to the recorded depth, rather than undoing a counted number of
        # actions, so a redo or a change made in the GUI cannot leave the two out of step.
        for _ in range(self._undo_depth() - checkpoint.undo_depth):
            self._bv.undo()

        # Remove checkpoints created after this one
        self.checkpoints = [cp for cp in self.checkpoints if cp.timestamp <= checkpoint.timestamp]
        return True

    def get_summary(self) -> str:
        """Generate context summary for LLM."""
        if not self._enabled:
            return "State tracking: disabled"

        if not self.checkpoints:
            return "Session: Latest checkpoint: none, so nothing can be rolled back yet"

        latest = self.checkpoints[-1]
        age = int(time() - latest.timestamp)
        age_str = f"{age}s ago" if age < 60 else f"{age // 60}m ago"
        parts = [f'Latest checkpoint: "{latest.name}" ({age_str})']

        # Counted off the undo stack rather than tallied as each mutation is made, so changes the
        # executed code made through `bv` directly are included.
        changes = self._undo_depth() - latest.undo_depth
        if changes:
            parts.append(f"{changes} change(s) since it")

        return "Session: " + " | ".join(parts)

    def list_checkpoints(self) -> list[dict]:
        """List all checkpoints."""
        return [{"name": cp.name, "timestamp": cp.timestamp} for cp in self.checkpoints]
