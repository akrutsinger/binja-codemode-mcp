import json
import os
from dataclasses import dataclass, field
from pathlib import Path

# Default API key for localhost-only access.
# This is NOT a security boundary - the server only binds to 127.0.0.1.
# The key prevents accidental connections from other local software.
DEFAULT_API_KEY = "binja-codemode-local"


def _get_binja_user_dir() -> Path:
    """Get Binary Ninja's user directory based on platform."""
    if os.name == "nt":  # Windows
        base = Path(os.environ.get("APPDATA", Path.home()))
        return base / "Binary Ninja"
    elif os.name == "posix":
        import platform

        if platform.system() == "Darwin":  # macOS
            return Path.home() / "Library" / "Application Support" / "Binary Ninja"
        else:  # Linux
            return Path.home() / ".binaryninja"
    else:
        return Path.home() / ".binaryninja"


def _default_data_dir() -> Path:
    """Get default data directory for workspace and skills."""
    return _get_binja_user_dir() / "codemode_mcp"


def _load_api_key(data_dir: Path) -> str:
    """
    Load API key from config file, or return default.

    Users can override by creating config.json with {"api_key": "custom-key"}
    """
    config_file = data_dir / "config.json"

    if config_file.exists():
        try:
            with open(config_file, "r") as f:
                config = json.load(f)
                if "api_key" in config:
                    return config["api_key"]
        except (json.JSONDecodeError, IOError):
            pass

    return DEFAULT_API_KEY


@dataclass
class Config:
    """Configuration for the Code Mode MCP server."""

    # Server settings
    host: str = "127.0.0.1"
    port: int = 42069
    api_key: str = field(default="")

    # Execution settings
    enable_state_tracking: bool = True
    max_output_bytes: int = 100_000
    execution_timeout_s: float = 30.0  # seconds

    # Session settings (for multi-agent support)
    session_timeout_s: float = 3600.0  # 1 hour
    max_sessions: int = 10

    # Persistence settings
    data_dir: Path = field(default_factory=_default_data_dir)

    @property
    def workspace_dir(self) -> Path:
        """Directory for workspace files."""
        return self.data_dir / "workspace"

    @property
    def skills_dir(self) -> Path:
        """Directory for saved skills."""
        return self.data_dir / "skills"

    # Logging
    log_executions: bool = True

    def __post_init__(self):
        """Load API key from config file or use default."""
        if not self.api_key:
            self.api_key = _load_api_key(self.data_dir)

    def ensure_dirs(self):
        """Create data directories if they don't exist."""
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.skills_dir.mkdir(parents=True, exist_ok=True)
