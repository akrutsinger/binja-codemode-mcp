import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

# Default API key for localhost-only access.
# This is NOT a security boundary - the server only binds to 127.0.0.1.
# The key prevents accidental connections from other local software.
DEFAULT_API_KEY = "binja-codemode-local"


def plugin_version() -> str:
    """Read the version from plugin.json, which is the manifest the plugin manager ships."""
    try:
        manifest = json.loads((Path(__file__).parent / "plugin.json").read_text())
        return manifest.get("version", "unknown")
    except (json.JSONDecodeError, OSError):
        return "unknown"


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


def workspace_key(bv) -> str:
    """A directory name for one binary's workspace files.

    Readable first and unique second: the binary's own filename, so the directory can be found by
    hand, followed by a digest of its full path, so two binaries with the same name do not share
    one. Keyed on the path rather than the contents, because hashing a large binary on every
    startup would cost more than it is worth - moving a binary presents an empty workspace, and
    the old files are still on disk under the old name.
    """
    source = getattr(bv.file, "original_filename", "") or bv.file.filename or "unnamed"
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()[:8]
    stem = re.sub(r"[^\w.-]+", "_", Path(source).name)[:64] or "unnamed"
    return f"{stem}-{digest}"


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
        except (OSError, json.JSONDecodeError):
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
    max_output_tokens: int = 6_000
    execution_timeout_s: float = 30.0  # seconds

    # Persistence settings
    data_dir: Path = field(default_factory=_default_data_dir)

    @property
    def workspace_dir(self) -> Path:
        """Root of the per-binary workspace directories."""
        return self.data_dir / "workspace"

    def workspace_dir_for(self, bv) -> Path:
        """Where this binary's workspace files live.

        Per binary, because workspace files are results about the binary in front of you: a
        decompilation, a report, a list of candidates. Shared across binaries they were both
        misleading - a previous binary's notes are advertised as this one's context - and unsafe,
        since two sessions writing `analysis.md` clobbered each other. Skills stay shared, being
        code that is meant to work on any binary.
        """
        return self.workspace_dir / workspace_key(bv)

    @property
    def skills_dir(self) -> Path:
        """Directory for saved skills."""
        return self.data_dir / "skills"

    def __post_init__(self):
        """Load API key from config file or use default."""
        if not self.api_key:
            self.api_key = _load_api_key(self.data_dir)

    def ensure_dirs(self):
        """Create data directories if they don't exist."""
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.skills_dir.mkdir(parents=True, exist_ok=True)
