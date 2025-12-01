"""Workspace and Skills persistence for Code Mode MCP."""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Valid filename pattern: alphanumeric, underscore, hyphen, dot
_VALID_FILENAME = re.compile(r"^[\w\-\.]+$")
_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


def _validate_name(name: str) -> bool:
    """Validate file/skill name for safety."""
    if not name or len(name) > 255:
        return False
    if not _VALID_FILENAME.match(name):
        return False
    if ".." in name or name.startswith("/") or name.startswith("\\"):
        return False
    return True


@dataclass
class Skill:
    """Represents a saved reusable analysis skill."""

    name: str
    description: str
    code: str


class WorkspaceManager:
    """Manages workspace files for the current session."""

    def __init__(self, workspace_dir: Path):
        self._dir = workspace_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    def write(self, name: str, content: str) -> bool:
        """Write content to workspace file."""
        if not _validate_name(name):
            return False
        if len(content.encode("utf-8")) > _MAX_FILE_SIZE:
            return False

        path = self._dir / name
        path.write_text(content, encoding="utf-8")
        return True

    def read(self, name: str) -> Optional[str]:
        """Read content from workspace file."""
        if not _validate_name(name):
            return None

        path = self._dir / name
        if not path.exists() or not path.is_file():
            return None

        return path.read_text(encoding="utf-8")

    def list(self) -> list[dict]:
        """List all workspace files with metadata."""
        files = []
        for path in self._dir.iterdir():
            if path.is_file() and not path.name.startswith("."):
                stat = path.stat()
                files.append(
                    {
                        "name": path.name,
                        "size": stat.st_size,
                        "modified": stat.st_mtime,
                    }
                )
        return sorted(files, key=lambda f: f["name"])

    def delete(self, name: str) -> bool:
        """Delete a workspace file."""
        if not _validate_name(name):
            return False

        path = self._dir / name
        if not path.exists() or not path.is_file():
            return False

        path.unlink()
        return True

    def clear(self) -> int:
        """Clear all workspace files. Returns count deleted."""
        count = 0
        for path in self._dir.iterdir():
            if path.is_file():
                path.unlink()
                count += 1
        return count


class SkillsManager:
    """Manages reusable code skills that persist across sessions."""

    def __init__(self, skills_dir: Path):
        self._dir = skills_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    def _skill_path(self, name: str) -> Path:
        """Get path for skill file."""
        return self._dir / f"{name}.json"

    def save(self, name: str, code: str, description: str) -> bool:
        """Save a skill."""
        if not _validate_name(name):
            return False

        skill_data = {
            "name": name,
            "description": description,
            "code": code,
        }

        path = self._skill_path(name)
        path.write_text(json.dumps(skill_data, indent=2), encoding="utf-8")
        return True

    def load(self, name: str) -> Optional[Skill]:
        """Load a skill by name."""
        if not _validate_name(name):
            return None

        path = self._skill_path(name)
        if not path.exists():
            return None

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return Skill(
                name=data["name"],
                description=data["description"],
                code=data["code"],
            )
        except (json.JSONDecodeError, KeyError):
            return None

    def list(self) -> list[dict]:
        """List all skills with descriptions."""
        skills = []
        for path in self._dir.glob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                skills.append(
                    {
                        "name": data["name"],
                        "description": data["description"],
                    }
                )
            except (json.JSONDecodeError, KeyError):
                continue
        return sorted(skills, key=lambda s: s["name"])

    def delete(self, name: str) -> bool:
        """Delete a skill."""
        if not _validate_name(name):
            return False

        path = self._skill_path(name)
        if not path.exists():
            return False

        path.unlink()
        return True

    def get_code(self, name: str) -> Optional[str]:
        """Get just the code for a skill."""
        skill = self.load(name)
        return skill.code if skill else None
