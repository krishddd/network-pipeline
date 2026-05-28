"""Progressive skill discovery loader.

Implements the Decepticon "skill disclosure" pattern in a stripped-down
form: agents see a directory of available SKILL.md titles for their
category and request the full text on demand. The loader treats the
``skills/`` tree as read-only.

Skill catalog format: each ``SKILL.md`` is parsed for its leading H1
heading as the title; the path becomes the key.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from network_pipeline.core.logging import get_logger

log = get_logger("tools.skills")


SKILLS_ROOT = Path(__file__).resolve().parent.parent / "skills"

# Map agent role → which top-level skill folders that agent should see.
# "shared" is included in every role for opsec / finding-protocol / workflow.
ROLE_TO_SKILL_DIRS: dict[str, tuple[str, ...]] = {
    "orchestrator": ("shared",),
    "recon": ("recon", "shared"),
    "scanner": ("scanner", "recon", "shared"),
    "exploit": ("exploit", "analyst", "shared"),
    "postexploit": ("post-exploit", "shared"),
    "analyst": ("analyst", "shared"),
    "defender": ("detector", "shared"),
    "verifier": ("exploit", "analyst", "shared"),
    "llm_redteam": ("shared",),
}


_HEADING_RE = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class SkillEntry:
    rel_path: str  # relative to SKILLS_ROOT
    title: str
    abs_path: Path

    def to_brief(self) -> str:
        return f"- {self.rel_path}: {self.title}"


def _read_title(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return path.parent.name
    m = _HEADING_RE.search(text)
    if m:
        return m.group(1).strip()
    return path.parent.name


def list_skills(role: str, root: Path = SKILLS_ROOT) -> list[SkillEntry]:
    """List SKILL.md files visible to ``role``."""
    dirs = ROLE_TO_SKILL_DIRS.get(role, ("shared",))
    out: list[SkillEntry] = []
    for d in dirs:
        base = root / d
        if not base.exists():
            continue
        for skill_file in sorted(base.rglob("SKILL.md")):
            rel = skill_file.relative_to(root).as_posix()
            out.append(
                SkillEntry(
                    rel_path=rel,
                    title=_read_title(skill_file),
                    abs_path=skill_file,
                )
            )
    return out


def read_skill(rel_path: str, root: Path = SKILLS_ROOT) -> str:
    """Return the SKILL.md body. Refuses any path that escapes SKILLS_ROOT."""
    candidate = (root / rel_path).resolve()
    root_resolved = root.resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError:
        raise PermissionError(f"skill path escapes SKILLS_ROOT: {rel_path}")
    if not candidate.exists() or candidate.name != "SKILL.md":
        raise FileNotFoundError(f"no SKILL.md at {rel_path}")
    return candidate.read_text(encoding="utf-8", errors="replace")


def skill_index_text(role: str) -> str:
    """A compact catalog string suitable for inclusion in a system prompt."""
    entries = list_skills(role)
    if not entries:
        return "(no skills available)"
    lines = [f"Available skills for {role!r} (read with read_skill(rel_path)):"]
    for e in entries:
        lines.append(e.to_brief())
    return "\n".join(lines)
