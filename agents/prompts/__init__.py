"""Loader for agent system prompts.

Each prompt is a Markdown file in this directory. ``load_prompt(name)``
returns the file contents.
"""

from pathlib import Path

_PROMPTS_DIR = Path(__file__).resolve().parent


def load_prompt(name: str) -> str:
    path = _PROMPTS_DIR / f"{name}.md"
    if not path.exists():
        raise FileNotFoundError(f"prompt not found: {name}.md in {_PROMPTS_DIR}")
    return path.read_text(encoding="utf-8")
