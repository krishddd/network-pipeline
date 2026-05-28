"""dalfox wrapper — XSS scanner (reflected / DOM / stored).

dalfox emits JSON via ``--format json``. We collect hits + parameters
into a histogram and return a condensed summary.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from network_pipeline.tools.web._common import truncate

if TYPE_CHECKING:
    from network_pipeline.tools.shell import ShellRunner


def run_dalfox(
    runner: "ShellRunner",
    target: str,
    *,
    method: str = "GET",
    agent: str = "exploit",
    objective_id: str = "",
) -> str:
    """Scan ``target`` for XSS via dalfox."""
    out_path = (
        runner._workspace / "tool_io" / agent
        / f"dalfox_{objective_id or 'noobj'}.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    argv = [
        "url", target,
        "--method", method.upper(),
        "--format", "json",
        "-o", str(out_path),
        "--silence",
        "--no-spinner",
        "--skip-bav",  # skip the basic-app verification stage to keep noise down
    ]
    res = runner.run(
        "dalfox", argv,
        targets=[target], timeout_s=600,
        agent=agent, objective_id=objective_id,
    )
    if not res.ok and res.error:
        return f"[dalfox skipped] {res.error}"

    hits: list[dict] = []
    if out_path.exists():
        try:
            payload = json.loads(out_path.read_text(encoding="utf-8") or "[]")
            if isinstance(payload, list):
                hits = payload
        except json.JSONDecodeError:
            pass

    titles = [
        f"  [{h.get('severity', '?')}] {h.get('type', '?')} on "
        f"{h.get('param', '?')} → {h.get('payload', '')[:80]}"
        for h in hits[:20]
    ]
    summary = (
        f"dalfox against {target}: {len(hits)} XSS candidates\n"
        + "\n".join(titles)
        + f"\nfull JSON: {out_path}"
    )
    return truncate(summary)
