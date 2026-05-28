"""High-level auth helpers built on BrowserSession.

login_with_form(url, user, password) → Playwright storage_state dict
extract_session_state()              → current cookies + localStorage
"""

from __future__ import annotations

from typing import Any

from network_pipeline.browser.playwright_session import BrowserSession
from network_pipeline.core.logging import get_logger

log = get_logger("browser.auth_flows")


async def login_with_form(
    session: BrowserSession,
    url: str,
    username: str,
    password: str,
    *,
    username_selector: str = "input[type='text'],input[name='username'],input[name='email']",
    password_selector: str = "input[type='password']",
) -> dict:
    """Fill and submit a login form; return Playwright storage_state."""
    try:
        await session.navigate(url)
        # Try to fill username field
        page = session._page
        if page is None:
            return {}
        for sel in username_selector.split(","):
            try:
                el = await page.query_selector(sel.strip())
                if el:
                    await el.fill(username)
                    break
            except Exception:
                continue
        # Fill password
        pw_el = await page.query_selector(password_selector.strip())
        if pw_el:
            await pw_el.fill(password)
        # Submit
        await page.keyboard.press("Enter")
        await page.wait_for_load_state("networkidle", timeout=10_000)
        state = await session._context.storage_state()
        log.info("login_with_form: obtained storage_state with %d cookies",
                 len(state.get("cookies", [])))
        return state
    except Exception as e:
        log.debug("login_with_form failed: %s", e)
        return {}


async def extract_session_state(session: BrowserSession) -> dict:
    """Return the current Playwright storage state (cookies + origins)."""
    try:
        return await session._context.storage_state()
    except Exception:
        return {}
