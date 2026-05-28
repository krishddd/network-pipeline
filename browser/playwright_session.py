"""BrowserSession — sole definition of the Playwright-backed browser session.

Single source of truth. All imports of BrowserSession come from here.
tools/runtime.get_browser_session() lazy-imports this module.

Raises BrowserUnavailable if playwright is not installed.
Install: pip install playwright && playwright install chromium
"""

from __future__ import annotations

import importlib.util
from typing import Any

from network_pipeline.core.logging import get_logger

log = get_logger("browser.playwright_session")


class BrowserUnavailable(RuntimeError):
    """Raised when playwright is not installed."""


def _require_playwright() -> Any:
    if importlib.util.find_spec("playwright") is None:
        raise BrowserUnavailable(
            "playwright not installed. "
            "Run: pip install playwright && playwright install chromium"
        )
    from playwright.async_api import async_playwright
    return async_playwright


class BrowserSession:
    """Async Playwright browser session for DOM-level testing."""

    def __init__(self, *, headless: bool = True) -> None:
        self._headless = headless
        self._pw: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None
        self._started = False

    @classmethod
    def is_available(cls) -> bool:
        """Return True if playwright is importable."""
        return importlib.util.find_spec("playwright") is not None

    async def start(self, auth_state: dict | None = None) -> "BrowserSession":
        """Launch headless Chromium. Call before using navigation methods."""
        async_playwright = _require_playwright()
        self._pw = await async_playwright().__aenter__()
        self._browser = await self._pw.chromium.launch(headless=self._headless)
        self._context = await self._browser.new_context(
            storage_state=auth_state,
            viewport={"width": 1280, "height": 800},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
        )
        self._page = await self._context.new_page()
        self._started = True
        log.info("BrowserSession started (headless=%s)", self._headless)
        return self

    async def stop(self) -> None:
        """Close the browser and Playwright instance."""
        if self._browser:
            await self._browser.close()
        if self._pw:
            await self._pw.__aexit__(None, None, None)
        self._started = False

    async def __aenter__(self) -> "BrowserSession":
        return await self.start()

    async def __aexit__(self, *_: Any) -> None:
        await self.stop()

    # ── Navigation ─────────────────────────────────────────────────────────────

    async def navigate(self, url: str, *, wait_until: str = "domcontentloaded") -> str:
        """Navigate to url; return page HTML."""
        self._assert_started()
        try:
            await self._page.goto(url, wait_until=wait_until, timeout=15_000)
            return await self._page.content()
        except Exception as e:
            log.debug("navigate %s failed: %s", url, e)
            return ""

    async def extract_links(self) -> list[str]:
        """Extract all href links from the current page."""
        self._assert_started()
        try:
            links = await self._page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)"
            )
            return [l for l in links if isinstance(l, str)]
        except Exception:
            return []

    async def extract_forms(self) -> list[dict]:
        """Extract all forms and their input fields from the current page."""
        self._assert_started()
        try:
            forms = await self._page.evaluate("""() => {
                return Array.from(document.forms).map(f => ({
                    action: f.action,
                    method: f.method,
                    inputs: Array.from(f.elements).map(e => ({
                        name: e.name,
                        type: e.type,
                        value: e.value
                    }))
                }));
            }""")
            return forms or []
        except Exception:
            return []

    async def evaluate(self, expression: str) -> Any:
        """Evaluate a JavaScript expression in the page context."""
        self._assert_started()
        try:
            return await self._page.evaluate(expression)
        except Exception:
            return None

    async def find_dom_xss(self, canary: str) -> bool:
        """Return True if canary string is found in a DOM sink (innerHTML etc)."""
        self._assert_started()
        try:
            result = await self._page.evaluate(f"""(() => {{
                const canary = {canary!r};
                // Check common DOM sinks
                const body = document.body.innerHTML;
                if (body.includes(canary)) return 'innerHTML';
                const scripts = Array.from(document.scripts).map(s => s.innerHTML).join('');
                if (scripts.includes(canary)) return 'script';
                return null;
            }})()""")
            return result is not None
        except Exception:
            return False

    async def screenshot(self, out_path: str) -> bool:
        """Take a screenshot and save to out_path."""
        self._assert_started()
        try:
            await self._page.screenshot(path=out_path, full_page=True)
            return True
        except Exception as e:
            log.debug("screenshot failed: %s", e)
            return False

    async def submit_login(self, url: str, fields: dict[str, str]) -> dict:
        """Fill and submit a login form; return storage_state (cookies + localStorage)."""
        self._assert_started()
        try:
            await self.navigate(url)
            for selector, value in fields.items():
                await self._page.fill(selector, value)
            await self._page.keyboard.press("Enter")
            await self._page.wait_for_load_state("networkidle", timeout=10_000)
            state = await self._context.storage_state()
            return state
        except Exception as e:
            log.debug("submit_login failed: %s", e)
            return {}

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _assert_started(self) -> None:
        if not self._started:
            raise RuntimeError("BrowserSession not started; call start() first")
