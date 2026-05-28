"""Browser layer — Playwright-based headless browser support.

All code that depends on playwright lives here. The rest of the pipeline
imports via tools/runtime.get_browser_session() so it never directly
imports playwright at module load time.
"""
