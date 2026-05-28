"""Phase-L: universal baseline scan — runs WITHOUT the LLM.

Why this exists:
- Small Ollama models in eco profile (3B-8B) often skip critical
  scanner calls or terminate early after 1-2 tool invocations.
- For ANY web target (not just our 7 curated demos), we want a
  deterministic, exhaustive scan path that runs every applicable
  scanner against an automatically-discovered attack surface.
- The LLM-driven iteration loop runs AFTER this baseline as
  enrichment / synthesis of unexpected findings.

Flow:
  1. discover_attack_surface() — BFS crawl, harvest URLs/params/forms
  2. run_universal_baseline() — invoke every applicable scanner

Findings auto-persist via agents._common.persist_scan_findings into
the engagement's FindingsLog. No LLM is consulted.

Works on:
- ANY HTTP/HTTPS target — no hardcoded paths or domain assumptions.
- The 7 curated allowlist targets get the same treatment as a
  user-supplied custom target.
"""

from __future__ import annotations

import asyncio
import re
from collections import deque
from typing import Any
from urllib.parse import urldefrag, urljoin, urlparse, urlunparse, parse_qs

from network_pipeline.core.logging import get_logger

log = get_logger("core.baseline_scan")


# ── Common-knowledge probe paths (universal across web apps) ──────

# Paths every web crawler/scanner tries on every target. Ordered roughly
# by "likely to exist on most sites".
_UNIVERSAL_PROBE_PATHS = (
    "/", "/index.html", "/index.php", "/index.aspx",
    "/login", "/login.php", "/login.aspx", "/signin", "/log-in",
    "/admin", "/admin/", "/administrator/", "/admin.php", "/wp-admin/",
    "/dashboard", "/dashboard/", "/account", "/profile",
    "/register", "/signup", "/sign-up",
    "/search", "/search.php", "/search.aspx",
    "/api", "/api/", "/api/v1/", "/api/v2/", "/v1/", "/v2/",
    "/graphql", "/graphiql", "/api/graphql",
    "/openapi.json", "/swagger.json", "/api-docs", "/v3/api-docs",
    "/.git/HEAD", "/.git/config", "/.env", "/.env.production",
    "/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt",
    "/server-status", "/server-info",
    "/phpinfo.php", "/info.php", "/test.php",
    "/backup", "/backup.zip", "/backup.tar.gz", "/db.sql",
    "/config", "/config.php", "/config.json", "/config.yaml",
    "/uploads/", "/upload.php",
    "/redirect", "/redir", "/r",
    "/file", "/file.php", "/download", "/download.php",
    "/.htaccess", "/web.config",
    "/actuator", "/actuator/health", "/actuator/env",
)

# Common parameter names every scanner brute-tests.
_UNIVERSAL_PARAMS = (
    "id", "cat", "category", "page", "p", "q", "query", "search",
    "user", "username", "uid", "name", "email", "file", "path",
    "url", "redirect", "next", "return", "ref", "lang", "locale",
    "view", "action", "type", "format", "sort", "order", "filter",
    "limit", "offset", "key", "token", "session", "sid",
    "callback", "jsonp", "data", "input", "value", "item",
)

# Static asset extensions we won't recurse into during crawl.
_SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp4", ".mp3", ".webm", ".ogg",
    ".pdf", ".zip", ".tar", ".gz",
})

# JS regex from LinkFinder paper — extracts URLs from JS bundles.
_JS_URL_RE = re.compile(
    r"""(?:["'])
    (
      (?:[a-z]+:\/\/|\/\/|\.\.?\/|\/)
      [^"'\s<>]+\.[a-zA-Z]{1,4}(?:\?[^"'\s<>]*)?
      |
      \/[^"'\s<>]+(?:\?[^"'\s<>]*)?
    )
    (?:["'])""",
    re.VERBOSE | re.IGNORECASE,
)


# ── Surface discovery ────────────────────────────────────────────────


async def discover_attack_surface(
    http_client: Any,
    target_url: str,
    *,
    max_pages: int = 80,
    max_depth: int = 3,
    max_concurrency: int = 6,
) -> dict[str, Any]:
    """BFS-walk the target site. Harvest every URL, form, parameter.

    Returns ``{urls, urls_with_params, forms, hosts, raw_pages}``.
    Pure HTTP — no LLM. Caps at ``max_pages`` so wall-time is bounded.
    """
    try:
        from bs4 import BeautifulSoup  # type: ignore[import-untyped]
        has_bs4 = True
    except ImportError:
        has_bs4 = False
        log.warning("bs4 not installed — surface discovery will be partial")

    seed_host = urlparse(target_url).netloc
    visited: set[str] = set()
    endpoints: set[str] = set()
    forms: list[dict[str, Any]] = []
    params_by_url: dict[str, set[str]] = {}

    # Seed queue: target URL + every universal probe path
    queue: deque[tuple[str, int]] = deque()
    queue.append((target_url, 0))
    base_clean = target_url.rstrip("/")
    for path in _UNIVERSAL_PROBE_PATHS:
        queue.append((base_clean + path, 0))

    sem = asyncio.Semaphore(max_concurrency)

    async def _fetch(url: str):
        async with sem:
            try:
                return await http_client.get(url, scanner_tool="baseline_scan")
            except Exception as e:  # noqa: BLE001
                log.debug("baseline fetch failed %s: %r", url, e)
                return None

    while queue and len(visited) < max_pages:
        batch: list[tuple[str, int]] = []
        while queue and len(batch) < max_concurrency:
            url, depth = queue.popleft()
            norm = _normalise(url)
            if norm is None or norm in visited:
                continue
            if urlparse(norm).netloc != seed_host:
                continue
            if _has_skip_ext(norm):
                continue
            visited.add(norm)
            batch.append((norm, depth))

        if not batch:
            break

        responses = await asyncio.gather(
            *(_fetch(u) for u, _ in batch), return_exceptions=True,
        )

        for (url, depth), resp in zip(batch, responses):
            if isinstance(resp, Exception) or resp is None:
                continue
            # Only treat 2xx/3xx/401/403 as "exists"
            if resp.status_code not in (200, 201, 204, 301, 302, 307, 308, 401, 403):
                continue
            endpoints.add(url)

            # Extract query-string params
            qs = urlparse(url).query
            if qs:
                for k in parse_qs(qs, keep_blank_values=True).keys():
                    params_by_url.setdefault(url, set()).add(k)

            # Don't recurse past max_depth
            if depth >= max_depth:
                continue

            ctype = (resp.headers.get("content-type") or "").lower()
            text = resp.text or ""
            if not text:
                continue

            # HTML parsing: links + forms
            if has_bs4 and ("html" in ctype or "<html" in text[:200].lower()):
                try:
                    soup = BeautifulSoup(text, "html.parser")
                    for tag, attr in (
                        ("a", "href"), ("link", "href"), ("script", "src"),
                        ("iframe", "src"), ("form", "action"), ("img", "src"),
                    ):
                        for el in soup.find_all(tag):
                            v = el.get(attr)
                            if v:
                                queue.append((urljoin(url, v), depth + 1))
                    # Forms
                    for f in soup.find_all("form"):
                        action = urljoin(url, f.get("action") or url)
                        method = (f.get("method") or "GET").upper()
                        inputs: list[str] = []
                        for inp in f.find_all(["input", "select", "textarea"]):
                            n = inp.get("name")
                            if n:
                                inputs.append(n)
                                params_by_url.setdefault(action, set()).add(n)
                        if inputs:
                            forms.append({
                                "url": action,
                                "method": method,
                                "inputs": inputs,
                            })
                except Exception as e:  # noqa: BLE001
                    log.debug("html parse failed %s: %r", url, e)

            # JS regex extraction
            if "javascript" in ctype or url.endswith(".js"):
                for m in _JS_URL_RE.finditer(text):
                    v = m.group(1)
                    if v:
                        queue.append((urljoin(url, v), depth + 1))

    urls_with_params = [
        (u, sorted(p)) for u, p in params_by_url.items() if p
    ]

    log.info(
        "surface discovery on %s: %d endpoints, %d forms, %d params, %d pages",
        target_url, len(endpoints), len(forms),
        sum(len(p) for p in params_by_url.values()),
        len(visited),
    )
    return {
        "urls": sorted(endpoints),
        "urls_with_params": urls_with_params,
        "forms": forms,
        "hosts": [seed_host],
    }


def _normalise(url: str) -> str | None:
    """Strip fragment, lowercase scheme/host."""
    try:
        u, _ = urldefrag(url)
        parsed = urlparse(u)
        if parsed.scheme not in ("http", "https"):
            return None
        host = (parsed.hostname or "").lower()
        if not host:
            return None
        port = ""
        if parsed.port and parsed.port not in (80, 443):
            port = f":{parsed.port}"
        path = parsed.path or "/"
        if len(path) > 1:
            path = path.rstrip("/")
        return urlunparse((
            parsed.scheme.lower(), host + port, path, "",
            parsed.query, "",
        ))
    except Exception:
        return None


def _has_skip_ext(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in _SKIP_EXTENSIONS)


# ── Universal baseline runner ────────────────────────────────────────


async def run_universal_baseline(
    http_client: Any,
    dns_client: Any,
    target_url: str,
    findings_log: Any,
    workspace: Any = None,
    *,
    deep_mode: bool = True,
) -> dict[str, int]:
    """Fire every applicable scanner against the discovered surface.

    Returns a histogram of ``{scanner_name: findings_persisted}``.
    Findings go straight into ``findings_log``; the LLM is not involved.

    Safe to call on any target — uses only the scope the
    HTTPClient/DNSClient were constructed with, so out-of-scope hosts
    are denied as usual.
    """
    from network_pipeline.agents._common import persist_scan_findings
    import time as _time

    histogram: dict[str, int] = {}
    started_at = _time.monotonic()

    # Per-target scanner allowlist (e.g. scanme-nmap restricts to
    # passive + nmap-style only). The agent layer enforces this for
    # LLM tool calls; Phase-L must enforce it too so the deterministic
    # baseline doesn't violate `scope_note: "passive + nmap only"`.
    allowed_scanners: set[str] = set()
    if workspace is not None:
        try:
            marker = workspace / "plan" / "scanner_allowlist.txt"
            if marker.exists():
                allowed_scanners = {
                    line.strip() for line in marker.read_text(
                        encoding="utf-8",
                    ).splitlines() if line.strip()
                }
                log.info(
                    "Phase-L: target restricts to allowed_scanners=%s",
                    sorted(allowed_scanners),
                )
        except Exception as e:  # noqa: BLE001
            log.warning("could not read scanner_allowlist.txt: %r", e)

    def _is_allowed(scanner_name: str) -> bool:
        """Return True if scanner is allowed per target's allowed_scanners.

        When the marker file is empty/absent, ALL scanners are allowed
        (the default for unrestricted targets). This matches the agent
        layer's ``_apply_scanner_allowlist`` behaviour.
        """
        if not allowed_scanners:
            return True
        return scanner_name in allowed_scanners

    # Per-scanner timeout budgets (seconds). Tight enough that no single
    # hung scanner can starve the others; loose enough that real work
    # completes. Phase-L has an overall ceiling of ~10 minutes.
    PER_SCANNER_TIMEOUT = {
        "dns_scan": 30, "whois_lookup": 30, "subdomain_enum": 90,
        "subdomain_takeover": 90,
        "port_scan": 60, "tls_audit": 30, "http_probe": 30,
        "content_discovery": 180,
        "web_audit": 90, "openapi_scan": 30, "graphql_scan": 30,
        "websocket_scan": 30, "supply_chain": 60, "auth_audit": 60,
        "cve_check": 60, "request_smuggling": 30,
        "sqli_scan": 60, "xss_scan": 60, "bola_scan": 60,
        "mass_assignment": 60, "surface_discovery": 90,
    }
    OVERALL_TIMEOUT = 600  # 10 min hard cap on Phase-L total wall time

    def _record(scanner_name: str, scan_result: Any, elapsed: float) -> None:
        try:
            n = persist_scan_findings(
                scan_result, findings_log,
                agent_role="baseline", iteration=0,
            )
            histogram[scanner_name] = histogram.get(scanner_name, 0) + n
            log.info(
                "baseline %s: %d findings (%.1fs)",
                scanner_name, n, elapsed,
            )
        except Exception as e:  # noqa: BLE001
            log.warning("baseline persist %s failed: %r", scanner_name, e)

    async def _bounded(scanner_name: str, coro):
        """Run one scanner with a bounded timeout and progress log."""
        # Allowlist gate (Phase-L parity with agent layer).
        if not _is_allowed(scanner_name):
            log.info(
                "baseline %s: SKIPPED (not in allowed_scanners)", scanner_name,
            )
            # Cancel the coroutine to release any captured resources.
            try:
                coro.close()
            except Exception:  # noqa: BLE001
                pass
            return None
        if histogram.get("__elapsed__", 0) and (
            _time.monotonic() - started_at > OVERALL_TIMEOUT
        ):
            log.warning("baseline %s: SKIPPED (overall %ds budget exhausted)",
                        scanner_name, OVERALL_TIMEOUT)
            return None
        timeout = PER_SCANNER_TIMEOUT.get(scanner_name, 60)
        log.info("baseline %s: starting (timeout=%ds)", scanner_name, timeout)
        t0 = _time.monotonic()
        try:
            result = await asyncio.wait_for(coro, timeout=timeout)
            elapsed = _time.monotonic() - t0
            _record(scanner_name, result, elapsed)
            return result
        except asyncio.TimeoutError:
            elapsed = _time.monotonic() - t0
            log.warning(
                "baseline %s: TIMED OUT after %.1fs (cap=%ds)",
                scanner_name, elapsed, timeout,
            )
            return None
        except Exception as e:  # noqa: BLE001
            elapsed = _time.monotonic() - t0
            log.warning(
                "baseline %s: FAILED after %.1fs: %r",
                scanner_name, elapsed, e,
            )
            return None

    parsed = urlparse(target_url)
    target_host = parsed.hostname or ""
    is_https = parsed.scheme == "https"

    # ── Bug-fix: detect localhost / private targets so we don't run
    # scanners that only make sense against public-internet hosts.
    # On localhost we'd otherwise (a) burn 16s on crt.sh subdomain
    # lookups that can't return anything, (b) port-scan the operator's
    # own OS and surface RPC/SMB/etc. as "findings" — misleading
    # because they belong to the dev machine, not the demo target.
    def _is_local_host(h: str) -> bool:
        if not h:
            return True
        h_lower = h.lower()
        if h_lower in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return True
        try:
            import ipaddress
            ip = ipaddress.ip_address(h)
            return ip.is_loopback or ip.is_private or ip.is_link_local
        except ValueError:
            return False

    is_local_target = _is_local_host(target_host)
    if is_local_target:
        log.info(
            "Phase-L: localhost/private target detected — skipping "
            "subdomain_enum and OS-level port_scan (would surface "
            "host-machine services, not target findings).",
        )

    # ── Phase 1: recon — runs IN PARALLEL ────────────────────────
    log.info("Phase-L stage 1/4: recon (parallel)")
    parallel_recon = []
    if dns_client is not None and not is_local_target:
        from network_pipeline.scanners.dns_scan import DNSScanner
        parallel_recon.append(
            ("dns_scan", DNSScanner(dns_client).resolve(target_host)),
        )
    if http_client is not None:
        if not is_local_target:
            from network_pipeline.scanners.whois_lookup import WhoisScanner
            parallel_recon.append(
                ("whois_lookup", WhoisScanner(http_client).lookup(target_host)),
            )
        from network_pipeline.scanners.http_probe import HTTPProbeScanner
        parallel_recon.append(
            ("http_probe", HTTPProbeScanner(http_client).probe([target_url])),
        )
        if not is_local_target:
            scope = getattr(http_client, "_scope", None)
            from network_pipeline.scanners.port_scan import PortScanner
            parallel_recon.append(
                ("port_scan", PortScanner(scope=scope).scan(target_host)),
            )
        if is_https:
            from network_pipeline.scanners.tls_audit import TLSAuditScanner
            parallel_recon.append(
                ("tls_audit", TLSAuditScanner(http_client).audit(target_url)),
            )
    await asyncio.gather(
        *(_bounded(name, coro) for name, coro in parallel_recon),
        return_exceptions=True,
    )

    # Subdomain enum runs separately (uses external APIs, can be slow).
    # Skip entirely on localhost — crt.sh has nothing useful for it.
    if dns_client is not None and http_client is not None and not is_local_target:
        try:
            from network_pipeline.scanners.subdomains import SubdomainScanner
            sub_result = await _bounded(
                "subdomain_enum",
                SubdomainScanner(http_client, dns_client).enumerate(target_host),
            )
            subs = (sub_result.data or {}).get("subdomains", []) if sub_result else []
            if subs:
                from network_pipeline.scanners.subdomain_takeover import (
                    SubdomainTakeoverScanner,
                )
                await _bounded(
                    "subdomain_takeover",
                    SubdomainTakeoverScanner(http_client, dns_client).scan(list(subs)[:20]),
                )
        except Exception as e:  # noqa: BLE001
            log.warning("subdomain stage failed: %r", e)

    # ── Phase 2: surface discovery (must run before injection) ────
    log.info("Phase-L stage 2/4: surface discovery")
    surface: dict[str, Any] = {"urls": [], "urls_with_params": [], "forms": []}
    if http_client is not None:
        try:
            surface = await asyncio.wait_for(
                discover_attack_surface(
                    http_client, target_url,
                    max_pages=30 if deep_mode else 15,  # was 80
                    max_depth=2,                         # was 3
                ),
                timeout=PER_SCANNER_TIMEOUT["surface_discovery"],
            )
        except asyncio.TimeoutError:
            log.warning("surface_discovery: TIMED OUT after 90s")
        except Exception as e:  # noqa: BLE001
            log.warning("surface_discovery failed: %r", e)

    # ── Phase 3: misconfig batteries — IN PARALLEL ──────────────
    log.info("Phase-L stage 3/4: misconfig + content (parallel)")
    parallel_misconfig = []
    if http_client is not None:
        from network_pipeline.scanners.content_discovery import ContentScanner
        from network_pipeline.scanners.web_audit import WebAuditScanner
        from network_pipeline.scanners.openapi_scan import OpenAPIScanner
        from network_pipeline.scanners.graphql_scan import GraphQLScanner
        from network_pipeline.scanners.websocket_scan import WebSocketScanner
        from network_pipeline.scanners.supply_chain import SupplyChainScanner
        from network_pipeline.scanners.auth_audit import AuthAuditScanner
        from network_pipeline.scanners.cve_check import CVECheckScanner
        from network_pipeline.scanners.request_smuggling import RequestSmugglingScanner

        # Phase-L runs content_discovery NON-recursive to keep wall time
        # bounded. The LLM-driven loop can re-run it recursively later
        # if a sensitive directory turns up.
        parallel_misconfig.extend([
            ("content_discovery",
             ContentScanner(http_client).discover(
                 target_url, wordlist="common", recurse=False,
             )),
            ("web_audit",
             WebAuditScanner(http_client).audit(target_url)),
            ("openapi_scan",
             OpenAPIScanner(http_client).scan(target_url)),
            ("graphql_scan",
             GraphQLScanner(http_client).scan(target_url)),
            ("websocket_scan",
             WebSocketScanner(http_client).scan(target_url)),
            ("supply_chain",
             SupplyChainScanner(http_client, workspace=workspace).scan(target_url)),
            ("auth_audit",
             AuthAuditScanner(http_client).audit(target_url)),
            ("cve_check",
             CVECheckScanner(http_client).run(target_url)),
            ("request_smuggling",
             RequestSmugglingScanner(http_client).scan(target_url)),
        ])
    await asyncio.gather(
        *(_bounded(name, coro) for name, coro in parallel_misconfig),
        return_exceptions=True,
    )

    # ── Phase 4: per-URL injection — IN PARALLEL ────────────────
    log.info("Phase-L stage 4/4: injection (parallel)")
    urls_with_params = list(surface.get("urls_with_params") or [])
    if not urls_with_params and surface.get("urls"):
        for u in list(surface["urls"])[:5]:
            urls_with_params.append((u, list(_UNIVERSAL_PARAMS[:6])))
    if not urls_with_params:
        # Universal fallback: probe ROOT with the 6 most-common param names.
        urls_with_params.append((
            target_url.rstrip("/") + "/",
            list(_UNIVERSAL_PARAMS[:6]),
        ))

    log.info("baseline injection phase: %d (url, params) tuples",
             len(urls_with_params))

    parallel_injection = []
    if http_client is not None:
        from network_pipeline.scanners.sqli_scan import SQLiScanner
        from network_pipeline.scanners.xss_scan import XSSScanner
        from network_pipeline.scanners.bola_scan import BOLAScanner
        sqli = SQLiScanner(http_client)
        xss = XSSScanner(http_client)
        # Tighter cap — Phase-L is a sweep, not an exhaustive scan.
        cap = 5 if deep_mode else 3
        for url, params in urls_with_params[:cap]:
            parallel_injection.append((
                f"sqli_scan[{url[:60]}]",
                sqli.scan(url, params=params[:4]),
            ))
            parallel_injection.append((
                f"xss_scan[{url[:60]}]",
                xss.scan(url, params=params[:4]),
            ))

        # BOLA against numeric/UUID paths
        bola_targets = [
            u for u in surface.get("urls", [])
            if re.search(r"/\d+(/|$|\?)", urlparse(u).path)
            or re.search(r"/[0-9a-f]{8}-[0-9a-f]{4}",
                         urlparse(u).path, re.I)
        ][:5]
        if bola_targets:
            parallel_injection.append((
                "bola_scan",
                BOLAScanner(http_client).scan(bola_targets),
            ))

    # Inject the histogram alias so injection results aggregate under
    # the canonical scanner name (not the per-URL label).
    async def _inject_with_alias(label: str, coro):
        # Strip the [url] suffix when persisting
        canonical = label.split("[", 1)[0]
        # Allowlist gate (e.g. scanme-nmap blocks sqli/xss/bola)
        if not _is_allowed(canonical):
            log.info(
                "baseline %s: SKIPPED (not in allowed_scanners)", label,
            )
            try:
                coro.close()
            except Exception:  # noqa: BLE001
                pass
            return
        timeout = PER_SCANNER_TIMEOUT.get(canonical, 60)
        t0 = _time.monotonic()
        try:
            r = await asyncio.wait_for(coro, timeout=timeout)
            _record(canonical, r, _time.monotonic() - t0)
        except asyncio.TimeoutError:
            log.warning("baseline %s: TIMED OUT after %ds", label, timeout)
        except Exception as e:  # noqa: BLE001
            log.warning("baseline %s: FAILED: %r", label, e)

    await asyncio.gather(
        *(_inject_with_alias(name, coro) for name, coro in parallel_injection),
        return_exceptions=True,
    )

    # ── Phase 7: form-driven mass-assignment ────────────────────
    if http_client is not None and surface.get("forms"):
        try:
            from network_pipeline.scanners.mass_assignment import MassAssignmentScanner
            ma = MassAssignmentScanner(http_client)
            captured = []
            for form in surface["forms"][:8]:
                if form.get("method", "GET").upper() in ("POST", "PUT", "PATCH"):
                    captured.append({
                        "method": form["method"],
                        "url": form["url"],
                        "headers": {"Content-Type": "application/json"},
                        "body": {n: "test" for n in form.get("inputs", [])[:8]},
                    })
            if captured:
                _t = _time.monotonic()
                r = await ma.scan(captured)
                _record("mass_assignment", r, _time.monotonic() - _t)
        except Exception as e:  # noqa: BLE001
            log.warning("mass_assignment failed: %r", e)

    # NOTE: request_smuggling already runs in Stage 3 (parallel misconfig
    # batch with proper timeout). The duplicate call here was a refactor
    # leftover that crashed with the new ``_record(elapsed)`` signature.

    total = sum(histogram.values())
    log.info(
        "Phase-L baseline complete: %d findings across %d scanners on %s",
        total, len(histogram), target_url,
    )
    return histogram


__all__ = ["discover_attack_surface", "run_universal_baseline"]
