"""Scanner package — pure-Python offensive scanner classes.

Base Scanner ABC and a lightweight registry. Each scanner module registers
itself at import time via @register_scanner.

Usage:
    from network_pipeline.scanners import get_scanner, list_scanners
"""

from __future__ import annotations

import importlib
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient, DNSClient

_REGISTRY: dict[str, type["Scanner"]] = {}


class Scanner(ABC):
    """Base class for all pure-Python scanner modules."""

    #: Short identifier — matches the @tool name in agent wrappers.
    name: str = ""
    #: If True, a BrowserSession will be injected (and tool gated if unavailable).
    requires_browser: bool = False
    #: Python module names that importlib.util.find_spec must find for this scanner.
    requires_libs: tuple[str, ...] = ()
    #: Minimum OpsecLevel (as string) this scanner is allowed at.
    opsec_min: str = "loud"
    #: Noise level: 'passive', 'low', 'medium', 'high'.
    loud_level: str = "medium"

    @classmethod
    def is_available(cls) -> bool:
        """Return True if all required libs are importable."""
        import importlib.util
        for lib in cls.requires_libs:
            if importlib.util.find_spec(lib) is None:
                return False
        return True


def register_scanner(cls: type[Scanner]) -> type[Scanner]:
    """Class decorator that registers a Scanner in the module registry."""
    _REGISTRY[cls.name] = cls
    return cls


def get_scanner(name: str) -> type[Scanner] | None:
    return _REGISTRY.get(name)


def list_scanners() -> list[str]:
    return sorted(_REGISTRY.keys())


def import_all_scanners() -> None:
    """Import every scanner module so they register themselves."""
    _MODULES = [
        # Phase A-G core
        "dns_scan", "whois_lookup", "subdomains", "js_endpoints",
        "parameter_mining", "port_scan", "http_probe", "content_discovery",
        "tls_audit", "cve_check", "sqli_scan", "sqlmap_dispatch",
        "xss_scan", "jwt_scan", "web_audit", "auth_audit",
        # Phase H 2026: adaptive web-attack core
        "openapi_scan", "bola_scan", "mass_assignment",
        # Phase I 2026: modern protocol coverage
        "graphql_scan", "request_smuggling", "websocket_scan",
        "subdomain_takeover", "supply_chain",
        # Phase K 2026: deep red-team aggression
        "web_crawler",
    ]
    for mod in _MODULES:
        try:
            importlib.import_module(f"network_pipeline.scanners.{mod}")
        except ImportError:
            pass
