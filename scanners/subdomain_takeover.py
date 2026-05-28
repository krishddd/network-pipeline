"""Subdomain takeover detector.

Post-processes the output of subdomain_enum: for every CNAME pointing
at a third-party service (Heroku, S3, GitHub Pages, Azure, Fastly,
Pantheon, Surge, Bitbucket, Tumblr, Squarespace, …), fetch the
HTTP body and match against the service's "no claim" fingerprint.
A match means the CNAME is dangling — anyone can register the name
on the upstream service and serve content from the victim subdomain.

Fingerprint table compiled from EdOverflow/can-i-take-over-xyz +
Project Discovery's nuclei-takeovers + recent 2025-26 CVE write-ups.

Pure stdlib + httpx (already in pipeline).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanFinding, ScanResult

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient, DNSClient


# (service_name, cname_pattern, body_fingerprint)
# cname_pattern is a substring match on the resolved CNAME target.
# body_fingerprint is a substring (case-insensitive) match on the HTTP
# response body returned when the subdomain is unclaimed.
_TAKEOVER_RULES: list[tuple[str, str, str]] = [
    ("AWS S3", "s3.amazonaws.com", "NoSuchBucket"),
    ("AWS S3", "s3-website", "NoSuchBucket"),
    ("AWS CloudFront", "cloudfront.net", "ERROR: The request could not be satisfied"),
    ("Heroku", "herokuapp.com", "no such app"),
    ("Heroku", "herokudns.com", "no such app"),
    ("GitHub Pages", "github.io", "There isn't a GitHub Pages site here"),
    ("GitHub Pages", "github.com", "There isn't a GitHub Pages site here"),
    ("Azure", "azurewebsites.net", "Web App - Unavailable"),
    ("Azure", "cloudapp.net", "Web App - Unavailable"),
    ("Azure CDN", "azureedge.net", "Web App - Unavailable"),
    ("Fastly", "fastly.net", "Fastly error: unknown domain"),
    ("Pantheon", "pantheonsite.io", "The gods are wise, but do not know"),
    ("Surge.sh", "surge.sh", "project not found"),
    ("Bitbucket", "bitbucket.io", "Repository not found"),
    ("Tumblr", "tumblr.com", "Whatever you were looking for doesn't currently exist"),
    ("Shopify", "myshopify.com", "Sorry, this shop is currently unavailable"),
    ("Squarespace", "squarespace.com", "No Such Account"),
    ("Unbounce", "unbouncepages.com", "The requested URL was not found on this server"),
    ("Tilda", "tilda.ws", "Please renew your subscription"),
    ("Webflow", "proxy.webflow.com", "The page you are looking for doesn't exist"),
    ("Vercel", "vercel-dns.com", "The deployment could not be found"),
    ("Netlify", "netlify.app", "Not Found - Request ID"),
    ("Cargo", "cargocollective.com", "404 Not Found"),
    ("HelpScout", "helpscoutdocs.com", "No settings were found for this company"),
    ("Strikingly", "strikinglydns.com", "But if you're looking to build your own website"),
    ("Tave", "tave.com", "<h1>Error 404: Page Not Found</h1>"),
    ("Wishpond", "wishpond.com", "https://www.wishpond.com/404?campaign=true"),
    ("LaunchRock", "launchrock.com", "It looks like you may have taken a wrong turn somewhere"),
    ("Smartling", "smartling.com", "Domain is not configured"),
    ("Acquia", "acquia-sites.com", "The site you are looking for could not be found"),
    ("Brightcove", "bcvp0rtal.com", "<p>Error: Invalid token</p>"),
    ("ReadMe.io", "readme.io", "Project doesnt exist"),
]


@register_scanner
class SubdomainTakeoverScanner(Scanner):
    name = "subdomain_takeover"
    requires_libs = ()
    opsec_min = "loud"
    loud_level = "low"

    def __init__(
        self,
        http_client: "HTTPClient",
        dns_client: "DNSClient | None" = None,
    ) -> None:
        self._http = http_client
        self._dns = dns_client

    async def scan(self, hostnames: list[str]) -> ScanResult:
        result = ScanResult(
            scanner=self.name,
            target=hostnames[0] if hostnames else "",
        )
        if not hostnames:
            result.success = False
            result.error = "no hostnames supplied"
            return result

        for host in hostnames:
            try:
                hits = await self._probe_host(host)
                result.findings.extend(hits)
            except Exception as e:  # noqa: BLE001
                result.data.setdefault("errors", []).append(f"{host}: {e!r}")

        result.data["hosts_probed"] = len(hostnames)
        result.data["takeover_candidates"] = len(result.findings)
        return result

    async def _probe_host(self, host: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        # 1. Resolve CNAME(s) — best effort
        cnames: list[str] = []
        if self._dns is not None:
            try:
                rec = await self._dns.resolve(host, rrtype="CNAME")
                cnames = list((rec or {}).get("answers", []))
            except Exception:  # noqa: BLE001
                pass

        # 2. Fetch the host over HTTP/HTTPS
        body: str = ""
        for scheme in ("https", "http"):
            r = await self._http.get(
                f"{scheme}://{host}/",
                scanner_tool=self.name,
                check_scope=False,
            )
            if r is None:
                continue
            body = (r.text or "")[:8192]
            if body:
                break

        if not body and not cnames:
            return findings

        # 3. Match against fingerprints. CNAME match weights higher; body
        # match alone is enough to flag (some services have no usable
        # CNAME signal at the resolver level).
        for service, cname_pat, body_pat in _TAKEOVER_RULES:
            cname_match = any(cname_pat.lower() in c.lower() for c in cnames)
            body_match = body_pat.lower() in body.lower()
            if not (cname_match or body_match):
                continue
            sev = "critical" if cname_match and body_match else "high"
            conf = "verified" if cname_match and body_match else "probable"
            findings.append(ScanFinding(
                vuln_class="subdomain-takeover",
                title=f"Subdomain takeover candidate on {host} ({service})",
                severity=sev,
                affected_target=host,
                description=(
                    f"Host {host} appears to point at unclaimed "
                    f"{service} infrastructure. CNAME match: {cname_match}; "
                    f"body fingerprint match: {body_match}. An adversary "
                    f"who registers the upstream resource on {service} "
                    "controls all content served from this subdomain."
                ),
                cwe=["CWE-350"],
                mitre=["T1583.001"],
                confidence=conf,
                extra={
                    "service": service,
                    "cnames": cnames,
                    "fingerprint_in_body": body_match,
                },
            ))
            # Stop on first match — multiple services rarely overlap and
            # listing duplicates muddies reports.
            break

        return findings
