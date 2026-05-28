# CVE Check Engine — YAML Format Reference

## Overview

The `cves/` directory contains YAML check files loaded by `scanners/cve_check.py`.
Each check describes one HTTP probe and the expected response signature that indicates the vulnerability is present.

## Schema

```yaml
id: CVE-YYYY-NNNNN           # unique identifier (CVE ID or custom slug)
title: short description     # human-readable title
severity: critical|high|medium|low|informational

http_request:
  method: GET|POST|PUT|...
  path: /path/to/probe       # appended to target URL
  body: ""                   # request body (empty string = no body)
  headers:                   # optional extra headers
    Content-Type: text/xml

expected_response:
  status: 200                # optional; if omitted, any status matches
  body_contains: "indicator" # must appear in response body (case-sensitive)
  body_not_contains: ""      # must NOT appear (empty = skip check)
  headers_contain:           # each key's value must appear in that response header
    Server: Apache

cvss: 9.8                    # CVSS v3 base score
cwe:
  - CWE-89
mitre:
  - T1190
references:
  - https://nvd.nist.gov/vuln/detail/CVE-...
remediation: One-line fix guidance.
```

## Adding Custom Checks

Drop additional `.yaml` files into `workspace/checks/` before running an engagement.
The engine loads both the bundled checks (this directory) and any workspace-specific ones.

## Nuclei → CVE Check Converter (v1.1)

A converter utility (`tools/nuclei_to_check.py`) that translates compatible nuclei
YAML templates into this format is planned for v1.1. Track progress in the project issues.

## Bundled Coverage

| Stack | Check IDs |
|-------|-----------|
| PHP | CVE-2017-9841 (PHPUnit RCE), CVE-2019-11043 (FPM) |
| Java / Spring | CVE-2022-22965 (Spring4Shell), SPRING-ACTUATOR-ENV |
| Log4j | CVE-2021-44228 (Log4Shell) |
| WordPress | WP-XMLRPC-ENABLED |
| Drupal | DRUPAL-SA-CORE-2018-002 (Drupalgeddon2) |
| Generic | EXPOSED-GIT-REPO, EXPOSED-ENV-FILE |
