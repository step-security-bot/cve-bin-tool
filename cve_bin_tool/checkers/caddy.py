# Copyright (C) 2026 Aryan Gupta
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for Caddy web server:

https://caddyserver.com/
https://www.cvedetails.com/product/142981/Caddyserver-Caddy.html?vendor_id=25164
https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_vendor=cpe%3A%2F%3Acaddyserver&cpe_product=cpe%3A%2F%3Acaddyserver%3Acaddy
"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class CaddyChecker(Checker):
    CONTAINS_PATTERNS = [
        r"github\.com/caddyserver/caddy/v2",
        r"github\.com/mholt/caddy",
        r"Caddyfile",
        r"\$ caddy run",
    ]
    FILENAME_PATTERNS = [
        r"^caddy$",
        r"^caddy\.exe$",
    ]
    VERSION_PATTERNS = [
        r"dep\tgithub\.com/caddyserver/caddy/v2\tv?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"github\.com/caddyserver/caddy/v2@v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)/",
        r"github\.com/caddyserver/caddy/v2\.CustomVersion=v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"/caddy-([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:-build)?/",
        r"caddy v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"Caddy v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    ]
    VENDOR_PRODUCT = [("caddyserver", "caddy"), ("caddy_project", "caddy")]
