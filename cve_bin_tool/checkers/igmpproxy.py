# Copyright (C) 2026 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for igmpproxy

https://www.cvedetails.com/product/185134/Pali-Igmpproxy.html?vendor_id=38488

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class IgmpproxyChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"igmpproxy ([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("pali", "igmpproxy")]
