# Copyright (C) 2026 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for drogon

https://www.cvedetails.com/product/99029/Drogon-Drogon.html?vendor_id=25077

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class DrogonChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"drogon-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("drogon", "drogon")]
