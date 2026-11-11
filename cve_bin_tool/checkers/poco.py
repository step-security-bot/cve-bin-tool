# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for poco

https://www.cvedetails.com/product/65385/Pocoproject-Poco.html?vendor_id=13266

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class PocoChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"poco-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("pocoproject", "poco")]
