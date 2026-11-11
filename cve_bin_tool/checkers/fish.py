# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for fish

https://www.cvedetails.com/product/43564/Fishshell-Fish.html?vendor_id=17623

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class FishChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"fish-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("fishshell", "fish")]
