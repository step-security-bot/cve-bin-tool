# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for fastnetmon

https://www.cvedetails.com/product/88854/Motion-Project-Motion.html?vendor_id=23775

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class FastnetmonChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"fastnetmon-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("pavel-odintsov", "fastnetmon")]
