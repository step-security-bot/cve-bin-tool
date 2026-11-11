# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for snapcast

https://www.cvedetails.com/product/168357/Badaix-Snapcast.html?vendor_id=34464

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class SnapcastChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nSnap",
        r"snapserver v\r?\n([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("badaix", "snapcast")]
