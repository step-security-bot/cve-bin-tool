# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for dcmtk

https://www.cvedetails.com/product/27867/Offis-Dcmtk.html?vendor_id=13397

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class DcmtkChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"dcmtk-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("offis", "dcmtk")]
