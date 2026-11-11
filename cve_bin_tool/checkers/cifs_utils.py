# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for cifs-utils

https://www.cvedetails.com/product/81639/Samba-Cifs-utils.html?vendor_id=102

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class CifsUtilsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"mount\.cifs[A-Za-z0-9%: \"\-\.\r\n]*([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("samba", "cifs-utils")]
