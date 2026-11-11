# Copyright (C) 2026 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for apr-util

https://www.cvedetails.com/product/17508/Apache-Apr-util.html?vendor_id=45

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class AprUtilChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"apr-util-1[a-zA-Z0-9/%_\-\.\r\n]*([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("apache", "apr-util")]
