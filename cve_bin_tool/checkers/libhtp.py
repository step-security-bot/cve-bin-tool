# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libhtp

https://www.cvedetails.com/product/52627/Oisf-Libhtp.html?vendor_id=17892

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibhtpChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"LibHTP v([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("oisf", "libhtp")]
