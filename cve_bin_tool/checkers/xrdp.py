# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for xrdp

https://www.cvedetails.com/product/63511/Neutrinolabs-Xrdp.html?vendor_id=21138

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class XrdpChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)\r?\nxrdp"]
    VENDOR_PRODUCT = [("neutrinolabs", "xrdp")]
