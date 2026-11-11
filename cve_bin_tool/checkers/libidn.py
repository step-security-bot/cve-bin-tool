# Copyright (C) 2026 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libidn

https://www.cvedetails.com/product/34531/GNU-Libidn.html?vendor_id=72

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibidnChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"UTF-8\r?\n([0-9]+\.[0-9]+)\r?\nNameprep"]
    VENDOR_PRODUCT = [("gnu", "libidn")]
