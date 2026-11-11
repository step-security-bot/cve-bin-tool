# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for catdoc

https://www.cvedetails.com/product/139726/Catdoc-Project-Catdoc.html?vendor_id=30573

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class CatdocChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+)\r?\nCatdoc Version"]
    VENDOR_PRODUCT = [("catdoc_project", "catdoc"), ("fossies", "catdoc")]
