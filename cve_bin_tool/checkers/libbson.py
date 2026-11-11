# Copyright (C) 2026 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libbson

https://www.cvedetails.com/product/50165/Mongodb-Libbson.html?vendor_id=12752

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibbsonChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+\.[0-9]+)(?:\r?\n|/)src/(?:lib|)bson"]
    VENDOR_PRODUCT = [("mongodb", "libbson")]
