# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for aomedia

https://www.cvedetails.com/product/94899/Aomedia-Aomedia.html?vendor_id=24569

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class AomediaChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"AOMedia[a-zA-Z0-9 ]*([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("aomedia", "aomedia")]
