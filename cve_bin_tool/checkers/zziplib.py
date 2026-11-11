# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for zziplib

https://www.cvedetails.com/product/36035/Zziplib-Project-Zziplib.html?vendor_id=16135
https://www.cvedetails.com/product/180089/Gdraheim-Zziplib.html?vendor_id=37568

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ZziplibChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"zziplib ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("gdraheim", "zziplib"), ("zziplib_project", "zziplib")]
