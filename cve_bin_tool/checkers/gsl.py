# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for gnu_scientific_library

https://www.cvedetails.com/product/160085/GNU-Gnu-Scientific-Library.html?vendor_id=72

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class GslChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"\r?\n([0-9]+\.[0-9]+)\r?\n[a-zA-Z0-9_%<>+()@!?,= \[\]\-\.\t\r\n]*gsl_",
        r"gsl_[a-zA-Z0-9_%<>+()@!?,= \[\]\-\.\t\r\n]*\r?\n([0-9]+\.[0-9]+)\r?\n",
    ]
    VENDOR_PRODUCT = [("gnu", "gnu_scientific_library")]
