# Copyright (C) 2026 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for jansson

https://www.cvedetails.com/product/27255/Jansson-Project-Jansson.html?vendor_id=13196

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class JanssonChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"jsonp_strtod\r?\n([0-9]+\.[0-9]+(\.[0-9]+)?)",
        r"([0-9]+\.[0-9]+(\.[0-9]+)?)[a-zA-Z`_{#' \[\r\n]*jsonp_strtod",
    ]
    VENDOR_PRODUCT = [("jansson_project", "jansson")]
