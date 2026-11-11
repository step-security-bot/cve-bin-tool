# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libsixel

https://www.cvedetails.com/product/48608/Libsixel-Project-Libsixel.html?vendor_id=19024

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibsixelChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"sixel[a-z0-9 ]*([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("libsixel_project", "libsixel")]
