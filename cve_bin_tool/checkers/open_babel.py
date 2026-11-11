# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for open_babel

https://www.cvedetails.com/product/155095/Openbabel-Open-Babel.html?vendor_id=32383

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class OpenBabelChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"Open Babel \r?\n([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("openbabel", "open_babel")]
