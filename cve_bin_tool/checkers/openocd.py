# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for openocd

https://www.cvedetails.com/product/43136/Openocd-Open-On-chip-Debugger.html?vendor_id=17563

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class OpenocdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"Open On-Chip Debugger ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("openocd", "open_on-chip_debugger")]
