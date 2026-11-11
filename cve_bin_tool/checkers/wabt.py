# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for wabt

https://www.cvedetails.com/product/122809/Webassembly-Wabt.html?vendor_id=20412
https://www.cvedetails.com/product/141410/Webassembly-Webassembly-Binary-Toolkit.html?vendor_id=20412

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class WabtChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"wabt-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [
        ("webassembly", "wabt"),
        ("webassembly", "webassembly_binary_toolkit"),
    ]
