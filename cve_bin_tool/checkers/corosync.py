# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for corosync

https://www.cvedetails.com/product/27835/Corosync-Corosync.html?vendor_id=13388

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class CorosyncChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+\.[0-9]+)[a-zA-Z_/%: \.\r\n]*corosync"]
    VENDOR_PRODUCT = [("corosync", "corosync")]
