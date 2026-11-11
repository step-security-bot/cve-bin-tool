# Copyright (C) 2026 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for cockpit

https://www.cvedetails.com/product/52480/Cockpit-project-Cockpit.html?vendor_id=19705

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class CockpitChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"\r?\n([0-9]+)\r?\n[a-zA-Z0-9/:%_ \.\-\r\n]*cockpit"]
    VENDOR_PRODUCT = [("cockpit-project", "cockpit")]
