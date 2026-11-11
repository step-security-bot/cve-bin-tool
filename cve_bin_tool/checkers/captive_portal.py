# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for captive_portal

https://www.cvedetails.com/product/165110/Opennds-Captive-Portal.html?vendor_id=33688

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class CaptivePortalChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"openNDS version ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("opennds", "captive_portal")]
