# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for traffic_server

https://www.cvedetails.com/product/19990/Apache-Traffic-Server.html?vendor_id=45

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class TrafficServerChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"Traffic Server ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("apache", "traffic_server")]
