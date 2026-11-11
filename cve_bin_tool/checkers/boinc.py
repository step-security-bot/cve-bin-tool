# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for boinc

https://www.cvedetails.com/product/16720/Berkeley-Boinc-Client.html?vendor_id=356
https://www.cvedetails.com/product/179893/Universityofcalifornia-Boinc-Client.html?vendor_id=37525

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class BoincChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"boinc.so.([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nboinc",
    ]
    VENDOR_PRODUCT = [
        ("berkeley", "boinc_client"),
        ("universityofcalifornia", "boinc_client"),
    ]
