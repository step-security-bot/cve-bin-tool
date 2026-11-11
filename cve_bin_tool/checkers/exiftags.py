# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for exiftags

https://www.cvedetails.com/product/12752/Aertherwide-Exiftags.html?vendor_id=7551

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ExiftagsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"Exif[a-z \.]*\r?\n([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("aertherwide", "exiftags")]
