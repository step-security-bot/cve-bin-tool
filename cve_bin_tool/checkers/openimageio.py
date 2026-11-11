# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for openimageio

https://www.cvedetails.com/product/126860/Openimageio-Openimageio.html?vendor_id=29024

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class OpenimageioChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"OpenImageIO ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("openimageio", "openimageio")]
