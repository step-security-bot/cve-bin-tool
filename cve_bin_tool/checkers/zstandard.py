# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for zstandard:

https://www.cvedetails.com/product/57378/Facebook-Zstandard.html?vendor_id=7758

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ZstandardChecker(Checker):
    """CVE checker for zstandard binary and library."""

    CONTAINS_PATTERNS: list[str] = [
        r"Zstandard CLI",
        r"Zstandard Frames",
        r"zstd command line interface",
        r"Frame requires too much memory for decoding",
    ]
    FILENAME_PATTERNS: list[str] = [
        r"zstd",
        r"libzstd",
    ]
    VERSION_PATTERNS = [
        r"v([0-9]+\.[0-9]+\.[0-9]+)\r?\n(?:zstd command line interface|Zstandard CLI)",
        r"(?:zstd command line interface|Zstandard CLI)\r?\nv([0-9]+\.[0-9]+\.[0-9]+)",
        r"\*\*\* Zstandard CLI .*? v([0-9]+\.[0-9]+\.[0-9]+)",
        r"zstd v([0-9]+\.[0-9]+\.[0-9]+)",
        r"Frame requires too much memory for decoding[a-zA-Z :(#$'/,\-\r\n]*([0-9]+\.[0-9]+\.[0-9]+)",
        r"\r?\n([0-9]+\.[0-9]+\.[0-9]+)[a-zA-Z0-9 -|<>/._=%:(#$'/\[\]\r\n]{0,250}?Frame requires too much memory for decoding",
    ]
    VENDOR_PRODUCT = [("facebook", "zstandard")]
