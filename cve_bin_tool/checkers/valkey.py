# Copyright (C) 2026 Shivam Agarwal
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for valkey

https://nvd.nist.gov/products/cpe/search/results?namingFormat=2.3&orderBy=2.3&keyword=cpe%3A2.3%3Aa%3Alfprojects%3Avalkey&status=FINAL
https://nvd.nist.gov/products/cpe/search/results?namingFormat=2.3&orderBy=2.3&keyword=cpe%3A2.3%3Aa%3Avalkey-io%3Avalkey&status=FINAL

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ValkeyChecker(Checker):
    """CVE checker for the Valkey key-value store.

    Valkey is the Linux Foundation fork of Redis. Its binaries embed a
    single string of the form ``valkey<version><build time>``, where the
    version is followed directly by the build time in nanoseconds since
    the epoch (19 digits), for example ``valkey8.1.1`` followed by the
    timestamp. The string is present in the multi-call binary shipped as
    valkey-check-rdb and valkey-check-aof (valkey-server and
    valkey-sentinel are symbolic links to it), and also in valkey-cli and
    valkey-benchmark.
    """

    CONTAINS_PATTERNS: list[str] = [
        r"valkey_version",
    ]
    FILENAME_PATTERNS: list[str] = [
        r"valkey-benchmark",
        r"valkey-check-aof",
        r"valkey-check-rdb",
        r"valkey-cli",
        r"valkey-sentinel",
        r"valkey-server",
    ]
    VERSION_PATTERNS = [r"valkey([0-9]+\.[0-9]+\.[0-9]{1,2})[0-9]{19}"]
    VENDOR_PRODUCT = [("lfprojects", "valkey"), ("valkey-io", "valkey")]
