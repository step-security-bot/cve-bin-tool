# Copyright (C) 2026 Shivam Agarwal
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for nsd

https://nvd.nist.gov/products/cpe/search/results?namingFormat=2.3&orderBy=2.3&keyword=cpe%3A2.3%3Aa%3Anlnetlabs%3Ansd&status=FINAL
https://nvd.nist.gov/products/cpe/search/results?namingFormat=2.3&orderBy=2.3&keyword=cpe%3A2.3%3Aa%3Anlnetlabs%3Aname_server_daemon&status=FINAL

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class NsdChecker(Checker):
    """CVE checker for the NSD authoritative DNS server.

    NSD is NLnet Labs' authoritative-only DNS server. The daemon binary
    (``nsd``) and the zone checker (``nsd-checkzone``) embed their release
    version as a standalone banner string of the form ``NSD x.y.z``, for
    example ``NSD 4.12.0``.
    """

    CONTAINS_PATTERNS: list[str] = [
        r"nsd-bugs@nlnetlabs.nl",
    ]
    FILENAME_PATTERNS: list[str] = [
        r"nsd",
        r"nsd-checkconf",
        r"nsd-checkzone",
        r"nsd-control",
    ]
    VERSION_PATTERNS = [r"NSD ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("nlnetlabs", "nsd"), ("nlnetlabs", "name_server_daemon")]
