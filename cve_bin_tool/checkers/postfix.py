# Copyright (C) 2026 Shivam Agarwal
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for postfix

https://nvd.nist.gov/products/cpe/search/results?namingFormat=2.3&orderBy=2.3&keyword=cpe%3A2.3%3Aa%3Apostfix%3Apostfix&status=FINAL

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class PostfixChecker(Checker):
    """CVE checker for the Postfix mail transfer agent.

    Postfix binaries embed their release version as a ``mail_version=x.y.z``
    string (it is the compiled-in value of the mail_version configuration
    parameter), which is present in the daemon and administration binaries
    such as smtpd, master and postconf.
    """

    CONTAINS_PATTERNS: list[str] = [
        r"the Postfix SMTP server",
        r"Postfix was built with include files",
    ]
    FILENAME_PATTERNS: list[str] = [
        r"postconf",
        r"postfix",
        r"postmap",
        r"postqueue",
        r"postsuper",
        r"smtpd",
    ]
    VERSION_PATTERNS = [r"mail_version=([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("postfix", "postfix")]
