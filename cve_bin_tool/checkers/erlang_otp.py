# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for Erlang OTP

https://www.cvedetails.com/product/20874/Erlang-Erlang-otp.html?vendor_id=9446
https://www.cvedetails.com/product/33599/Erlang-OTP.html?vendor_id=9446

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ErlangOtpChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+(\.[0-9]+)?(\.[0-9]+)?)\r?\nErlang/OTP",
        r"Erlang/OTP[a-z0-9%: \.\-\[\]]*\r?\n([0-9]+\.[0-9]+(\.[0-9]+)?(\.[0-9]+)?)",
    ]
    VENDOR_PRODUCT = [("erlang", "erlang\\/otp"), ("erlang", "otp")]
