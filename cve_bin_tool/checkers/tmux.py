# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE Binary Tool checker for tmux (terminal multiplexer).
"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class TmuxChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"^tmux$"]
    VERSION_PATTERNS = [
        r"tmux ([0-9]+\.[0-9]+[a-z]?)",
        r"([0-9]+\.[0-9]+[a-z]?)[A-Za-z0-9_:\-/. \r\n%()\"',*#<>=;[\]\\\$]{1,1000}TMUX",
        r"([0-9]+\.[0-9]+[a-z]?)\r?\nversion\r?\nhost",
    ]
    VENDOR_PRODUCT = [
        ("tmux_project", "tmux"),
        ("tmux", "tmux"),
    ]
