# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later
"""Python script containing all functionalities related to parsing of Windows PE files."""

import pefile

from cve_bin_tool.parsers import Parser
from cve_bin_tool.util import ProductInfo, ScanInfo


class PeParser(Parser):
    """
    Parser for Windows PE files
    """

    PARSER_MATCH_FILENAMES = [
        ".pyd",
    ]

    def __init__(self, cve_db, logger):
        """Initialize the pe package metadata parser."""
        super().__init__(cve_db, logger)

    def run_checker(self, filename):
        """
        This generator runs only for Windows PE files.
        There are no actual checkers.
        """
        self.filename = filename
        try:
            with pefile.PE(filename) as pe:
                for fileinfo in pe.FileInfo:
                    for entry in fileinfo:
                        if entry.Key == b"StringFileInfo":
                            for st in entry.StringTable:
                                entries = st.entries
                                vendor = entries.get(b"CompanyName", b"").decode(
                                    errors="ignore"
                                )
                                if vendor == "Python Software Foundation":
                                    vendor = "python"
                                product = (
                                    entries.get(b"ProductName", b"")
                                    .decode(errors="ignore")
                                    .lower()
                                )
                                version = entries.get(b"ProductVersion", b"").decode(
                                    errors="ignore"
                                )
                                self.logger.debug(product)
                                vendorlist: list[ScanInfo] = [
                                    ScanInfo(
                                        ProductInfo(vendor, product, version),
                                        self.filename,
                                    )
                                ]
                                yield from vendorlist
        except pefile.PEFormatError:
            self.logger.debug(f"Failed to parse PE file {filename}")
        self.logger.debug(f"Done scanning file: {filename}")
