# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
These are the customized strings and file classes, by doing this
the tool is able to support other operating systems like Windows
and MacOS.
"""

from __future__ import annotations

import re
import subprocess
from typing import ClassVar

from cve_bin_tool.async_utils import FileIO, run_coroutine
from cve_bin_tool.log import LOGGER
from cve_bin_tool.util import inpath


class Strings:
    """Utility class for parsing files and extracting printable characters."""

    PATTERN: ClassVar[re.Pattern[bytes]] = re.compile(rb"[\x20-\x7f\t]{3,}")
    TRAILING_PRINTABLE: ClassVar[re.Pattern[bytes]] = re.compile(rb"[\x20-\x7f\t]+$")
    CHUNK_SIZE: ClassVar[int] = 64 * 1024

    def __init__(self, filename: str = "") -> None:
        self.filename = filename
        self.output: str = ""

    async def aio_parse(self) -> str:
        """
        Asynchronous coroutine for parsing a file and extracting
        printable characters.

        Returns:
           str: The accumulated printable characters from the file.
        """
        results: list[str] = []
        leftover = b""
        async with FileIO(self.filename, "rb") as f:
            while True:
                data = await f.read(self.CHUNK_SIZE)
                if not data:
                    break
                chunk = leftover + data
                match = self.TRAILING_PRINTABLE.search(chunk)
                if match:
                    leftover = match.group(0)
                    chunk = chunk[: -len(leftover)]
                else:
                    leftover = b""
                if chunk:
                    for s in self.PATTERN.findall(chunk):
                        results.append(s.decode("ascii"))
            if leftover:
                for s in self.PATTERN.findall(leftover):
                    results.append(s.decode("ascii"))

        self.output = "\n".join(results) + ("\n" if results else "")
        return self.output

    def parse(self) -> str:
        """
        Synchronous entry point for parsing a file.

        Returns:
            str: The result of parsing.
        """
        return run_coroutine(self.aio_parse())


def parse_strings(filename: str) -> str:
    """parse binary file's strings"""

    if inpath("strings"):
        # use "strings" on system if available (for performance)
        try:
            data = subprocess.check_output(
                ["strings", "-n", "3", filename], stderr=subprocess.PIPE
            )
        except subprocess.CalledProcessError as error:
            # The system tool refused the file, which does not mean the file has
            # no strings in it. macOS ships a strings that reads a Java class
            # file's 0xCAFEBABE magic as Mach-O fat-binary magic, fails to parse
            # the header and exits 1, and the resulting CalledProcessError used
            # to end the whole scan rather than that one file. Fall back to the
            # Python implementation below, which reads bytes and cares nothing
            # about the container format.
            # stderr is captured rather than inherited so a jar full of class
            # files does not print one of these per entry.
            LOGGER.debug(
                "system strings failed on %s (%s), falling back to the Python "
                "implementation",
                filename,
                (error.stderr or b"").decode("utf-8", errors="replace").strip(),
            )
        else:
            return data.decode("utf-8", errors="backslashreplace")

    # Otherwise, use python implementation
    s = Strings(filename)
    return s.parse()
