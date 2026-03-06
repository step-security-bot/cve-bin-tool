# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import importlib.resources as resources
from abc import ABC, abstractmethod


class Data_Source(ABC):
    @abstractmethod
    async def get_cve_data(self):
        pass


class DataSourceSupport:
    # Supported Data Sources
    DATA_SOURCES_ENTRYPOINT = "cve_bin_tool.data_sources"

    def __init__(self):
        self.data_sources = self.available_data_sources()

    @classmethod
    def available_data_sources(cls) -> list[str]:
        """Find Data Sources"""
        data_sources_directory = resources.files(cls.DATA_SOURCES_ENTRYPOINT)
        sources = data_sources_directory.iterdir()
        disable_source = []
        disable_source.append("__init__")
        data_sources = []
        for data_source in sources:
            if str(data_source).endswith(".py"):
                source = data_source.name.replace(".py", "")
                if source not in disable_source:
                    data_sources.append(source.replace("_source", "").upper())
        return sorted(data_sources)

    def get_data_sources(self) -> list[str]:
        return self.data_sources
