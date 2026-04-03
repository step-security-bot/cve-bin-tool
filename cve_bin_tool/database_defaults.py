# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import os
from pathlib import Path

CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
DISK_LOCATION_DEFAULT = CACHE_DIR / "cve-bin-tool"
DISK_LOCATION_BACKUP = CACHE_DIR / "cve-bin-tool-backup"
OLD_CACHE_DIR = Path.home() / ".cache" / "cvedb"
DBNAME = "cve.db"
NVD_VERSION = "2.0"
# You must add gz or zip after the template for it to be valid
NVD_FILENAME_TEMPLATE = "nvdcve-" + NVD_VERSION + "-{}.json."
