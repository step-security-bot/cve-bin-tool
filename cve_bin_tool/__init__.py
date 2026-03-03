# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import os

# Hardcode CycloneDX version to 1.6
# Can be removed when other opensource tools will handle version 1.7
os.environ["LIB4SBOM_CYCLONEDX_VERSION"] = "1.6"
