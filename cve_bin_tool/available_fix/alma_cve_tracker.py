# Copyright (C) 2026 CVE Binary Tool contributors
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from cve_bin_tool.cve_scanner import CVEData
from cve_bin_tool.log import LOGGER
from cve_bin_tool.output_engine.util import ProductInfo, format_output
from cve_bin_tool.util import make_http_requests

# AlmaLinux errata API endpoint
# Using errata.full.json (not errata.json) because we need complete package details
# See: https://errata.almalinux.org/
ALMA_ERRATA_URL = "https://errata.almalinux.org/{}/errata.full.json"


class AlmaCVETracker:
    """
    AlmaCVETracker is responsible for tracking CVE information for AlmaLinux.

    AlmaLinux backports security fixes without changing version numbers.
    This tracker uses errata data to identify which CVEs have been fixed,
    helping reduce false positives when scanning AlmaLinux systems.

    Attributes:
        distro_name (str): The name of the distribution.
        distro_codename (str): The version number.
    """

    def __init__(self, distro_name: str, distro_codename: str):
        self.distro_name = distro_name
        self.distro_codename = distro_codename
        self.errata_data = None
        self.fixed_cves = {}  # Maps CVE ID -> list of fixed package info

    def _load_errata(self):
        """Load errata data from AlmaLinux API."""
        if self.errata_data is not None:
            return  # Already loaded

        url = ALMA_ERRATA_URL.format(self.distro_codename)

        LOGGER.debug(f"Fetching AlmaLinux {self.distro_codename} errata from {url}")

        try:
            self.errata_data = make_http_requests("json", url=url, timeout=300)
            if self.errata_data:
                self._process_errata()
                LOGGER.debug(
                    f"Loaded {len(self.fixed_cves)} CVE fixes from AlmaLinux errata"
                )
        except Exception as e:
            LOGGER.warning(f"Failed to fetch AlmaLinux errata: {e}")
            self.errata_data = []

    def _process_errata(self):
        """Process errata data to build CVE -> fixed packages mapping."""
        advisories = self.errata_data.get("data", [])

        for advisory in advisories:
            try:
                # Extract CVE IDs from references
                cve_ids = []
                for ref in advisory["references"]:
                    if ref["type"] == "cve":
                        cve_id = ref["id"]
                        if cve_id:
                            cve_ids.append(cve_id)

                if not cve_ids:
                    continue

                # Extract fixed packages
                packages = []
                for pkg in advisory["packages"]:
                    name = pkg["name"]
                    version = pkg["version"]
                    release = pkg["release"]

                    if name and version:
                        package_entry = {
                            "name": name,
                            "version": version,
                            "release": release,
                            "advisory": advisory["id"],
                        }
                        if package_entry not in packages:
                            packages.append(package_entry)

                # Map each CVE to its fixed packages
                for cve_id in cve_ids:
                    if cve_id not in self.fixed_cves:
                        self.fixed_cves[cve_id] = []
                    self.fixed_cves[cve_id].extend(packages)
            except (KeyError, TypeError) as exc:
                LOGGER.warning(f"Skipping malformed AlmaLinux advisory: {exc}")

    def cve_info(
        self,
        all_cve_data: dict[ProductInfo, CVEData],
    ):
        """
        Produces the available fixes' info for AlmaLinux.

        Args:
            all_cve_data: Dictionary mapping ProductInfo to CVEData
        """
        # Load errata if not already loaded
        self._load_errata()

        cve_data = format_output(all_cve_data, None)

        for cve in cve_data:
            cve_number = cve["cve_number"]
            product = cve["product"]

            if cve_number == "UNKNOWN":
                continue

            # Check if this CVE has a fix in AlmaLinux errata
            if cve_number in self.fixed_cves:
                fixed_packages = self.fixed_cves[cve_number]

                # Look for matching product in fixed packages
                matching_fixes = [
                    pkg
                    for pkg in fixed_packages
                    if self._product_matches(product, pkg["name"])
                ]

                if matching_fixes:
                    for fix in matching_fixes:
                        pkg_info = f"{fix['name']} v{fix['version']}-{fix['release']}"
                        LOGGER.info(
                            f"{product}: {cve_number} - Status: Fixed - "
                            f"Fixed package: {pkg_info} (Advisory: {fix['advisory']}; AlmaLinux {self.distro_codename})"
                        )
                else:
                    # CVE is fixed but for different packages
                    LOGGER.info(
                        f"{product}: {cve_number} - Status: Fixed "
                        f"(by different package(s) in AlmaLinux {self.distro_codename}: {fixed_packages})"
                    )
            else:
                LOGGER.info(
                    f"{product}: No known fix for {cve_number} in AlmaLinux {self.distro_codename}."
                )

    def _product_matches(self, product: str, package_name: str) -> bool:
        """
        Check if a product name matches a package name.

        Currently uses exact matching only (case-insensitive).
        """
        return product.lower() == package_name.lower()
