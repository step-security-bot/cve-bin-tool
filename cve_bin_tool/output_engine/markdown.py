# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
output_engine/markdown.py - Output scan results in GitHub Flavored Markdown (GFM) format.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import IO, Any

from cve_bin_tool.cve_scanner import CVEData
from cve_bin_tool.output_engine.util import (
    ProductInfo,
    VersionInfo,
    format_output,
    get_cve_summary,
    get_latest_upstream_stable_version,
)
from cve_bin_tool.util import strip_path
from cve_bin_tool.version import VERSION


def _escape_cell(text: Any) -> str:
    """Escape pipes and replace newlines for markdown table cell formatting."""
    if text is None:
        return ""
    text_str = str(text)
    text_str = (
        text_str.replace("\r\n", "<br>").replace("\n", "<br>").replace("\r", "<br>")
    )
    text_str = text_str.replace("|", "\\|")
    return text_str


def _format_cve_link(cve_number: str) -> str:
    """Format CVE number as a Markdown link to NVD if applicable."""
    if cve_number.startswith("CVE-"):
        return f"[{cve_number}](https://nvd.nist.gov/vuln/detail/{cve_number})"
    return cve_number


def _build_markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    """Build a GitHub Flavored Markdown table string."""
    escaped_headers = [_escape_cell(h) for h in headers]
    header_line = "| " + " | ".join(escaped_headers) + " |"
    separator_line = "| " + " | ".join([":---"] * len(headers)) + " |"
    table_lines = [header_line, separator_line]
    for row in rows:
        escaped_row = [_escape_cell(cell) for cell in row]
        table_lines.append("| " + " | ".join(escaped_row) + " |")
    return "\n".join(table_lines)


def output_markdown(
    all_cve_data: dict[ProductInfo, CVEData],
    all_cve_version_info: dict[str, VersionInfo] | None,
    scanned_dir: str,
    outfile: IO[str] | Any,
    time_of_last_update: datetime | str | None = None,
    detailed: bool = False,
    affected_versions: int = 0,
    metrics: bool = False,
    strip_scan_dir: bool = False,
    no_scan: bool = False,
    all_product_data: dict[ProductInfo, Any] | None = None,
    exploits: bool = False,
    offline: bool = False,
) -> None:
    """
    Output a Markdown report of CVEs or detected components (in no-scan mode).

    Args:
        all_cve_data: Dictionary mapping ProductInfo to CVEData
        all_cve_version_info: Dictionary containing version ranges for CVEs
        scanned_dir: Directory or file that was scanned
        outfile: File-like object or path to write Markdown output
        time_of_last_update: Timestamp of the last CVE database update
        detailed: If True, include vulnerability descriptions
        affected_versions: If non-zero, include affected version ranges
        metrics: If True, include EPSS probability and percentile metrics
        strip_scan_dir: If True, strip the scan directory path from reported file paths
        no_scan: If True, only report detected components without CVE analysis
        all_product_data: Full mapping of all scanned product data
        exploits: If True, include exploit status in severity summary
        offline: If True, operate in offline mode (skip online version lookups)
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(time_of_last_update, datetime):
        db_date = time_of_last_update.strftime("%Y-%m-%d %H:%M:%S")
    elif time_of_last_update:
        db_date = str(time_of_last_update)
    else:
        db_date = "UNKNOWN"

    sections: list[str] = []

    # Title & Metadata
    metadata_lines = [
        "# CVE Binary Tool Report\n",
        f"- **cve-bin-tool version:** {VERSION}",
        f"- **Report Generated:** {now}",
    ]
    if no_scan:
        metadata_lines.append("- **Scan Mode:** No-Scan Mode (CVE scanning disabled)")
    else:
        metadata_lines.append(f"- **CVE Database Last Updated:** {db_date}")
    sections.append("\n".join(metadata_lines))

    if no_scan:
        # Callout banner for no-scan mode
        sections.append(
            "> [!NOTE]\n"
            "> **No-Scan Mode Active:** CVE scanning was disabled. This report shows only "
            "detected products and versions without vulnerability analysis."
        )

        detected_rows: list[list[str]] = []
        for product_info, component_data in all_cve_data.items():
            if strip_scan_dir:
                paths = ", ".join(
                    [strip_path(path, scanned_dir) for path in component_data["paths"]]
                )
            else:
                paths = ", ".join(component_data["paths"])

            detected_rows.append(
                [
                    product_info.vendor or "Unknown",
                    product_info.product or "Unknown",
                    product_info.version or "Unknown",
                    paths or "-",
                ]
            )

        sections.append("## Detected Products")
        if detected_rows:
            sections.append(
                _build_markdown_table(
                    ["Vendor", "Product", "Version", "Paths"],
                    sorted(detected_rows, key=lambda r: (r[0], r[1], r[2])),
                )
            )
        else:
            sections.append("No products detected.")

    else:
        # Standard Scan Mode
        # 1. Severity Summary Table
        summary = get_cve_summary(all_cve_data, exploits=exploits)
        summary_rows = [[sev, str(count)] for sev, count in summary.items()]
        sections.append("## Severity Summary")
        sections.append(_build_markdown_table(["Severity", "Count"], summary_rows))

        # 2. CPE Summary Table
        cpe_headers = [
            "Vendor",
            "Product",
            "Version",
            "Latest Upstream Stable Version",
        ]
        for severity in summary.keys():
            cpe_headers.append(f"{severity} CVEs Count")
        cpe_headers.append("TOTAL CVEs Count")

        prod_source = (
            all_product_data
            if all_product_data is not None
            else {
                prod: {"cves_total": len(data.get("cves", []))}
                for prod, data in all_cve_data.items()
            }
        )

        cpe_rows: list[list[str]] = []
        version_cache: dict[tuple[str, str], str] = {}
        for product_data in sorted(
            prod_source,
            key=lambda item: (
                item.product or "",
                item.version or "",
                item.vendor or "",
            ),
        ):
            prod_val = prod_source[product_data]
            cves_total = prod_val.get(
                "cves_total", len(all_cve_data.get(product_data, {}).get("cves", []))
            )
            if cves_total != 0:
                vendor = product_data.vendor or "Unknown"
                product = product_data.product or "Unknown"
                version = product_data.version or "Unknown"

                if offline:
                    latest_stable_version = "UNKNOWN (offline mode)"
                else:
                    cache_key = (vendor, product)
                    if cache_key not in version_cache:
                        version_cache[cache_key] = get_latest_upstream_stable_version(
                            product_data
                        )
                    latest_stable_version = version_cache[cache_key]

                prod_summary = get_cve_summary(
                    {
                        product_data: all_cve_data.get(
                            product_data, {"cves": [], "paths": set()}
                        )
                    },
                    exploits=exploits,
                )

                row = [
                    vendor,
                    product,
                    version,
                    latest_stable_version or "UNKNOWN",
                ]
                for severity in summary.keys():
                    row.append(str(prod_summary.get(severity, 0)))
                row.append(str(cves_total))
                cpe_rows.append(row)

        sections.append("## CPE Summary")
        if cpe_rows:
            sections.append(_build_markdown_table(cpe_headers, cpe_rows))
        else:
            sections.append("No products with vulnerabilities detected.")

        # 3. CVE Details Table
        formatted_cves = format_output(
            all_cve_data,
            scanned_dir,
            strip_scan_dir,
            all_cve_version_info,
            detailed,
            affected_versions,
            metrics,
        )

        sections.append("## Vulnerabilities")
        if formatted_cves:
            headers = [
                "Vendor",
                "Product",
                "Version",
                "CVE Number",
                "Severity",
                "Score",
                "CVSS Version",
            ]
            if metrics:
                headers.extend(["EPSS Probability", "EPSS Percentile"])
            if detailed:
                headers.append("Description")
            if affected_versions != 0:
                headers.append("Affected Versions")
            headers.append("Remarks")

            cve_rows: list[list[str]] = []
            has_guessed_vendor = False
            for cve_entry in formatted_cves:
                vendor = cve_entry.get("vendor", "")
                if "*" in vendor:
                    has_guessed_vendor = True
                row = [
                    vendor,
                    cve_entry.get("product", ""),
                    cve_entry.get("version", ""),
                    _format_cve_link(cve_entry.get("cve_number", "")),
                    cve_entry.get("severity", ""),
                    cve_entry.get("score", ""),
                    cve_entry.get("cvss_version", ""),
                ]
                if metrics:
                    row.append(cve_entry.get("epss_probability", "-"))
                    row.append(cve_entry.get("epss_percentile", "-"))
                if detailed:
                    row.append(cve_entry.get("description", ""))
                if affected_versions != 0:
                    row.append(cve_entry.get("affected_versions", "-"))
                row.append(cve_entry.get("remarks", ""))
                cve_rows.append(row)

            sections.append(_build_markdown_table(headers, cve_rows))
            if has_guessed_vendor:
                sections.append(
                    "*\\* Vendors marked with an asterisk were guessed by the tool.*"
                )
        else:
            sections.append("No vulnerabilities found.")

        # 4. Product Paths Table (Vulnerable Products)
        paths_by_product: dict[tuple[str, str, str], dict[str, Any]] = {}
        for product_info, cve_data in all_cve_data.items():
            if len(cve_data.get("cves", [])) > 0:
                vendor = product_info.vendor or "Unknown"
                product = product_info.product or "Unknown"
                version = product_info.version or "Unknown"
                key = (product, version, vendor)

                if key not in paths_by_product:
                    paths_by_product[key] = {
                        "vendor": vendor,
                        "product": product,
                        "version": version,
                        "sources": set(),
                        "paths": set(),
                    }

                for cve in cve_data.get("cves", []):
                    if isinstance(cve, str):
                        continue
                    source = (
                        getattr(cve, "data_source", None)
                        or (cve.get("source") if isinstance(cve, dict) else None)
                        or (cve.get("data_source") if isinstance(cve, dict) else None)
                    )
                    if source:
                        paths_by_product[key]["sources"].add(str(source))

                raw_paths = cve_data.get("paths", [])
                if (
                    not raw_paths
                    and all_product_data
                    and product_info in all_product_data
                ):
                    raw_paths = all_product_data[product_info].get("paths", [])

                for p in raw_paths:
                    if p and str(p).strip():
                        if strip_scan_dir:
                            paths_by_product[key]["paths"].add(
                                strip_path(str(p), scanned_dir)
                            )
                        else:
                            paths_by_product[key]["paths"].add(str(p))

        if paths_by_product:
            product_paths_rows = []
            for key in sorted(paths_by_product.keys()):
                info = paths_by_product[key]
                source_str = (
                    ", ".join(sorted(info["sources"])) if info["sources"] else "UNKNOWN"
                )
                paths_str = ", ".join(sorted(info["paths"])) if info["paths"] else "-"
                product_paths_rows.append(
                    [
                        info["vendor"],
                        info["product"],
                        info["version"],
                        source_str,
                        paths_str,
                    ]
                )

            sections.append("## Product Paths")
            sections.append(
                _build_markdown_table(
                    ["Vendor", "Product", "Version", "Source", "Paths"],
                    product_paths_rows,
                )
            )

        # 5. Products with No Identified Vulnerabilities
        if all_product_data is not None:
            products_with_cves = {
                f"{prod.product}={prod.version}"
                for prod, data in all_cve_data.items()
                if len(data.get("cves", [])) > 0
            }
            no_cve_by_product: dict[tuple[str, str, str], dict[str, Any]] = {}
            for prod_info, prod_val in all_product_data.items():
                if (
                    prod_val.get("cves_total", 0) == 0
                    and f"{prod_info.product}={prod_info.version}"
                    not in products_with_cves
                ):
                    vendor = prod_info.vendor or "Unknown"
                    product = prod_info.product or "Unknown"
                    version = prod_info.version or "Unknown"
                    key = (product, version, vendor)

                    if key not in no_cve_by_product:
                        no_cve_by_product[key] = {
                            "vendor": vendor,
                            "product": product,
                            "version": version,
                            "paths": set(),
                        }

                    for p in prod_val.get("paths", []):
                        if p and str(p).strip():
                            if strip_scan_dir:
                                no_cve_by_product[key]["paths"].add(
                                    strip_path(str(p), scanned_dir)
                                )
                            else:
                                no_cve_by_product[key]["paths"].add(str(p))

            if no_cve_by_product:
                no_cve_rows = []
                for key in sorted(no_cve_by_product.keys()):
                    info = no_cve_by_product[key]
                    paths_str = (
                        ", ".join(sorted(info["paths"])) if info["paths"] else "-"
                    )
                    no_cve_rows.append(
                        [
                            info["vendor"],
                            info["product"],
                            info["version"],
                            paths_str,
                        ]
                    )

                sections.append("## Products with No Identified Vulnerabilities")
                sections.append(
                    _build_markdown_table(
                        ["Vendor", "Product", "Version", "Paths"],
                        no_cve_rows,
                    )
                )

    content = "\n\n".join(s.strip() for s in sections) + "\n"

    # Write output to destination
    if hasattr(outfile, "write"):
        outfile.write(content)
    elif isinstance(outfile, (str, Path)):
        with open(outfile, "w", encoding="utf-8") as f:
            f.write(content)
    else:
        sys.stdout.write(content)
