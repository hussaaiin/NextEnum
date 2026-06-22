"""Command-line interface for NextEnum."""

from __future__ import annotations

import argparse
from pathlib import Path
from textwrap import wrap

from nextenum.parsers.normal_parser import ParsedNmapScan, ParsedService
from nextenum.parsers.normal_parser import parse_normal_nmap_file


def main() -> None:
    """Run the NextEnum CLI."""
    parser = build_argument_parser()
    args = parser.parse_args()

    if not args.file:
        parser.print_help()
        return

    file_path = Path(args.file)

    try:
        scan = parse_normal_nmap_file(file_path)
    except FileNotFoundError:
        print(f"[!] File not found: {file_path}")
        return
    except ValueError as error:
        print(f"[!] {error}")
        return

    target = args.target or scan.target or "Unknown"

    print_scan_summary(target=target, scan=scan)

    if args.show_scripts:
        print_script_results(scan)
    elif any(service.scripts for service in scan.services):
        print("Tip: run with --show-scripts to display detailed Nmap script results.")
        print()


def build_argument_parser() -> argparse.ArgumentParser:
    """Create and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="nextenum",
        description="Guide enumeration after Nmap scans.",
    )

    parser.add_argument(
        "--file",
        "-f",
        help="Path to an existing Nmap normal text output file.",
    )

    parser.add_argument(
        "--target",
        "-t",
        help="Target IP or hostname. Overrides the target detected from the scan file.",
    )

    parser.add_argument(
        "--show-scripts",
        action="store_true",
        help="Show detailed Nmap script output in a separate table.",
    )

    return parser


def print_scan_summary(target: str, scan: ParsedNmapScan) -> None:
    """Print a clean summary of the parsed Nmap scan."""
    print()
    print("=" * 110)
    print("NextEnum Scan Summary")
    print("=" * 110)
    print(f"Target: {target}")

    if scan.os_hints:
        print(f"OS Hints: {scan.os_hints}")

    print()
    print("Detected Services")

    headers = ["#", "Port", "Service", "Product", "Version / Extra", "Scripts"]
    widths = [3, 10, 18, 24, 26, 24]

    rows: list[list[str]] = []

    for index, service in enumerate(scan.services, start=1):
        rows.append(
            [
                str(index),
                f"{service.port}/{service.protocol}",
                _format_service_name(service),
                service.product or "-",
                _format_version_extra(service),
                _format_script_names(service),
            ]
        )

    if not rows:
        print("No open services found.")
        return

    print_table(headers=headers, rows=rows, widths=widths)
    print()


def print_script_results(scan: ParsedNmapScan) -> None:
    """Print detailed Nmap script results in a bordered table."""
    services_with_scripts = [
        service for service in scan.services if service.scripts
    ]

    if not services_with_scripts:
        print("No Nmap script results found.")
        return

    print("Nmap Script Results")

    headers = ["Port", "Script Result"]
    widths = [18, 86]

    rows: list[list[str]] = []

    for service in services_with_scripts:
        rows.append(
            [
                f"{service.port}/{service.protocol} {service.service.upper()}",
                _format_script_result_cell(service),
            ]
        )

    print_table(headers=headers, rows=rows, widths=widths)
    print()


def print_table(headers: list[str], rows: list[list[str]], widths: list[int]) -> None:
    """Print a bordered table with wrapped multiline cells."""
    border = _table_border(widths)

    print(border)
    print(_format_table_line(headers, widths))
    print(border)

    for row in rows:
        wrapped_cells = [
            _wrap_cell(cell, width) for cell, width in zip(row, widths)
        ]

        max_lines = max(len(cell_lines) for cell_lines in wrapped_cells)

        for line_index in range(max_lines):
            line_values = []

            for cell_lines in wrapped_cells:
                if line_index < len(cell_lines):
                    line_values.append(cell_lines[line_index])
                else:
                    line_values.append("")

            print(_format_table_line(line_values, widths))

        print(border)


def _table_border(widths: list[int]) -> str:
    """Return a horizontal table border."""
    return "+" + "+".join("-" * (width + 2) for width in widths) + "+"


def _format_table_line(values: list[str], widths: list[int]) -> str:
    """Return one formatted table line."""
    cells = []

    for value, width in zip(values, widths):
        cells.append(f" {value:<{width}} ")

    return "|" + "|".join(cells) + "|"


def _wrap_cell(value: str, width: int) -> list[str]:
    """Wrap one cell into multiple lines."""
    value = str(value).strip()

    if not value:
        return [""]

    lines: list[str] = []

    for part in value.splitlines():
        wrapped = wrap(part, width=width, break_long_words=False)
        lines.extend(wrapped or [""])

    return lines or [""]


def _format_service_name(service: ParsedService) -> str:
    """Return normalized service name with raw Nmap name if different."""
    if service.raw_service != service.service:
        return f"{service.service} ({service.raw_service})"

    return service.service


def _format_version_extra(service: ParsedService) -> str:
    """Return version and extra info inside one cell."""
    values = []

    if service.version:
        values.append(service.version)

    if service.extra_info:
        values.append(service.extra_info)

    return "\n".join(values) if values else "-"


def _format_script_names(service: ParsedService) -> str:
    """Return script names for the summary table."""
    if not service.scripts:
        return "-"

    return "\n".join(script.name for script in service.scripts)


def _format_script_result_cell(service: ParsedService) -> str:
    """Return full script output for one service as a multiline cell."""
    blocks = []

    for script in service.scripts:
        lines = [f"{script.name}:"]

        if script.output:
            lines.extend(f"  {output_line}" for output_line in script.output)
        else:
            lines.append("  -")

        blocks.append("\n".join(lines))

    return "\n\n".join(blocks)


if __name__ == "__main__":
    main()