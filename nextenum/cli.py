"""Command-line interface for NextEnum."""

from __future__ import annotations

import argparse
from pathlib import Path
from textwrap import dedent, wrap

from nextenum.knowledge.loader import (
    KnowledgeBaseError,
    get_knowledge_for_service,
    list_available_service_guides,
)
from nextenum.parsers.normal_parser import ParsedNmapScan, ParsedService
from nextenum.parsers.normal_parser import parse_normal_nmap_file
from nextenum.parsers.xml_parser import parse_xml_nmap_file


GUIDE_WIDTH = 100
FINDING_COLUMN_WIDTH = 32
NEXT_STEPS_COLUMN_WIDTH = GUIDE_WIDTH - FINDING_COLUMN_WIDTH - 7


def main() -> None:
    """Run the NextEnum CLI."""
    parser = build_argument_parser()
    args = parser.parse_args()

    if args.short_help:
        print_short_help()
        return

    if args.detailed_help:
        print_detailed_help()
        return

    if args.show_scripts and args.only_scripts:
        parser.error("Use either --show-scripts or --only-scripts, not both.")

    if args.only_scripts and args.guide is not None:
        parser.error("Use either --only-scripts or --guide, not both.")

    if args.show_scripts and args.guide is not None:
        parser.error("Use either --show-scripts or --guide, not both.")

    if not args.file:
        print_short_help()
        return

    file_path = Path(args.file)

    try:
        scan = parse_nmap_file(file_path)
    except FileNotFoundError:
        print(f"[!] File not found: {file_path}")
        return
    except ValueError as error:
        print(f"[!] {error}")
        return

    target = args.target or scan.target or "Unknown"

    if args.only_scripts:
        print_script_results(scan)
        return

    if args.guide is not None:
        print_guidance(target=target, scan=scan, guide_filters=args.guide)
        return

    print_scan_summary(target=target, scan=scan)

    if args.show_scripts:
        print_script_results(scan)
    elif any(service.scripts for service in scan.services):
        print("Tip: run with --show-scripts to display detailed Nmap script results.")
        print("Tip: run with --only-scripts to display only detailed Nmap script results.")
        print()


def parse_nmap_file(file_path: Path) -> ParsedNmapScan:
    """Parse an Nmap file based on its extension."""
    if file_path.suffix.lower() == ".xml":
        return parse_xml_nmap_file(file_path)

    return parse_normal_nmap_file(file_path)


def build_argument_parser() -> argparse.ArgumentParser:
    """Create and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="nextenum",
        description="Guide enumeration after Nmap scans.",
        add_help=False,
    )

    parser.add_argument(
        "-h",
        dest="short_help",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    parser.add_argument(
        "--help",
        dest="detailed_help",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    parser.add_argument(
        "--file",
        "-f",
        help="Path to an existing Nmap output file. Supports normal text and XML.",
    )

    parser.add_argument(
        "--target",
        "-t",
        help="Target IP or hostname. Overrides the target detected from the scan file.",
    )

    parser.add_argument(
        "--show-scripts",
        action="store_true",
        help="Show detailed Nmap script output after the main service table.",
    )

    parser.add_argument(
        "--only-scripts",
        action="store_true",
        help="Only show detailed Nmap script output, without the main service table.",
    )

    parser.add_argument(
        "--guide",
        nargs="*",
        metavar="SERVICE_OR_PORT",
        help=(
            "Show enumeration guidance. Use without values for all detected services, "
            "or pass service names/ports like: --guide http 80 ftp 21."
        ),
    )

    return parser


def print_short_help() -> None:
    """Print the short help menu."""
    print(
        dedent(
            """
            NextEnum - Nmap enumeration guide

            Usage:
              nextenum -f SCAN_FILE [options]

            Common flags:
              -f, --file FILE        Read an Nmap normal text or XML output file.
              -t, --target TARGET    Override the target detected from the scan file.
              --guide [SERVICE|PORT] Show enumeration guidance for all services, or only
                                     selected services/ports.
              --show-scripts         Show the service table and detailed NSE script output.
              --only-scripts         Show only detailed NSE script output.

            Example:
              nextenum -f examples/sample_scan.xml --guide http

            Use --help for the detailed help menu.
            """
        ).strip()
    )


def print_detailed_help() -> None:
    """Print the detailed help menu."""
    print(
        dedent(
            """
            NextEnum - Nmap enumeration guide

            NextEnum reads Nmap scan output and helps you decide what to enumerate next.
            It is designed for authorized labs, CTFs, and learning environments.

            Usage:
              nextenum -f SCAN_FILE [options]

            Input:
              -f, --file FILE
                  Path to an existing Nmap output file.
                  Supported formats:
                    - Normal text output, usually created with: nmap -oN scan.txt
                    - XML output, usually created with: nmap -oX scan.xml

              -t, --target TARGET
                  Override the target detected from the scan file.
                  Useful when the scan file does not contain the target you want shown
                  in generated commands.

            Script output:
              --show-scripts
                  Print the normal service summary table, then print a detailed table
                  containing NSE script results.

              --only-scripts
                  Print only the detailed NSE script table.
                  This cannot be combined with --guide.

            Enumeration guide:
              --guide [SERVICE_OR_PORT ...]
                  Show enumeration guidance from the service knowledge base.

                  Without values:
                    --guide
                    Shows guides for all detected services that have guide files.

                  With service names:
                    --guide http smb ssh
                    Shows only the matching service guides.

                  With ports:
                    --guide 80 445 22
                    Shows only the guides for services found on those ports.

                  Service names and ports can be mixed:
                    --guide http 445

                  This cannot be combined with --show-scripts or --only-scripts.

            Help:
              -h
                  Show the short help menu.

              --help
                  Show this detailed help menu.

            Examples:
              nextenum -f examples/sample_scan.xml
              nextenum -f examples/sample_scan.xml -t 10.10.10.5 --guide http
              nextenum -f examples/sample_scan.xml --only-scripts
            """
        ).strip()
    )


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

    print()
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


def print_guidance(
    target: str,
    scan: ParsedNmapScan,
    guide_filters: list[str],
) -> None:
    """Print enumeration guidance for matching services."""
    matched_services, missing_filters = select_services_for_guidance(
        scan=scan,
        guide_filters=guide_filters,
    )

    if missing_filters:
        print_missing_guide_filters(scan=scan, missing_filters=missing_filters)

    if not matched_services:
        print("[!] No matching services were found for guidance.")
        return

    print()
    print("=" * GUIDE_WIDTH)
    print("NextEnum Enumeration Guide")
    print("=" * GUIDE_WIDTH)
    print(f"Target: {target}")

    available_guides = list_available_service_guides()
    printed_any_guide = False

    for service in matched_services:
        try:
            knowledge = get_knowledge_for_service(service)
        except KnowledgeBaseError as error:
            print(f"[!] {error}")
            continue

        if not knowledge:
            print()
            print(
                f"[!] No guide available yet for "
                f"{service.port}/{service.protocol} {service.service.upper()}."
            )
            if available_guides:
                print(f"    Available guides: {', '.join(available_guides)}")
            continue

        printed_any_guide = True
        print_service_guidance(target=target, service=service, knowledge=knowledge)

    if not printed_any_guide:
        print()
        print("[!] None of the matched services have knowledge base entries yet.")


def select_services_for_guidance(
    scan: ParsedNmapScan,
    guide_filters: list[str],
) -> tuple[list[ParsedService], list[str]]:
    """Return services matching guide filters and filters that matched nothing."""
    if not guide_filters:
        return scan.services, []

    matched_services: list[ParsedService] = []
    missing_filters: list[str] = []

    for guide_filter in guide_filters:
        matches = _find_services_by_filter(scan.services, guide_filter)

        if not matches:
            missing_filters.append(guide_filter)
            continue

        for service in matches:
            if service not in matched_services:
                matched_services.append(service)

    return matched_services, missing_filters


def print_missing_guide_filters(
    scan: ParsedNmapScan,
    missing_filters: list[str],
) -> None:
    """Print helpful errors for guide filters that did not match."""
    print()

    for missing_filter in missing_filters:
        print(f"[!] No detected service matched guide filter: {missing_filter}")

    if scan.services:
        available = ", ".join(
            f"{service.port}/{service.protocol} {service.service}"
            for service in scan.services
        )
        print(f"    Detected services: {available}")
    else:
        print("    No open services were detected in the scan.")


def print_service_guidance(
    target: str,
    service: ParsedService,
    knowledge: dict[str, object],
) -> None:
    """Print one service guidance block."""
    display_name = str(knowledge.get("display_name") or service.service.upper())
    description = str(knowledge.get("description") or "").strip()
    why_prioritize = _string_list(knowledge.get("why_prioritize"))
    enumeration_steps = _dict_list(knowledge.get("enumeration_steps"))
    finding_next_steps = _dict_list(knowledge.get("finding_next_steps"))
    beginner_notes = _string_list(knowledge.get("beginner_notes"))
    useful_nmap_scripts = _string_list(knowledge.get("useful_nmap_scripts"))

    print()
    print("=" * GUIDE_WIDTH)
    print(f"{service.port}/{service.protocol} {display_name}")
    print("=" * GUIDE_WIDTH)

    if service.display_info:
        print("Detected:")
        _print_wrapped_text(service.display_info, indent=2)

    if description:
        print()
        print("What it is:")
        _print_wrapped_text(description, indent=2)

    if why_prioritize:
        print()
        print("Why check it:")
        _print_bullets(why_prioritize, indent=2)

    if useful_nmap_scripts:
        print()
        print("Useful Nmap scripts to consider:")
        _print_bullets(useful_nmap_scripts, indent=2)

    if enumeration_steps:
        print()
        print("Suggested enumeration steps:")

        for index, step in enumerate(enumeration_steps, start=1):
            title = str(step.get("title") or f"Step {index}")
            reason = str(step.get("reason") or "").strip()
            commands = _string_list(step.get("commands"))
            look_for = _string_list(step.get("look_for"))

            print()
            print("-" * GUIDE_WIDTH)
            print(f"Step {index}: {title}")
            print("-" * GUIDE_WIDTH)

            if reason:
                print("Reason:")
                _print_wrapped_text(reason, indent=2)

            if commands:
                print()
                print("Commands:")
                for command in commands:
                    formatted_command = format_guide_command(command, target, service)
                    print(f"  {formatted_command}")

            if look_for:
                print()
                print("Look for:")
                _print_bullets(look_for, indent=2)

    if finding_next_steps:
        print()
        print("=" * GUIDE_WIDTH)
        print("If you find something interesting")
        print("=" * GUIDE_WIDTH)
        print_finding_next_steps_table(finding_next_steps)

    if beginner_notes:
        print()
        print("=" * GUIDE_WIDTH)
        print("Beginner notes")
        print("=" * GUIDE_WIDTH)
        _print_bullets(beginner_notes, indent=2)


def _print_wrapped_text(text: str, indent: int = 0) -> None:
    """Print wrapped text using a consistent guide width."""
    prefix = " " * indent
    available_width = max(20, GUIDE_WIDTH - indent)

    lines = wrap(
        text.strip(),
        width=available_width,
        break_long_words=False,
        break_on_hyphens=False,
    )

    for line in lines or [""]:
        print(f"{prefix}{line}")


def _print_bullets(items: list[str], indent: int = 0) -> None:
    """Print wrapped bullet points."""
    for item in items:
        _print_bullet(item, indent=indent)


def _print_bullet(text: str, indent: int = 0) -> None:
    """Print one wrapped bullet point."""
    bullet_prefix = " " * indent + "- "
    continuation_prefix = " " * (indent + 2)
    available_width = max(20, GUIDE_WIDTH - len(bullet_prefix))

    lines = wrap(
        text.strip(),
        width=available_width,
        break_long_words=False,
        break_on_hyphens=False,
    )

    if not lines:
        print(bullet_prefix.rstrip())
        return

    print(f"{bullet_prefix}{lines[0]}")

    for line in lines[1:]:
        print(f"{continuation_prefix}{line}")


def print_finding_next_steps_table(
    finding_next_steps: list[dict[str, object]],
) -> None:
    """Print finding-based next steps in a two-column table."""
    rows: list[list[str]] = []

    for item in finding_next_steps:
        finding = str(item.get("finding") or "").strip()
        next_steps = _string_list(item.get("next_steps"))

        if not finding or not next_steps:
            continue

        rows.append(
            [
                finding,
                _format_bullet_table_cell(
                    items=next_steps,
                    width=NEXT_STEPS_COLUMN_WIDTH,
                ),
            ]
        )

    if not rows:
        print("No finding-based next steps available.")
        return

    print()
    print_table(
        headers=["Finding", "Next steps"],
        rows=rows,
        widths=[FINDING_COLUMN_WIDTH, NEXT_STEPS_COLUMN_WIDTH],
    )


def _format_bullet_table_cell(items: list[str], width: int) -> str:
    """Return wrapped bullet points for use inside a table cell."""
    lines: list[str] = []

    for item in items:
        wrapped_lines = wrap(
            item.strip(),
            width=max(20, width - 2),
            break_long_words=False,
            break_on_hyphens=False,
        )

        if not wrapped_lines:
            lines.append("-")
            continue

        lines.append(f"- {wrapped_lines[0]}")

        for wrapped_line in wrapped_lines[1:]:
            lines.append(f"  {wrapped_line}")

    return "\n".join(lines)


def format_guide_command(command: str, target: str, service: ParsedService) -> str:
    """Fill command placeholders with target and service values."""
    scheme = _default_url_scheme(service)

    return command.format(
        target=target,
        port=service.port,
        protocol=service.protocol,
        service=service.service,
        raw_service=service.raw_service,
        scheme=scheme,
    )


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


def _find_services_by_filter(
    services: list[ParsedService],
    guide_filter: str,
) -> list[ParsedService]:
    """Find services by port, normalized service name, or raw service name."""
    normalized_filter = guide_filter.strip().lower()

    if not normalized_filter:
        return []

    if normalized_filter.isdigit():
        port = int(normalized_filter)
        return [service for service in services if service.port == port]

    return [
        service
        for service in services
        if normalized_filter in {service.service.lower(), service.raw_service.lower()}
    ]


def _default_url_scheme(service: ParsedService) -> str:
    """Return a practical URL scheme for web guidance commands."""
    if service.service == "https" or service.port in {443, 8443}:
        return "https"

    return "http"


def _string_list(value: object) -> list[str]:
    """Return value as a list of strings if possible."""
    if not isinstance(value, list):
        return []

    return [str(item) for item in value if isinstance(item, str)]


def _dict_list(value: object) -> list[dict[str, object]]:
    """Return value as a list of dictionaries if possible."""
    if not isinstance(value, list):
        return []

    return [item for item in value if isinstance(item, dict)]


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
