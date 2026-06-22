"""Command-line interface for NextEnum."""

from __future__ import annotations

import argparse
from pathlib import Path

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

    return parser


def print_scan_summary(target: str, scan) -> None:
    """Print a clean summary of the parsed Nmap scan."""
    print()
    print("=" * 60)
    print("NextEnum Scan Summary")
    print("=" * 60)
    print(f"Target: {target}")

    if scan.os_hints:
        print(f"OS Hints: {scan.os_hints}")

    print()
    print("Detected Services")
    print("-" * 60)

    if not scan.services:
        print("No open services found.")
        return

    print(f"{'#':<4}{'PORT':<10}{'SERVICE':<16}{'VERSION'}")
    print("-" * 60)

    for index, service in enumerate(scan.services, start=1):
        port = f"{service.port}/{service.protocol}"
        version = service.version if service.version else "-"
        print(f"{index:<4}{port:<10}{service.service:<16}{version}")

    print("-" * 60)
    print()


if __name__ == "__main__":
    main()