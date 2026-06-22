"""Parser for normal Nmap text output."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re


@dataclass(frozen=True)
class ParsedService:
    """Represents one detected service from an Nmap scan."""

    port: int
    protocol: str
    state: str
    service: str
    version: str = ""


@dataclass(frozen=True)
class ParsedNmapScan:
    """Represents important information extracted from an Nmap scan."""

    target: str | None = None
    services: list[ParsedService] = field(default_factory=list)
    os_hints: str | None = None


PORT_LINE_PATTERN = re.compile(
    r"^(?P<port>\d+)\/(?P<protocol>\w+)\s+"
    r"(?P<state>\w+)\s+"
    r"(?P<service>\S+)"
    r"(?:\s+(?P<version>.*))?$"
)

TARGET_PATTERN = re.compile(r"^Nmap scan report for (?P<target>.+)$")
SERVICE_INFO_PATTERN = re.compile(r"^Service Info:\s*(?P<info>.+)$")


def parse_normal_nmap_file(file_path: str | Path) -> ParsedNmapScan:
    """Parse a normal Nmap text output file.

    Args:
        file_path: Path to the Nmap .txt output file.

    Returns:
        ParsedNmapScan containing the target, services, and OS hints.

    Raises:
        FileNotFoundError: If the provided file does not exist.
        ValueError: If the provided path is not a file.
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Nmap output file not found: {path}")

    if not path.is_file():
        raise ValueError(f"Expected a file path, got: {path}")

    content = path.read_text(encoding="utf-8", errors="replace")
    return parse_normal_nmap_text(content)


def parse_normal_nmap_text(text: str) -> ParsedNmapScan:
    """Parse normal Nmap text output from a string."""
    target: str | None = None
    services: list[ParsedService] = []
    os_hints: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        target_match = TARGET_PATTERN.match(line)
        if target_match:
            target = _clean_target(target_match.group("target"))
            continue

        service_info_match = SERVICE_INFO_PATTERN.match(line)
        if service_info_match:
            os_hints = service_info_match.group("info").strip()
            continue

        port_match = PORT_LINE_PATTERN.match(line)
        if not port_match:
            continue

        state = port_match.group("state").lower()

        if state != "open":
            continue

        services.append(
            ParsedService(
                port=int(port_match.group("port")),
                protocol=port_match.group("protocol").lower(),
                state=state,
                service=port_match.group("service").lower(),
                version=(port_match.group("version") or "").strip(),
            )
        )

    return ParsedNmapScan(
        target=target,
        services=services,
        os_hints=os_hints,
    )


def _clean_target(raw_target: str) -> str:
    """Clean the target value from the Nmap scan report line.

    Handles both:
    - Nmap scan report for 10.10.10.5
    - Nmap scan report for example.local (10.10.10.5)
    """
    raw_target = raw_target.strip()

    ip_match = re.search(r"\(([^)]+)\)$", raw_target)
    if ip_match:
        return ip_match.group(1).strip()

    return raw_target


def _demo(file_path: str) -> None:
    """Small manual test helper."""
    scan = parse_normal_nmap_file(file_path)

    print(f"Target: {scan.target or 'Unknown'}")

    if scan.os_hints:
        print(f"OS Hints: {scan.os_hints}")

    print("\nDetected Services:")

    if not scan.services:
        print("No open services found.")
        return

    for index, service in enumerate(scan.services, start=1):
        version = f" {service.version}" if service.version else ""
        print(
            f"[{index}] {service.port}/{service.protocol} "
            f"{service.service}{version}"
        )


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python -m nextenum.parsers.normal_parser <nmap-output.txt>")
        raise SystemExit(1)

    _demo(sys.argv[1])