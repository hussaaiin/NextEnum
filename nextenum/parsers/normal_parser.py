"""Parser for normal Nmap text output."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re


@dataclass
class ParsedScriptOutput:
    """Represents NSE script output attached to a service."""

    name: str
    output: list[str] = field(default_factory=list)


@dataclass
class ParsedService:
    """Represents one detected service from an Nmap scan."""

    port: int
    protocol: str
    state: str
    raw_service: str
    service: str
    product: str = ""
    version: str = ""
    extra_info: str = ""
    scripts: list[ParsedScriptOutput] = field(default_factory=list)

    @property
    def display_info(self) -> str:
        """Return product, version, and extra info as one readable string."""
        parts = [self.product, self.version, self.extra_info]
        return " ".join(part for part in parts if part).strip()


@dataclass
class ParsedNmapScan:
    """Represents important information extracted from an Nmap scan."""

    target: str | None = None
    services: list[ParsedService] = field(default_factory=list)
    os_hints: str | None = None


PORT_LINE_PATTERN = re.compile(
    r"^(?P<port>\d+)\/(?P<protocol>\w+)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<service>\S+)"
    r"(?:\s+(?P<details>.*))?$"
)

TARGET_PATTERN = re.compile(r"^Nmap scan report for (?P<target>.+)$")
SERVICE_INFO_PATTERN = re.compile(r"^Service Info:\s*(?P<info>.+)$")

SCRIPT_START_PATTERN = re.compile(
    r"^(?P<name>[A-Za-z0-9_.-]+):\s*(?P<output>.*)$"
)

VERSION_TOKEN_PATTERN = re.compile(
    r"\b\d+(?:[._-][A-Za-z0-9]+)*(?:[A-Za-z][A-Za-z0-9._-]*)?\b"
)

SERVICE_ALIASES = {
    "http-alt": "http",
    "http-proxy": "http",
    "www": "http",
    "www-http": "http",
    "ssl/http": "https",
    "https-alt": "https",
    "netbios-ssn": "smb",
    "microsoft-ds": "smb",
    "netbios-ns": "smb",
    "netbios-dgm": "smb",
    "domain": "dns",
    "domain-s": "dns",
    "ms-wbt-server": "rdp",
    "submission": "smtp",
    "nfs_acl": "nfs",
    "mountd": "nfs",
    "postgres": "postgresql",
}

COMMON_PORT_SERVICES = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    139: "smb",
    443: "https",
    445: "smb",
    161: "snmp",
    2049: "nfs",
    3306: "mysql",
    5432: "postgresql",
    3389: "rdp",
    8000: "http",
    8080: "http",
    8443: "https",
}


def parse_normal_nmap_file(file_path: str | Path) -> ParsedNmapScan:
    """Parse a normal Nmap text output file."""
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
    current_service: ParsedService | None = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped_line = line.strip()

        if not stripped_line:
            continue

        if _is_script_output_line(line) and current_service:
            _add_script_output_line(current_service, line)
            continue

        target_match = TARGET_PATTERN.match(stripped_line)
        if target_match:
            target = _clean_target(target_match.group("target"))
            current_service = None
            continue

        service_info_match = SERVICE_INFO_PATTERN.match(stripped_line)
        if service_info_match:
            os_hints = service_info_match.group("info").strip()
            current_service = None
            continue

        port_match = PORT_LINE_PATTERN.match(stripped_line)
        if not port_match:
            continue

        state = port_match.group("state").lower()

        if state != "open":
            current_service = None
            continue

        port = int(port_match.group("port"))
        protocol = port_match.group("protocol").lower()
        raw_service = port_match.group("service").lower()
        service = normalize_service_name(raw_service=raw_service, port=port)
        details = (port_match.group("details") or "").strip()
        product, version, extra_info = split_product_version(details)

        parsed_service = ParsedService(
            port=port,
            protocol=protocol,
            state=state,
            raw_service=raw_service,
            service=service,
            product=product,
            version=version,
            extra_info=extra_info,
        )

        services.append(parsed_service)
        current_service = parsed_service

    return ParsedNmapScan(
        target=target,
        services=services,
        os_hints=os_hints,
    )


def normalize_service_name(raw_service: str, port: int) -> str:
    """Normalize Nmap service names into simpler names for guidance."""
    raw_service = raw_service.strip().lower()

    if raw_service in SERVICE_ALIASES:
        return SERVICE_ALIASES[raw_service]

    if raw_service in {"unknown", "tcpwrapped"}:
        return COMMON_PORT_SERVICES.get(port, raw_service)

    if port == 443 and raw_service == "http":
        return "https"

    return raw_service


def split_product_version(details: str) -> tuple[str, str, str]:
    """Split Nmap service details into product, version, and extra info."""
    details = details.strip()

    if not details:
        return "", "", ""

    version_match = VERSION_TOKEN_PATTERN.search(details)

    if not version_match:
        return details, "", ""

    product = details[: version_match.start()].strip(" -")
    version = version_match.group().strip()
    extra_info = details[version_match.end() :].strip()

    return product, version, extra_info


def _is_script_output_line(line: str) -> bool:
    """Return True if a line looks like Nmap NSE script output."""
    stripped = line.lstrip()
    return stripped.startswith("|") or stripped.startswith("|_")


def _add_script_output_line(service: ParsedService, line: str) -> None:
    """Attach one NSE script output line to the current service."""
    body, is_new_script = _clean_script_line(line)

    if not body:
        return

    script_start_match = SCRIPT_START_PATTERN.match(body)

    if is_new_script and script_start_match:
        script_name = script_start_match.group("name").strip()
        script_output = script_start_match.group("output").strip()

        parsed_script = ParsedScriptOutput(name=script_name)

        if script_output:
            parsed_script.output.append(script_output)

        service.scripts.append(parsed_script)
        return

    if service.scripts:
        service.scripts[-1].output.append(body)
        return

    service.scripts.append(
        ParsedScriptOutput(
            name="unknown-script-output",
            output=[body],
        )
    )


def _clean_script_line(line: str) -> tuple[str, bool]:
    """Remove Nmap script markers and detect if the line starts a new script.

    Nmap script output has two common forms:

    | script-name: output
    |   continuation line
    |_final continuation line

    Only top-level script lines should become new script entries.
    Indented lines should stay under the previous script.
    """
    stripped = line.lstrip()

    if stripped.startswith("|_"):
        content = stripped[2:]
    elif stripped.startswith("|"):
        content = stripped[1:]
    else:
        return stripped.strip(), False

    leading_spaces = len(content) - len(content.lstrip(" "))
    body = content.strip()

    is_new_script = leading_spaces <= 1 and bool(SCRIPT_START_PATTERN.match(body))

    return body, is_new_script


def _clean_target(raw_target: str) -> str:
    """Clean the target value from the Nmap scan report line."""
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
        raw_note = ""
        if service.raw_service != service.service:
            raw_note = f" raw={service.raw_service}"

        service_info = service.display_info or "-"
        print(
            f"[{index}] {service.port}/{service.protocol} "
            f"{service.service}{raw_note} {service_info}"
        )

        if service.scripts:
            print("    Scripts:")
            for script in service.scripts:
                print(f"    - {script.name}")
                for output_line in script.output:
                    print(f"      {output_line}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python -m nextenum.parsers.normal_parser <nmap-output.txt>")
        raise SystemExit(1)

    _demo(sys.argv[1])