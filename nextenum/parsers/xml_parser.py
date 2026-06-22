"""Parser for Nmap XML output."""

from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET

from nextenum.parsers.normal_parser import (
    ParsedNmapScan,
    ParsedScriptOutput,
    ParsedService,
    normalize_service_name,
)


def parse_xml_nmap_file(file_path: str | Path) -> ParsedNmapScan:
    """Parse an Nmap XML output file."""
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Nmap XML output file not found: {path}")

    if not path.is_file():
        raise ValueError(f"Expected a file path, got: {path}")

    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as error:
        raise ValueError(f"Invalid Nmap XML file: {path}") from error

    return parse_xml_nmap_root(root)


def parse_xml_nmap_text(text: str) -> ParsedNmapScan:
    """Parse Nmap XML output from a string."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError as error:
        raise ValueError("Invalid Nmap XML content.") from error

    return parse_xml_nmap_root(root)


def parse_xml_nmap_root(root: ET.Element) -> ParsedNmapScan:
    """Parse an ElementTree root from an Nmap XML document."""
    host = _find_first_up_host(root)

    if host is None:
        return ParsedNmapScan()

    target = _extract_target(host)
    services = _extract_services(host)
    os_hints = _extract_os_hints(host)

    return ParsedNmapScan(
        target=target,
        services=services,
        os_hints=os_hints,
    )


def _find_first_up_host(root: ET.Element) -> ET.Element | None:
    """Return the first host that is up, or the first host if status is missing."""
    hosts = root.findall("host")

    for host in hosts:
        status = host.find("status")
        if status is None or status.get("state") == "up":
            return host

    return hosts[0] if hosts else None


def _extract_target(host: ET.Element) -> str | None:
    """Extract the best target value from a host element."""
    ipv4_address = host.find("address[@addrtype='ipv4']")
    if ipv4_address is not None and ipv4_address.get("addr"):
        return ipv4_address.get("addr")

    ipv6_address = host.find("address[@addrtype='ipv6']")
    if ipv6_address is not None and ipv6_address.get("addr"):
        return ipv6_address.get("addr")

    hostname = host.find("hostnames/hostname")
    if hostname is not None and hostname.get("name"):
        return hostname.get("name")

    address = host.find("address")
    if address is not None and address.get("addr"):
        return address.get("addr")

    return None


def _extract_services(host: ET.Element) -> list[ParsedService]:
    """Extract open services from a host element."""
    services: list[ParsedService] = []

    for port_element in host.findall("ports/port"):
        state_element = port_element.find("state")
        state = (state_element.get("state") if state_element is not None else "").lower()

        if state != "open":
            continue

        port = int(port_element.get("portid", "0"))
        protocol = (port_element.get("protocol") or "tcp").lower()
        service_element = port_element.find("service")
        raw_service = _get_raw_service(service_element)
        service = normalize_service_name(raw_service=raw_service, port=port)
        product = _get_xml_attribute(service_element, "product")
        version = _get_xml_attribute(service_element, "version")
        extra_info = _get_xml_attribute(service_element, "extrainfo")
        scripts = _extract_scripts(port_element)

        services.append(
            ParsedService(
                port=port,
                protocol=protocol,
                state=state,
                raw_service=raw_service,
                service=service,
                product=product,
                version=version,
                extra_info=extra_info,
                scripts=scripts,
            )
        )

    return services


def _get_raw_service(service_element: ET.Element | None) -> str:
    """Return the raw Nmap service name from a service element."""
    if service_element is None:
        return "unknown"

    return (service_element.get("name") or "unknown").strip().lower()


def _get_xml_attribute(element: ET.Element | None, attribute_name: str) -> str:
    """Safely get and clean an XML attribute value."""
    if element is None:
        return ""

    return (element.get(attribute_name) or "").strip()


def _extract_scripts(port_element: ET.Element) -> list[ParsedScriptOutput]:
    """Extract NSE script output from a port element."""
    scripts: list[ParsedScriptOutput] = []

    for script_element in port_element.findall("script"):
        script_name = (script_element.get("id") or "unknown-script-output").strip()
        output = (script_element.get("output") or "").strip()
        output_lines = output.splitlines() if output else []

        scripts.append(
            ParsedScriptOutput(
                name=script_name,
                output=output_lines,
            )
        )

    return scripts


def _extract_os_hints(host: ET.Element) -> str | None:
    """Extract readable OS hints from XML OS match data."""
    os_matches = []

    for os_match in host.findall("os/osmatch"):
        name = os_match.get("name")
        accuracy = os_match.get("accuracy")

        if not name:
            continue

        if accuracy:
            os_matches.append(f"{name} ({accuracy}% accuracy)")
        else:
            os_matches.append(name)

    if not os_matches:
        return None

    return "OS matches: " + "; ".join(os_matches)
