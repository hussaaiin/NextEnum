"""Build service enumeration recommendations from parsed Nmap scans."""

from __future__ import annotations

from dataclasses import dataclass, field

from nextenum.knowledge.loader import KnowledgeBaseError, get_knowledge_for_service
from nextenum.parsers.normal_parser import ParsedNmapScan, ParsedService


@dataclass(slots=True)
class ServiceRecommendation:
    """Represents one recommended service to enumerate."""

    service: ParsedService
    priority: str
    score: int
    reasons: list[str] = field(default_factory=list)

    @property
    def guide_filter(self) -> str:
        """Return the preferred value to pass to --guide for this service."""
        return str(self.service.port)


PRIORITY_SCORES = {
    "low": 20,
    "medium": 45,
    "high": 65,
}

DEFAULT_SERVICE_PRIORITIES = {
    "http": "high",
    "https": "high",
    "ftp": "medium",
    "ssh": "medium",
    "smb": "high",
    "dns": "medium",
    "smtp": "medium",
    "nfs": "high",
    "mysql": "high",
    "postgresql": "high",
    "rdp": "medium",
}

SCRIPT_SCORE_RULES = {
    "ftp-anon": (
        45,
        "Anonymous FTP login appears to be allowed, so exposed files should be checked early.",
    ),
    "http-robots.txt": (
        15,
        "robots.txt results may reveal hidden or interesting web paths.",
    ),
    "http-title": (
        5,
        "HTTP title output gives quick context about the hosted web application.",
    ),
    "http-server-header": (
        5,
        "HTTP server header output may reveal useful version or platform details.",
    ),
    "smb-os-discovery": (
        15,
        "SMB OS discovery output may reveal host, domain, and operating system details.",
    ),
    "smb2-security-mode": (
        15,
        "SMB security mode output may reveal signing settings worth noting.",
    ),
    "nfs-showmount": (
        35,
        "NFS export information was found, so shared directories should be reviewed early.",
    ),
    "smtp-commands": (
        10,
        "SMTP command output shows supported mail commands and authentication behavior.",
    ),
    "dns-nsid": (
        10,
        "DNS script output may reveal server version or name server details.",
    ),
    "mysql-info": (
        15,
        "MySQL script output may reveal database version and protocol details.",
    ),
    "pgsql-brute": (
        10,
        "PostgreSQL script output is available and may include authentication clues.",
    ),
    "rdp-enum-encryption": (
        10,
        "RDP encryption output describes the remote desktop security configuration.",
    ),
}

SERVICE_REASON_HINTS = {
    "http": "Web services often expose pages, directories, login forms, APIs, and version leaks.",
    "https": "Web services often expose pages, directories, login forms, APIs, and version leaks.",
    "ftp": "FTP can expose readable files, anonymous access, writable folders, or credentials.",
    "smb": "SMB can expose shares, users, host details, and readable or writable files.",
    "nfs": "NFS can expose mounted directories that may contain sensitive files.",
    "mysql": "Database services can expose application data if weak credentials or misconfigurations exist.",
    "postgresql": "Database services can expose application data if weak credentials or misconfigurations exist.",
    "ssh": "SSH is useful to revisit when valid usernames, passwords, or private keys are discovered.",
    "dns": "DNS can reveal hostnames, zones, subdomains, and infrastructure naming patterns.",
    "smtp": "SMTP can reveal supported commands, users, mail behavior, and host naming details.",
    "rdp": "RDP can become important when valid Windows credentials are discovered.",
}


def recommend_services(scan: ParsedNmapScan) -> list[ServiceRecommendation]:
    """Return services sorted by recommended enumeration priority."""
    recommendations = [recommend_service(service) for service in scan.services]

    return sorted(
        recommendations,
        key=lambda recommendation: (
            recommendation.score,
            -recommendation.service.port,
        ),
        reverse=True,
    )


def recommend_service(service: ParsedService) -> ServiceRecommendation:
    """Return a recommendation for one parsed service."""
    priority = _base_priority_for_service(service)
    score = PRIORITY_SCORES.get(priority, PRIORITY_SCORES["low"])
    reasons: list[str] = []

    service_hint = SERVICE_REASON_HINTS.get(service.service)
    if service_hint:
        reasons.append(service_hint)

    if service.display_info:
        score += 5
        reasons.append(
            "Version or banner information is available and should be reviewed."
        )

    if service.scripts:
        score += 5
        reasons.append("Nmap script output is available for this service.")

    script_score, script_reasons = _score_scripts(service)
    score += script_score
    reasons.extend(script_reasons)

    if service.service in {"mysql", "postgresql"}:
        score += 10
        reasons.append(
            "The service is a database exposed over the network, so access control should be checked."
        )

    if service.service == "ssh":
        reasons.append(
            "SSH is usually not first unless you already have credentials, but it is important to track."
        )

    score = min(score, 100)
    priority = _priority_from_score(score)

    return ServiceRecommendation(
        service=service,
        priority=priority,
        score=score,
        reasons=_deduplicate(reasons),
    )


def _base_priority_for_service(service: ParsedService) -> str:
    """Return the base priority from knowledge data or service defaults."""
    try:
        knowledge = get_knowledge_for_service(service)
    except KnowledgeBaseError:
        knowledge = None

    if isinstance(knowledge, dict):
        priority = knowledge.get("base_priority")
        if isinstance(priority, str) and priority.lower() in PRIORITY_SCORES:
            return priority.lower()

    return DEFAULT_SERVICE_PRIORITIES.get(service.service, "low")


def _score_scripts(service: ParsedService) -> tuple[int, list[str]]:
    """Return score bonus and reasons based on NSE script names/output."""
    total_score = 0
    reasons: list[str] = []

    for script in service.scripts:
        script_name = script.name.lower()
        rule = SCRIPT_SCORE_RULES.get(script_name)

        if rule:
            score_bonus, reason = rule
            total_score += score_bonus
            reasons.append(reason)

        output_text = " ".join(script.output).lower()

        if script_name == "smb2-security-mode" and "not required" in output_text:
            total_score += 10
            reasons.append(
                "SMB signing appears to be not required, which is useful to note during lab enumeration."
            )

        if script_name == "http-robots.txt" and output_text:
            total_score += 5
            reasons.append(
                "The robots.txt output includes paths that should be checked manually."
            )

    return total_score, reasons


def _priority_from_score(score: int) -> str:
    """Convert a numeric score into a readable priority label."""
    if score >= 75:
        return "high"

    if score >= 45:
        return "medium"

    return "low"


def _deduplicate(items: list[str]) -> list[str]:
    """Return items in order without duplicates."""
    seen = set()
    unique_items: list[str] = []

    for item in items:
        if item in seen:
            continue

        seen.add(item)
        unique_items.append(item)

    return unique_items
