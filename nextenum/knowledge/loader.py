"""Load service enumeration knowledge for NextEnum."""

from __future__ import annotations

import json
from importlib import resources
from json import JSONDecodeError

from nextenum.parsers.normal_parser import ParsedService


class KnowledgeBaseError(Exception):
    """Raised when a knowledge base file exists but cannot be loaded safely."""


def load_service_knowledge(service_name: str) -> dict[str, object] | None:
    """Load one service knowledge file by normalized service name.

    Returns None when the service does not have a knowledge file yet.
    Raises KnowledgeBaseError when the file exists but contains invalid data.
    """
    safe_service_name = _normalize_service_name(service_name)

    if not safe_service_name:
        return None

    knowledge_path = (
        resources.files("nextenum.knowledge")
        .joinpath("services")
        .joinpath(f"{safe_service_name}.json")
    )

    if not knowledge_path.is_file():
        return None

    try:
        with knowledge_path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except JSONDecodeError as error:
        raise KnowledgeBaseError(
            f"Knowledge file for {safe_service_name!r} contains invalid JSON."
        ) from error
    except OSError as error:
        raise KnowledgeBaseError(
            f"Could not read knowledge file for {safe_service_name!r}."
        ) from error

    if not isinstance(data, dict):
        raise KnowledgeBaseError(
            f"Knowledge file for {safe_service_name!r} must contain a JSON object."
        )

    return data


def get_knowledge_for_service(service: ParsedService) -> dict[str, object] | None:
    """Return knowledge for a parsed service."""
    return load_service_knowledge(service.service)


def list_available_service_guides() -> list[str]:
    """Return normalized service names that currently have JSON guide files."""
    services_path = resources.files("nextenum.knowledge").joinpath("services")

    if not services_path.is_dir():
        return []

    guides = []

    for item in services_path.iterdir():
        if item.is_file() and item.name.endswith(".json"):
            guides.append(item.name.removesuffix(".json"))

    return sorted(guides)


def _normalize_service_name(service_name: str) -> str:
    """Return a safe service name for knowledge file lookup."""
    return service_name.strip().lower().replace("/", "-")
