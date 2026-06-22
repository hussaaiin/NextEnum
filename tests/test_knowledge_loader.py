"""Tests for the service knowledge base loader."""

import unittest

from nextenum.knowledge.loader import (
    get_knowledge_for_service,
    list_available_service_guides,
    load_service_knowledge,
)
from nextenum.parsers.normal_parser import ParsedService


class TestKnowledgeLoader(unittest.TestCase):
    """Tests for loading service knowledge JSON files."""

    def test_loads_http_knowledge(self) -> None:
        """It should load the HTTP knowledge file."""
        knowledge = load_service_knowledge("http")

        self.assertIsNotNone(knowledge)
        self.assertEqual(knowledge["service"], "http")
        self.assertEqual(knowledge["display_name"], "HTTP / Web Server")
        self.assertIn("enumeration_steps", knowledge)
        self.assertIn("finding_next_steps", knowledge)
        self.assertNotIn(
            "eJPT",
            " ".join(knowledge.get("why_prioritize", [])),
        )

    def test_returns_none_for_missing_service(self) -> None:
        """It should return None when a service guide does not exist yet."""
        knowledge = load_service_knowledge("service-that-does-not-exist")

        self.assertIsNone(knowledge)

    def test_gets_knowledge_for_parsed_service(self) -> None:
        """It should load knowledge using a ParsedService object."""
        service = ParsedService(
            port=80,
            protocol="tcp",
            state="open",
            raw_service="http",
            service="http",
            product="Apache httpd",
            version="2.4.29",
        )

        knowledge = get_knowledge_for_service(service)

        self.assertIsNotNone(knowledge)
        self.assertEqual(knowledge["service"], "http")

    def test_lists_available_service_guides(self) -> None:
        """It should list currently available service guides."""
        guides = list_available_service_guides()

        self.assertIn("http", guides)


if __name__ == "__main__":
    unittest.main()
