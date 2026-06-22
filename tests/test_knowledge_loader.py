"""Tests for the service knowledge base loader."""

import unittest

from nextenum.knowledge.loader import (
    get_knowledge_for_service,
    list_available_service_guides,
    load_service_knowledge,
)
from nextenum.parsers.normal_parser import ParsedService


EXPECTED_GUIDES = {
    "http": "HTTP / Web Server",
    "ftp": "FTP / File Transfer Service",
    "ssh": "SSH / Secure Shell",
    "smb": "SMB / Windows File Sharing",
    "dns": "DNS / Domain Name Service",
}


class TestKnowledgeLoader(unittest.TestCase):
    """Tests for loading service knowledge JSON files."""

    def test_loads_expected_service_guides(self) -> None:
        """It should load every expected service guide."""
        for service_name, display_name in EXPECTED_GUIDES.items():
            with self.subTest(service_name=service_name):
                knowledge = load_service_knowledge(service_name)

                self.assertIsNotNone(knowledge)
                self.assertEqual(knowledge["service"], service_name)
                self.assertEqual(knowledge["display_name"], display_name)
                self.assertIn("enumeration_steps", knowledge)
                self.assertIn("finding_next_steps", knowledge)
                self.assertIn("beginner_notes", knowledge)
                self.assertIn("useful_nmap_scripts", knowledge)
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
        test_cases = [
            ParsedService(
                port=80,
                protocol="tcp",
                state="open",
                raw_service="http",
                service="http",
                product="Apache httpd",
                version="2.4.29",
            ),
            ParsedService(
                port=21,
                protocol="tcp",
                state="open",
                raw_service="ftp",
                service="ftp",
                product="vsftpd",
                version="2.3.4",
            ),
            ParsedService(
                port=22,
                protocol="tcp",
                state="open",
                raw_service="ssh",
                service="ssh",
                product="OpenSSH",
                version="7.6p1",
            ),
            ParsedService(
                port=445,
                protocol="tcp",
                state="open",
                raw_service="netbios-ssn",
                service="smb",
                product="Samba smbd",
                version="4.7.6-Ubuntu",
            ),
            ParsedService(
                port=53,
                protocol="tcp",
                state="open",
                raw_service="domain",
                service="dns",
                product="ISC BIND",
                version="9.11.3",
            ),
        ]

        for service in test_cases:
            with self.subTest(service_name=service.service):
                knowledge = get_knowledge_for_service(service)

                self.assertIsNotNone(knowledge)
                self.assertEqual(knowledge["service"], service.service)

    def test_lists_available_service_guides(self) -> None:
        """It should list currently available service guides."""
        guides = list_available_service_guides()

        for service_name in EXPECTED_GUIDES:
            with self.subTest(service_name=service_name):
                self.assertIn(service_name, guides)


if __name__ == "__main__":
    unittest.main()
