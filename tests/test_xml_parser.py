"""Tests for the Nmap XML parser."""

from pathlib import Path
import unittest

from nextenum.parsers.xml_parser import parse_xml_nmap_file


SAMPLE_SCAN_PATH = Path("examples/sample_scan.xml")


class TestXmlNmapParser(unittest.TestCase):
    """Tests for parsing Nmap XML output."""

    def setUp(self) -> None:
        """Parse the sample XML scan once before each test."""
        self.scan = parse_xml_nmap_file(SAMPLE_SCAN_PATH)

    def test_extracts_target(self) -> None:
        """It should extract the target IP from the XML address field."""
        self.assertEqual(self.scan.target, "10.10.10.5")

    def test_extracts_open_services(self) -> None:
        """It should extract open services from the XML scan."""
        ports = [service.port for service in self.scan.services]

        self.assertIn(21, ports)
        self.assertIn(22, ports)
        self.assertIn(80, ports)
        self.assertIn(445, ports)
        self.assertIn(3306, ports)
        self.assertIn(3389, ports)

    def test_normalizes_common_service_names(self) -> None:
        """It should normalize XML service names like the normal text parser."""
        services_by_port = {
            service.port: service for service in self.scan.services
        }

        self.assertEqual(services_by_port[445].raw_service, "netbios-ssn")
        self.assertEqual(services_by_port[445].service, "smb")

        self.assertEqual(services_by_port[53].raw_service, "domain")
        self.assertEqual(services_by_port[53].service, "dns")

        self.assertEqual(services_by_port[3389].raw_service, "ms-wbt-server")
        self.assertEqual(services_by_port[3389].service, "rdp")

    def test_extracts_product_version_and_extra_info(self) -> None:
        """It should extract product, version, and extra info from XML attributes."""
        services_by_port = {
            service.port: service for service in self.scan.services
        }

        http = services_by_port[80]
        self.assertEqual(http.product, "Apache httpd")
        self.assertEqual(http.version, "2.4.29")
        self.assertEqual(http.extra_info, "((Ubuntu))")

        ftp = services_by_port[21]
        self.assertEqual(ftp.product, "vsftpd")
        self.assertEqual(ftp.version, "2.3.4")

    def test_parses_script_output(self) -> None:
        """It should attach XML script output to the correct service."""
        services_by_port = {
            service.port: service for service in self.scan.services
        }

        http = services_by_port[80]
        http_script_names = [script.name for script in http.scripts]

        self.assertIn("http-title", http_script_names)
        self.assertIn("http-server-header", http_script_names)
        self.assertIn("http-robots.txt", http_script_names)

        robots_script = next(
            script for script in http.scripts if script.name == "http-robots.txt"
        )
        self.assertIn("/admin /backup", robots_script.output)

        smb = services_by_port[445]
        smb_script_names = [script.name for script in smb.scripts]

        self.assertIn("smb-os-discovery", smb_script_names)
        self.assertIn("smb2-security-mode", smb_script_names)

    def test_extracts_os_hints(self) -> None:
        """It should extract OS hints from XML osmatch elements."""
        self.assertIsNotNone(self.scan.os_hints)
        self.assertIn("Linux 4.X", self.scan.os_hints)


if __name__ == "__main__":
    unittest.main()
