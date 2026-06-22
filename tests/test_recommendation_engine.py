"""Tests for the recommendation engine."""

import unittest

from nextenum.parsers.normal_parser import (
    ParsedNmapScan,
    ParsedScriptOutput,
    ParsedService,
)
from nextenum.recommendations.engine import recommend_service, recommend_services


class TestRecommendationEngine(unittest.TestCase):
    """Tests for building service recommendations."""

    def test_recommends_services_in_score_order(self) -> None:
        """It should sort the most interesting services first."""
        scan = ParsedNmapScan(
            target="10.10.10.5",
            services=[
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
                    port=21,
                    protocol="tcp",
                    state="open",
                    raw_service="ftp",
                    service="ftp",
                    product="vsftpd",
                    version="2.3.4",
                    scripts=[
                        ParsedScriptOutput(
                            name="ftp-anon",
                            output=[
                                "Anonymous FTP login allowed (FTP code 230)",
                            ],
                        ),
                    ],
                ),
                ParsedService(
                    port=80,
                    protocol="tcp",
                    state="open",
                    raw_service="http",
                    service="http",
                    product="Apache httpd",
                    version="2.4.29",
                    scripts=[
                        ParsedScriptOutput(
                            name="http-robots.txt",
                            output=[
                                "2 disallowed entries",
                                "/admin /backup",
                            ],
                        ),
                    ],
                ),
            ],
        )

        recommendations = recommend_services(scan)

        self.assertEqual(recommendations[0].service.port, 21)
        self.assertEqual(recommendations[0].priority, "high")
        self.assertGreaterEqual(
            recommendations[0].score,
            recommendations[-1].score,
        )

    def test_ftp_anonymous_script_increases_priority(self) -> None:
        """It should prioritize FTP when anonymous access appears allowed."""
        service = ParsedService(
            port=21,
            protocol="tcp",
            state="open",
            raw_service="ftp",
            service="ftp",
            product="vsftpd",
            version="2.3.4",
            scripts=[
                ParsedScriptOutput(
                    name="ftp-anon",
                    output=["Anonymous FTP login allowed"],
                )
            ],
        )

        recommendation = recommend_service(service)

        self.assertEqual(recommendation.priority, "high")
        self.assertTrue(
            any("Anonymous FTP" in reason for reason in recommendation.reasons)
        )

    def test_http_robots_script_adds_reason(self) -> None:
        """It should explain when robots.txt output is found."""
        service = ParsedService(
            port=80,
            protocol="tcp",
            state="open",
            raw_service="http",
            service="http",
            product="Apache httpd",
            version="2.4.29",
            scripts=[
                ParsedScriptOutput(
                    name="http-robots.txt",
                    output=["/admin /backup"],
                )
            ],
        )

        recommendation = recommend_service(service)

        self.assertEqual(recommendation.priority, "high")
        self.assertTrue(
            any("robots.txt" in reason for reason in recommendation.reasons)
        )

    def test_nfs_showmount_is_high_priority(self) -> None:
        """It should prioritize NFS when export information is available."""
        service = ParsedService(
            port=2049,
            protocol="tcp",
            state="open",
            raw_service="nfs_acl",
            service="nfs",
            product="",
            version="3",
            scripts=[
                ParsedScriptOutput(
                    name="nfs-showmount",
                    output=["/home *(everyone)"],
                )
            ],
        )

        recommendation = recommend_service(service)

        self.assertEqual(recommendation.priority, "high")
        self.assertTrue(
            any("NFS export" in reason for reason in recommendation.reasons)
        )

    def test_unknown_service_is_low_priority(self) -> None:
        """It should keep unknown services low when there are no useful clues."""
        service = ParsedService(
            port=9999,
            protocol="tcp",
            state="open",
            raw_service="unknown",
            service="unknown",
        )

        recommendation = recommend_service(service)

        self.assertEqual(recommendation.priority, "low")
        self.assertEqual(recommendation.score, 20)
        self.assertEqual(recommendation.reasons, [])


if __name__ == "__main__":
    unittest.main()
