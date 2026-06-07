import json
import tempfile
import unittest
from pathlib import Path


class DummyEngine:
    def __init__(self):
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


class TestRDPLogExporterAnalysis(unittest.TestCase):

    def setUp(self):
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))

    def test_build_account_analysis_with_historical_crosses(self):
        from skills.rdp_log_exporter.rdp_log_exporter import RDPLogExporter

        exporter = RDPLogExporter(DummyEngine())
        exporter.admin_accounts = {"local-admin"}

        exporter.rdp_events = [
            {
                "timestamp": "2026-06-06T09:00:00",
                "user": "LOCAL-ADMIN",
                "ip": "10.0.0.5",
                "after_hours": False,
                "external_ip": False,
            },
            {
                "timestamp": "2026-06-06T21:00:00",
                "user": "EMEAL-IT",
                "ip": "88.20.10.5",
                "after_hours": True,
                "external_ip": True,
            },
        ]

        exporter.historical_context = {
            "files_analyzed": 1,
            "snapshots": [{"file": "rdp_log_1.json", "generated_at": "2026-06-05T10:00:00", "total_events": 1}],
            "events": [
                {
                    "timestamp": "2026-06-05T10:00:00",
                    "user": "LOCAL-ADMIN",
                    "ip": "10.0.0.5",
                    "after_hours": False,
                    "external_ip": False,
                }
            ],
        }

        exporter._build_account_analysis()

        by_account = exporter.account_analysis["by_account"]
        self.assertGreaterEqual(len(by_account), 2)

        crosses = exporter.account_analysis["crosses"]
        self.assertIn("LOCAL-ADMIN", crosses["users_seen_current_and_historical"])
        self.assertIn("10.0.0.5", crosses["ips_seen_current_and_historical"])

        admin_accounts = exporter.account_analysis["admin_accounts"]
        admin_names = [a["account"] for a in admin_accounts]
        self.assertIn("LOCAL-ADMIN", admin_names)

    def test_load_historical_evidence_reads_previous_exports(self):
        from skills.rdp_log_exporter.rdp_log_exporter import RDPLogExporter

        exporter = RDPLogExporter(DummyEngine())

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            exporter.evidence_dir = tmp_dir

            payload = {
                "generated_at": "2026-06-01T10:00:00",
                "total_events": 1,
                "events": [
                    {
                        "timestamp": "2026-06-01T09:00:00",
                        "user": "ADMIN01",
                        "ip": "192.168.1.10",
                        "after_hours": False,
                        "external_ip": False,
                    }
                ],
            }
            (tmp_dir / "rdp_log_20260601_100000.json").write_text(
                json.dumps(payload), encoding="utf-8"
            )

            exporter._load_historical_evidence()

            self.assertEqual(exporter.historical_context["files_analyzed"], 1)
            self.assertEqual(len(exporter.historical_context["events"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
