import unittest
from pathlib import Path


class DummyEngine:
    def __init__(self):
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


class TestDataExfiltrationTemporalCorrelation(unittest.TestCase):

    def setUp(self):
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))

    def test_temporal_correlation_detects_chain_within_window(self):
        from skills.data_exfiltration_audit.exfiltration_scanner import DataExfiltrationAudit

        skill = DataExfiltrationAudit(DummyEngine())

        transfer_tools = [
            {
                "product": "rclone",
                "installed_name": "rclone",
                "observed_at": "2026-06-08T09:55:00",
            }
        ]
        connections = [
            {
                "remote_ip": "185.199.110.153",
                "remote_port": 22,
                "process": "rclone.exe",
                "pid": 4321,
                "observed_at": "2026-06-08T10:02:00",
            }
        ]
        large_files = [
            {
                "path": "C:\\Users\\usuario\\Downloads\\dump.zip",
                "name": "dump.zip",
                "size_mb": 120.4,
                "observed_at": "2026-06-08T10:06:00",
            }
        ]
        cli_tools = [
            {
                "tool": "rclone",
                "path": "C:\\rclone",
                "has_config": True,
                "observed_at": "2026-06-08T10:08:00",
            }
        ]

        result = skill._build_temporal_correlation(
            transfer_tools=transfer_tools,
            connections=connections,
            large_files=large_files,
            cli_tools=cli_tools,
            dlp_indicators=[],
            window_minutes=15,
        )

        self.assertTrue(result["correlated"])
        self.assertEqual(
            result["sequence"],
            ["transfer_tool", "suspicious_connection", "large_file", "cloud_cli"],
        )
        self.assertEqual(result["span_minutes"], 13)
        self.assertIn("rclone.exe", result["ordered_events"][1]["label"])
        self.assertIn("185.199.110.153", result["ordered_events"][1]["label"])

    def test_temporal_correlation_rejects_spread_out_events(self):
        from skills.data_exfiltration_audit.exfiltration_scanner import DataExfiltrationAudit

        skill = DataExfiltrationAudit(DummyEngine())

        transfer_tools = [
            {
                "product": "rclone",
                "installed_name": "rclone",
                "observed_at": "2026-06-08T08:00:00",
            }
        ]
        connections = [
            {
                "remote_ip": "185.199.110.153",
                "remote_port": 22,
                "process": "rclone.exe",
                "pid": 4321,
                "observed_at": "2026-06-08T10:30:00",
            }
        ]
        large_files = [
            {
                "path": "C:\\Users\\usuario\\Downloads\\dump.zip",
                "name": "dump.zip",
                "size_mb": 120.4,
                "observed_at": "2026-06-08T13:10:00",
            }
        ]
        cli_tools = [
            {
                "tool": "rclone",
                "path": "C:\\rclone",
                "has_config": True,
                "observed_at": "2026-06-08T15:00:00",
            }
        ]

        result = skill._build_temporal_correlation(
            transfer_tools=transfer_tools,
            connections=connections,
            large_files=large_files,
            cli_tools=cli_tools,
            dlp_indicators=[],
            window_minutes=60,
        )

        self.assertFalse(result["correlated"])
        self.assertEqual(result["span_minutes"], 420)
        self.assertEqual(
            result["sequence"],
            ["transfer_tool", "suspicious_connection", "large_file", "cloud_cli"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
