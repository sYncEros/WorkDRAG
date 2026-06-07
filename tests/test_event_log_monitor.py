import unittest
from unittest.mock import patch


class DummyEngine:
    def __init__(self):
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


class TestEventLogInfrastructure(unittest.TestCase):

    def setUp(self):
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))

    def test_query_log_timeout_returns_inaccessible_result(self):
        from skills.event_logs import log_query

        with patch.object(log_query.subprocess, "run", side_effect=log_query.subprocess.TimeoutExpired(cmd="powershell", timeout=1)):
            res = log_query.query_log(
                "Security",
                [4624],
                "security",
                scan_scope="recent",
                hours_back=24,
                max_events=100,
                timeout=1,
            )

        self.assertFalse(res.accessible)
        self.assertIn("timeout", res.error.lower())


class TestEventLogMonitor(unittest.TestCase):

    def setUp(self):
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))

    def test_report_includes_usb_finding_when_events_exist(self):
        from skills.event_logs.event_log_monitor import EventLogMonitor

        engine = DummyEngine()
        skill = EventLogMonitor(engine)

        skill.wef_active = False
        skill.ps_transcription = False
        skill.ps_scriptblock = False
        skill.usb_events = {
            "total": 3,
            "by_log": {
                "Microsoft-Windows-DriverFrameworks-UserMode/Operational": {
                    "matched": 3,
                    "by_id": {2003: 2, 2100: 1},
                    "source": "usb_dfu",
                }
            },
            "samples": [{"Id": 2003}, {"Id": 2100}],
        }

        skill._report()

        categories = [f.category for f in engine.findings]
        self.assertIn("usb_event_log_activity", categories)


if __name__ == "__main__":
    unittest.main(verbosity=2)
