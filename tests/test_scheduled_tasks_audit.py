"""Tests unitarios del skill scheduled_tasks_audit."""

import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))


class MockEngine:
    def __init__(self):
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


class TestScheduledTasksAudit(unittest.TestCase):

    def setUp(self):
        from skills.scheduled_tasks_audit.scheduled_tasks_scanner import ScheduledTasksAudit
        self.engine = MockEngine()
        self.audit = ScheduledTasksAudit(self.engine)

    def test_extract_action_details_detects_interpreter_patterns(self):
        task = {
            "Actions": [
                {
                    "Execute": r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "Arguments": "-NoP -W Hidden -EncodedCommand ZWNobyBoaQ==",
                    "WorkingDir": r"C:\\ProgramData",
                }
            ]
        }

        actions = self.audit._extract_action_details(task)
        self.assertEqual(len(actions), 1)
        self.assertTrue(actions[0]["is_interpreter"])
        self.assertEqual(actions[0]["interpreter"], "powershell.exe")
        self.assertIn("-encodedcommand", actions[0]["suspicious_patterns"])
        self.assertIn("-nop", actions[0]["suspicious_patterns"])
        self.assertIn("-w hidden", actions[0]["suspicious_patterns"])

    def test_extract_action_details_for_regular_executable(self):
        task = {
            "Actions": {
                "Execute": r"C:\\Program Files\\Vendor\\Agent\\agent.exe",
                "Arguments": "--run --mode=normal",
                "WorkingDir": r"C:\\Program Files\\Vendor\\Agent",
            }
        }

        actions = self.audit._extract_action_details(task)
        self.assertEqual(len(actions), 1)
        self.assertFalse(actions[0]["is_interpreter"])
        self.assertEqual(actions[0]["suspicious_patterns"], [])

    def test_analyze_interpreter_tasks_creates_finding(self):
        tasks = [
            {
                "TaskName": "VendorTelemetry",
                "TaskPath": r"\\Vendor\\",
                "Author": "Vendor",
                "Date": "2026-06-12T10:00:00",
                "RunAsUser": "SYSTEM",
                "RunLevel": "Highest",
                "LastRunTime": "2026-06-12T10:10:00",
                "LastResult": 0,
                "Actions": [
                    {
                        "Execute": r"C:\\Windows\\System32\\cmd.exe",
                        "Arguments": "/c powershell -EncodedCommand QUJD",
                        "WorkingDir": r"C:\\ProgramData",
                    }
                ],
            }
        ]

        self.audit._analyze_interpreter_tasks(tasks)

        self.assertEqual(len(self.engine.findings), 1)
        finding = self.engine.findings[0]
        self.assertEqual(finding.category, "scheduled_tasks_interpreters")
        self.assertEqual(finding.risk_level, "orange")
        self.assertIn("interpreter_tasks", finding.raw_data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
