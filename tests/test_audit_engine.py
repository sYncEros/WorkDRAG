# tests/test_audit_engine.py
"""Tests unitarios para el motor de auditoría."""

import json
import datetime
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock


class MockEngine:
    """Motor de auditoría simulado para tests de skills."""
    def __init__(self):
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)


# ── Tests del AuditFinding ─────────────────────────────────────────────────────

class TestAuditFinding(unittest.TestCase):

    def setUp(self):
        # Necesita importar desde el directorio raíz
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))

    def test_finding_has_timestamp(self):
        from core.audit_engine import AuditFinding
        f = AuditFinding(
            skill="test", category="test_cat", title="Test",
            description="Descripción", risk_level="green",
            technical_risk="Bajo", legal_risk="Bajo",
            what_it_is="Es algo", what_it_is_not="No es otra cosa",
            raw_data={}
        )
        self.assertIsNotNone(f.timestamp)
        # Verificar que el timestamp es parseable como ISO
        dt = datetime.datetime.fromisoformat(f.timestamp)
        self.assertIsNotNone(dt)

    def test_finding_risk_levels(self):
        from core.audit_engine import AuditFinding
        for level in ["green", "yellow", "orange", "red"]:
            f = AuditFinding(
                skill="test", category="cat", title="T",
                description="D", risk_level=level,
                technical_risk="T", legal_risk="L",
                what_it_is="W", what_it_is_not="WN",
                raw_data={"key": "value"}
            )
            self.assertEqual(f.risk_level, level)

    def test_raw_data_is_dict(self):
        from core.audit_engine import AuditFinding
        f = AuditFinding(
            skill="test", category="cat", title="T",
            description="D", risk_level="yellow",
            technical_risk="T", legal_risk="L",
            what_it_is="W", what_it_is_not="WN",
            raw_data={"count": 42, "items": ["a", "b"]}
        )
        self.assertIsInstance(f.raw_data, dict)
        self.assertEqual(f.raw_data["count"], 42)


# ── Tests del AuditEngine ──────────────────────────────────────────────────────

class TestAuditEngine(unittest.TestCase):

    def setUp(self):
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))

    def _make_engine(self, tmp_dir):
        """Crea un engine con DB en directorio temporal."""
        from core.audit_engine import AuditEngine
        with patch('core.audit_engine.DB_PATH', Path(tmp_dir) / 'test.db'), \
             patch('core.audit_engine.EXPORTS_PATH', Path(tmp_dir)):
            engine = AuditEngine()
        return engine, tmp_dir

    def test_engine_init(self):
        with tempfile.TemporaryDirectory() as tmp:
            from core.audit_engine import AuditEngine, AuditFinding
            with patch('core.audit_engine.DB_PATH', Path(tmp) / 'test.db'), \
                 patch('core.audit_engine.EXPORTS_PATH', Path(tmp)):
                engine = AuditEngine()
                self.assertIsNotNone(engine.db)
                self.assertEqual(engine.findings, [])

    def test_add_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            from core.audit_engine import AuditEngine, AuditFinding
            with patch('core.audit_engine.DB_PATH', Path(tmp) / 'test.db'), \
                 patch('core.audit_engine.EXPORTS_PATH', Path(tmp)):
                engine = AuditEngine()
                finding = AuditFinding(
                    skill="test_skill", category="test_cat",
                    title="Test Finding", description="Descripción de prueba",
                    risk_level="yellow", technical_risk="Riesgo técnico",
                    legal_risk="Riesgo legal", what_it_is="Qué es",
                    what_it_is_not="Qué no es", raw_data={"test": True}
                )
                engine.add_finding(finding)
                self.assertEqual(len(engine.findings), 1)
                self.assertEqual(engine.findings[0].title, "Test Finding")

    def test_compute_max_risk(self):
        with tempfile.TemporaryDirectory() as tmp:
            from core.audit_engine import AuditEngine, AuditFinding
            with patch('core.audit_engine.DB_PATH', Path(tmp) / 'test.db'), \
                 patch('core.audit_engine.EXPORTS_PATH', Path(tmp)):
                engine = AuditEngine()

                # Sin hallazgos: verde
                self.assertEqual(engine._compute_max_risk(), "green")

                # Añadir hallazgos de diferentes niveles
                for risk in ["green", "yellow", "orange"]:
                    engine.add_finding(AuditFinding(
                        skill="s", category="c", title=f"t_{risk}",
                        description="d", risk_level=risk,
                        technical_risk="t", legal_risk="l",
                        what_it_is="w", what_it_is_not="wn",
                        raw_data={}
                    ))

                self.assertEqual(engine._compute_max_risk(), "orange")

    def test_export_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            from core.audit_engine import AuditEngine, AuditFinding
            with patch('core.audit_engine.DB_PATH', Path(tmp) / 'test.db'), \
                 patch('core.audit_engine.EXPORTS_PATH', Path(tmp)):
                engine = AuditEngine()
                engine.add_finding(AuditFinding(
                    skill="test", category="cat", title="T",
                    description="D", risk_level="green",
                    technical_risk="T", legal_risk="L",
                    what_it_is="W", what_it_is_not="WN",
                    raw_data={"x": 1}
                ))
                out = engine.export_json(filename="test_export")
                self.assertTrue(Path(out).exists())
                data = json.loads(Path(out).read_text(encoding="utf-8"))
                self.assertIn("integrity_hash", data)
                self.assertEqual(data["total_findings"], 1)
                self.assertEqual(len(data["findings"]), 1)

    def test_validate_schema_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            from core.audit_engine import AuditEngine, AuditFinding
            with patch('core.audit_engine.DB_PATH', Path(tmp) / 'test.db'), \
                 patch('core.audit_engine.EXPORTS_PATH', Path(tmp)):
                engine = AuditEngine()
                engine.add_finding(AuditFinding(
                    skill="test", category="cat", title="T",
                    description="D", risk_level="green",
                    technical_risk="T", legal_risk="L",
                    what_it_is="W", what_it_is_not="WN",
                    raw_data={"x": 1}
                ))
                out = engine.export_json(filename="test_valid")
                report = json.loads(Path(out).read_text(encoding="utf-8"))
                errors = engine.validate_schema(report)
                self.assertEqual(errors, [], f"Errores de esquema: {errors}")

    def test_validate_schema_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            from core.audit_engine import AuditEngine
            with patch('core.audit_engine.DB_PATH', Path(tmp) / 'test.db'), \
                 patch('core.audit_engine.EXPORTS_PATH', Path(tmp)):
                engine = AuditEngine()
                bad_report = {
                    "generated_at": "2025-01-01",
                    "total_findings": 1,
                    "max_risk": "INVALID_LEVEL",
                    "findings": [],
                    "integrity_hash": "abc",
                }
                errors = engine.validate_schema(bad_report)
                self.assertGreater(len(errors), 0)


# ── Tests del motor legal ──────────────────────────────────────────────────────

class TestLegalEngine(unittest.TestCase):

    def setUp(self):
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))

    def _make_finding(self, category, risk="orange"):
        from core.audit_engine import AuditFinding
        return AuditFinding(
            skill="test", category=category,
            title=f"Test {category}", description="D",
            risk_level=risk, technical_risk="T", legal_risk="L",
            what_it_is="W", what_it_is_not="WN", raw_data={}
        )

    def test_evaluate_empty(self):
        from skills.compliance_engine.legal_engine import LegalEngine
        engine = LegalEngine([])
        issues = engine.evaluate()
        self.assertEqual(issues, [])

    def test_evaluate_known_category(self):
        from skills.compliance_engine.legal_engine import LegalEngine
        findings = [self._make_finding("productivity_monitoring")]
        engine = LegalEngine(findings)
        issues = engine.evaluate()
        self.assertGreater(len(issues), 0)
        self.assertEqual(issues[0]["category"], "productivity_monitoring")
        self.assertIn("references", issues[0])
        self.assertIn("recommendations", issues[0])

    def test_evaluate_unknown_category(self):
        from skills.compliance_engine.legal_engine import LegalEngine
        findings = [self._make_finding("unknown_random_category")]
        engine = LegalEngine(findings)
        issues = engine.evaluate()
        self.assertEqual(issues, [])

    def test_summary_text_with_issues(self):
        from skills.compliance_engine.legal_engine import LegalEngine
        findings = [
            self._make_finding("productivity_monitoring", "orange"),
            self._make_finding("input_monitoring", "red"),
        ]
        engine = LegalEngine(findings)
        engine.evaluate()
        text = engine.summary_text()
        self.assertIn("EVALUACIÓN LEGAL", text)
        self.assertIn("VERY_HIGH", text.upper())

    def test_evaluate_urgent_mode_filters(self):
        from skills.compliance_engine.legal_engine import LegalEngine
        findings = [
            self._make_finding("productivity_monitoring"),  # high
            self._make_finding("browser_inspection"),       # medium
            self._make_finding("edr_xdr"),                  # low
        ]
        engine = LegalEngine(findings)
        issues = engine.evaluate(recommendation_mode="urgente")

        self.assertGreater(len(issues), 0)
        self.assertTrue(
            all(i["legal_risk"] in {"very_high", "high", "medium-high"} for i in issues)
        )

    def test_evaluate_custom_mode_by_category(self):
        from skills.compliance_engine.legal_engine import LegalEngine
        findings = [
            self._make_finding("productivity_monitoring"),
            self._make_finding("edr_xdr"),
        ]
        engine = LegalEngine(findings)
        issues = engine.evaluate(
            recommendation_mode="personalizado",
            custom_categories=["edr_xdr"],
        )

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["category"], "edr_xdr")

    def test_to_dict_structure(self):
        from skills.compliance_engine.legal_engine import LegalEngine
        findings = [self._make_finding("ssl_inspection")]
        engine = LegalEngine(findings)
        engine.evaluate()
        d = engine.to_dict()
        self.assertIn("total_issues", d)
        self.assertIn("issues", d)
        self.assertIn("framework_references", d)
        self.assertIsInstance(d["issues"], list)


# ── Tests de skills individuales (smoke tests) ────────────────────────────────

class TestSkillsSmoke(unittest.TestCase):
    """
    Smoke tests: verifican que cada skill se instancia y llama a run()
    sin excepciones no controladas, usando un engine mock.
    """

    def setUp(self):
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))

    def _run_skill(self, skill_class):
        engine = MockEngine()
        skill = skill_class(engine)
        try:
            skill.run()
        except Exception as e:
            self.fail(f"{skill_class.__name__}.run() lanzó excepción no controlada: {e}")
        return engine.findings

    def test_persistence_audit_smoke(self):
        from skills.persistence_audit.persistence_scanner import PersistenceAudit
        self._run_skill(PersistenceAudit)

    def test_scheduled_tasks_smoke(self):
        from skills.scheduled_tasks_audit.scheduled_tasks_scanner import ScheduledTasksAudit
        self._run_skill(ScheduledTasksAudit)

    def test_usb_audit_smoke(self):
        from skills.usb_audit.usb_scanner import USBAudit
        self._run_skill(USBAudit)

    def test_email_audit_smoke(self):
        from skills.email_audit.email_scanner import EmailAudit
        self._run_skill(EmailAudit)

    def test_third_party_apps_smoke(self):
        from skills.third_party_apps_audit.third_party_scanner import ThirdPartyAppsAudit
        self._run_skill(ThirdPartyAppsAudit)

    def test_user_behavior_smoke(self):
        from skills.user_behavior_audit.behavior_scanner import UserBehaviorAudit
        self._run_skill(UserBehaviorAudit)

    def test_data_exfiltration_smoke(self):
        from skills.data_exfiltration_audit.exfiltration_scanner import DataExfiltrationAudit
        self._run_skill(DataExfiltrationAudit)

    def test_incident_response_smoke(self):
        """El playbook necesita findings en el engine para generar contenido."""
        import tempfile
        from core.audit_engine import AuditEngine, AuditFinding
        with tempfile.TemporaryDirectory() as tmp:
            with patch('core.audit_engine.DB_PATH', Path(tmp) / 'test.db'), \
                 patch('core.audit_engine.EXPORTS_PATH', Path(tmp)):
                engine = AuditEngine()
                engine.add_finding(AuditFinding(
                    skill="test", category="productivity_monitoring",
                    title="Test finding", description="D",
                    risk_level="orange", technical_risk="T",
                    legal_risk="L", what_it_is="W",
                    what_it_is_not="WN", raw_data={}
                ))
                from skills.incident_response.playbook_generator import IncidentResponsePlaybook
                playbook = IncidentResponsePlaybook(engine)
                try:
                    playbook.run()
                except Exception as e:
                    self.fail(f"IncidentResponsePlaybook.run() lanzó excepción: {e}")
                # Debe haber generado al menos 1 hallazgo adicional
                new_findings = [
                    f for f in engine.findings
                    if f.skill == "incident_response"
                ]
                self.assertGreater(len(new_findings), 0)

    def test_event_viewer_smoke(self):
        from skills.event_logs.event_viewer_scanner import (
            EventQueryResult,
            EventViewerAudit,
        )

        def fake_query(self, log_name, event_ids, source_label):
            return EventQueryResult(
                log_name=log_name,
                total=3,
                by_id={event_ids[0]: 3} if event_ids else {},
                samples=[{"Id": event_ids[0] if event_ids else 0}],
                source_label=source_label,
                accessible=True,
                error="",
            )

        with patch.object(EventViewerAudit, "_query_log", new=fake_query), \
             patch.object(EventViewerAudit, "_export_full_logs_report", new=lambda self: None):
            self._run_skill(EventViewerAudit)


# ── Tests de exportadores ──────────────────────────────────────────────────────

class TestExporters(unittest.TestCase):

    def setUp(self):
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))

    def test_json_export_structure(self):
        """El JSON exportado tiene la estructura correcta."""
        with tempfile.TemporaryDirectory() as tmp:
            from core.audit_engine import AuditEngine, AuditFinding
            with patch('core.audit_engine.DB_PATH', Path(tmp) / 'test.db'), \
                 patch('core.audit_engine.EXPORTS_PATH', Path(tmp)):
                engine = AuditEngine()
                engine.add_finding(AuditFinding(
                    skill="test_skill", category="test_cat",
                    title="Export Test", description="D",
                    risk_level="red", technical_risk="T",
                    legal_risk="L", what_it_is="W",
                    what_it_is_not="WN", raw_data={"key": "value"}
                ))
                out = engine.export_json(filename="test_structure")
                data = json.loads(Path(out).read_text(encoding="utf-8"))

                required_keys = [
                    "generated_at", "total_findings", "max_risk",
                    "findings", "integrity_hash"
                ]
                for key in required_keys:
                    self.assertIn(key, data, f"Falta clave requerida: {key}")

                self.assertEqual(data["max_risk"], "red")
                self.assertEqual(data["total_findings"], 1)

                finding = data["findings"][0]
                finding_keys = [
                    "skill", "category", "title", "description",
                    "risk_level", "technical_risk", "legal_risk",
                    "what_it_is", "what_it_is_not", "raw_data", "timestamp"
                ]
                for key in finding_keys:
                    self.assertIn(key, finding, f"Falta clave en finding: {key}")

    def test_json_integrity_hash(self):
        """El hash de integridad es un SHA-256 válido."""
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            from core.audit_engine import AuditEngine, AuditFinding
            with patch('core.audit_engine.DB_PATH', Path(tmp) / 'test.db'), \
                 patch('core.audit_engine.EXPORTS_PATH', Path(tmp)):
                engine = AuditEngine()
                out = engine.export_json(filename="test_hash")
                data = json.loads(Path(out).read_text(encoding="utf-8"))
                hash_val = data.get("integrity_hash", "")
                # SHA-256 son 64 caracteres hexadecimales
                self.assertEqual(len(hash_val), 64)
                self.assertTrue(all(c in "0123456789abcdef" for c in hash_val))

    def test_example_files_valid_schema(self):
        """Los archivos de ejemplo en .docs/examples/ pasan la validación de esquema."""
        with tempfile.TemporaryDirectory() as tmp:
            from core.audit_engine import AuditEngine
            with patch('core.audit_engine.DB_PATH', Path(tmp) / 'test.db'), \
                 patch('core.audit_engine.EXPORTS_PATH', Path(tmp)):
                engine = AuditEngine()

                examples_dir = Path(__file__).parent.parent / ".docs" / "examples"
                example_files = list(examples_dir.glob("*.json"))

                self.assertGreater(len(example_files), 0, "No hay archivos de ejemplo")

                for example_file in example_files:
                    with self.subTest(file=example_file.name):
                        data = json.loads(
                            example_file.read_text(encoding="utf-8")
                        )
                        errors = engine.validate_schema(data)
                        # Los ejemplos tienen integrity_hash de ejemplo (no real),
                        # así que pueden tener ese error específico — ignorarlo
                        real_errors = [
                            e for e in errors
                            if "integrity_hash" not in e.lower()
                        ]
                        self.assertEqual(
                            real_errors, [],
                            f"Errores en {example_file.name}: {real_errors}"
                        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
