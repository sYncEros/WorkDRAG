# tests/test_api.py
"""Tests de integración para los endpoints de la API Flask."""

import json
import unittest
from pathlib import Path
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestAPIEndpoints(unittest.TestCase):

    def setUp(self):
        from ui.server import app
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_status_endpoint(self):
        """GET /api/status devuelve JSON con campo 'running'."""
        r = self.client.get("/api/status")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertIn("running", data)
        self.assertIsInstance(data["running"], bool)

    def test_reports_endpoint(self):
        """GET /api/reports devuelve una lista."""
        r = self.client.get("/api/reports")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertIsInstance(data, list)

    def test_skills_endpoint(self):
        """GET /api/skills devuelve lista de skills."""
        r = self.client.get("/api/skills")
        self.assertEqual(r.status_code, 200)
        skills = json.loads(r.data)
        self.assertIsInstance(skills, list)
        self.assertIn("mdm", skills)
        self.assertIn("surveillance", skills)
        self.assertIn("incident_response", skills)
        self.assertIn("event_viewer", skills)

    def test_recommendation_modes_endpoint(self):
        """GET /api/recommendation-modes devuelve modos soportados."""
        r = self.client.get("/api/recommendation-modes")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertIn("urgente", data)
        self.assertIn("completo", data)
        self.assertIn("personalizado", data)

    def test_report_not_found(self):
        """GET /api/report/<inexistente> devuelve 404."""
        r = self.client.get("/api/report/nonexistent_file.json")
        self.assertEqual(r.status_code, 404)

    def test_compare_missing_params(self):
        """GET /api/compare sin parámetros devuelve 400."""
        r = self.client.get("/api/compare")
        self.assertEqual(r.status_code, 400)

    def test_compare_file_not_found(self):
        """GET /api/compare con archivos inexistentes devuelve 404."""
        r = self.client.get("/api/compare?a=noexiste_a.json&b=noexiste_b.json")
        self.assertEqual(r.status_code, 404)

    def test_run_audit_returns_started(self):
        """POST /api/run inicia una auditoría (mock del subprocess)."""
        with patch("ui.server.audit_status", {"running": False}), \
             patch("threading.Thread") as mock_thread:
            mock_thread.return_value.start = lambda: None
            r = self.client.post(
                "/api/run",
                json={},
                content_type="application/json"
            )
            self.assertIn(r.status_code, [200, 409])

    def test_run_audit_with_recommendation_payload(self):
        """POST /api/run acepta modo y filtros de recomendaciones."""
        with patch("ui.server.audit_status", {"running": False, "last_skills": None, "last_started": None}), \
             patch("threading.Thread") as mock_thread:
            mock_thread.return_value.start = lambda: None
            r = self.client.post(
                "/api/run",
                json={
                    "skills": ["event_viewer"],
                    "recommendation_mode": "personalizado",
                    "recommendation_categories": ["event_viewer_sensitive_events"],
                    "recommendation_risks": ["high"],
                },
                content_type="application/json"
            )
            self.assertEqual(r.status_code, 200)
            data = json.loads(r.data)
            self.assertEqual(data["recommendation_mode"], "personalizado")
            self.assertEqual(data["recommendation_categories"], ["event_viewer_sensitive_events"])
            self.assertEqual(data["recommendation_risks"], ["high"])

    def test_run_audit_already_running(self):
        """POST /api/run cuando ya hay una auditoría en curso devuelve 409."""
        with patch("ui.server.audit_status", {"running": True, "last_skills": None, "last_started": None}):
            r = self.client.post("/api/run", json={})
            self.assertEqual(r.status_code, 409)
            data = json.loads(r.data)
            self.assertEqual(data["status"], "already_running")

    def test_validate_with_example_file(self):
        """GET /api/validate/<example> valida un fichero de ejemplo si existe en exports."""
        # Este test es condicional: solo si hay informes en exports/
        r = self.client.get("/api/reports")
        reports = json.loads(r.data)
        if not reports:
            self.skipTest("No hay informes en exports/ para validar")
        r = self.client.get(f"/api/validate/{reports[0]}")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertIn("valid", data)
        self.assertIn("errors", data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
