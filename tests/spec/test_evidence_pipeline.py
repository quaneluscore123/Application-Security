"""Luồng bằng chứng -> trạng thái -> CWE -> CWSS (kế hoạch §2)."""
import unittest

from tests.helpers import base_cfg
from winguard import cwe_map
from winguard.detectors import collector_health, config_audit
from winguard.evidence import NOT_PRESENT, Finding, classify, score
from winguard.models import CONFIRMED_WEAKNESS, NEEDS_REVIEW


def finding(**kw):
    return Finding("uac", "uac", "UAC đang bị tắt", observed={"EnableLUA": 0},
                   expected={"EnableLUA": 1}, source="registry", raw={"EnableLUA": 0}, **kw)


def fake_vector(f):
    return {"vector": {"TI": "H"}, "metric_sources": {"TI": "collected"}, "rationale": {"TI": "x"}}


def fake_compute(vector):
    return {"base": 90.0, "attack_surface": 0.9, "environmental": 0.9, "score": 72.9}


def broken_compute(vector):
    raise ValueError("bảng trọng số hỏng")


class Classify(unittest.TestCase):
    def test_violation_confirmed(self):
        self.assertEqual(classify(finding(), True).status, CONFIRMED_WEAKNESS)

    def test_compliant_not_present(self):
        self.assertEqual(classify(finding(), False).status, NOT_PRESENT)

    def test_missing_data_needs_review_and_keeps_raw(self):
        f = classify(finding(missing=["không đọc được registry"]), True)
        self.assertEqual(f.status, NEEDS_REVIEW)
        self.assertEqual(f.evidence()["raw"], {"EnableLUA": 0})
        self.assertEqual(f.evidence()["missing"], ["không đọc được registry"])

    def test_unknown_violation_needs_review(self):
        f = classify(finding(), None)
        self.assertEqual(f.status, NEEDS_REVIEW)
        self.assertTrue(f.missing)


class Score(unittest.TestCase):
    def test_scored(self):
        r = score(classify(finding(), True), cwe_map.lookup, fake_vector, fake_compute)
        self.assertEqual((r["cwe"], r["cwe_status"], r["cwss"]["score"], r["scoring_error"]),
                         ("CWE-250", "proposed", 72.9, ""))

    def test_scoring_error_keeps_cwe(self):
        r = score(classify(finding(), True), cwe_map.lookup, fake_vector, broken_compute)
        self.assertEqual((r["cwe"], r["cwss"]), ("CWE-250", {}))
        self.assertIn("bảng trọng số hỏng", r["scoring_error"])

    def test_vector_error_is_scoring_error(self):
        def no_vector(f):
            raise KeyError("không có vector")
        r = score(classify(finding(), True), cwe_map.lookup, no_vector, fake_compute)
        self.assertIn("KeyError", r["scoring_error"])

    def test_no_cwe_keeps_finding(self):
        f = Finding("la", "la", "Thiết lập lạ")
        r = score(classify(f, True), cwe_map.lookup, fake_vector, fake_compute)
        self.assertEqual(r["cwe"], "")
        self.assertTrue(r["cwe_rationale"])

    def test_refuses_unconfirmed(self):
        with self.assertRaises(ValueError):
            score(classify(finding(), False), cwe_map.lookup, fake_vector, fake_compute)


class ConfigAuditPipeline(unittest.TestCase):
    def test_scoring_error_keeps_alert_and_evidence(self):
        original = config_audit.COMPUTE
        config_audit.COMPUTE = broken_compute
        try:
            alerts = config_audit.detect(base_cfg(uac_enabled=False), profile="WINGUARD_LAB")
        finally:
            config_audit.COMPUTE = original
        uac = [a for a in alerts if a.root_cause == "uac"]
        self.assertEqual(len(uac), 1)
        self.assertEqual(uac[0].pillar, CONFIRMED_WEAKNESS)
        self.assertEqual(uac[0].evidence["observed"], {"EnableLUA": 0})
        self.assertIsNone(uac[0].score)
        self.assertTrue(uac[0].scoring_error)
        review = [a for a in alerts if a.root_cause == "SCORING_ERROR"]
        self.assertEqual([a.pillar for a in review], [NEEDS_REVIEW])

    def test_collector_error_never_safe(self):
        cfg = base_cfg(accounts_policy={}, _errors=["accounts_policy"])
        alerts = config_audit.detect(cfg, profile="WINGUARD_LAB") + collector_health.detect(cfg)
        self.assertTrue(alerts)
        self.assertTrue(all(a.pillar == NEEDS_REVIEW for a in alerts))

    def test_every_config_alert_has_pillar(self):
        cfg = base_cfg(uac_enabled=False, firewall={"Domain": False, "Private": True, "Public": True},
                       defender={"RealTimeProtectionEnabled": False, "AntivirusSignatureAge": 30},
                       _errors=["local_users"])
        alerts = config_audit.detect(cfg, profile="WINGUARD_LAB") + collector_health.detect(cfg)
        self.assertTrue(all(a.pillar in (CONFIRMED_WEAKNESS, NEEDS_REVIEW) for a in alerts))


if __name__ == "__main__":
    unittest.main()
