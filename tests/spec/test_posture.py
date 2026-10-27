"""Investigation Priority (kế hoạch §10) và Posture Score (§11)."""
import unittest

from tests.helpers import base_cfg
from winguard import posture, priority
from winguard.detectors import collector_health, config_audit
from winguard.models import CONFIRMED_WEAKNESS, NEEDS_REVIEW, Alert


def weakness(root, score, title=None, **kw):
    return Alert("HIGH", title or root, "", category="config", pillar=CONFIRMED_WEAKNESS,
                 root_cause=root, score=score, **kw)


class Posture(unittest.TestCase):
    def test_no_findings_is_100(self):
        self.assertEqual(posture.posture([])["score"], 100.0)

    def test_one_finding(self):
        self.assertEqual(posture.posture([weakness("uac", 36.6)])["score"], 63.4)

    def test_independent_findings(self):
        alerts = [weakness("firewall", 38.5), weakness("lockout_threshold", 27.8),
                  weakness("min_password_length", 25.0)]
        r = posture.posture(alerts)
        self.assertEqual((r["peak"], r["others"], r["score"]), (38.5, [27.8, 25.0], 56.2))  # 56.22

    def test_same_root_cause_not_double_counted(self):
        alerts = [weakness("firewall", 38.5, "Private"), weakness("firewall", 38.5, "Public"),
                  weakness("uac", 36.6)]
        r = posture.posture(alerts)
        self.assertEqual(r["clusters"], {"firewall": 38.5, "uac": 36.6})
        self.assertEqual(r["score"], 57.8)  # 100 - 38.5 - 3.66 = 57.84

    def test_clamped_at_zero_and_range(self):
        r = posture.posture([weakness(f"r{i}", 100.0) for i in range(20)])
        self.assertEqual(r["score"], 0.0)
        for n in range(6):
            s = posture.posture([weakness(f"r{i}", 75.5) for i in range(n)])["score"]
            self.assertTrue(0.0 <= s <= 100.0)

    def test_scoring_error_makes_posture_unknown(self):
        r = posture.posture([weakness("uac", None, scoring_error="ValueError"), weakness("firewall", 38.5)])
        self.assertIsNone(r["score"])
        self.assertEqual(r["unscored"], ["uac"])

    def test_ignores_other_pillars_and_mitigated(self):
        alerts = [Alert("HIGH", "x", "", score=100.0), weakness("uac", 36.6, status="mitigated"),
                  Alert("INFO", "y", "", category="config", pillar=NEEDS_REVIEW, score=80.0)]
        self.assertEqual(posture.posture(alerts)["score"], 100.0)

    def test_internal_label(self):
        self.assertIn("nội bộ", posture.KIND)
        self.assertNotIn("MITRE", posture.KIND)


class Priority(unittest.TestCase):
    def test_table_values(self):
        expect = {"HMAC_MISMATCH": 80.0, "PRIVILEGED_UNVERIFIED": 70.0, "BASELINE_UNSIGNED": 60.0,
                  "PASSWORD_NOT_REQUIRED": 60.0, "SCORING_ERROR": 60.0, "COLLECTOR_ERROR": 50.0,
                  "PROFILE_UNDEFINED": 50.0, "FIREWALL_INACTIVE_PROFILE_OFF": 30.0}
        for code, score in expect.items():
            self.assertEqual(priority.priority(code)[0], score, code)

    def test_assign_every_review_item(self):
        cfg = base_cfg(_errors=["firewall"], accounts_policy={})
        alerts = priority.assign(config_audit.detect(cfg, profile=None) + collector_health.detect(cfg))
        reviews = [a for a in alerts if a.pillar == NEEDS_REVIEW]
        self.assertTrue(reviews)
        for a in reviews:
            self.assertIsNotNone(a.score, a.title)
            self.assertEqual(a.score_kind, priority.KIND)
            self.assertIn("review_code", a.score_breakdown)

    def test_unknown_code_falls_back(self):
        a = priority.assign([Alert("INFO", "x", "", category="config", pillar=NEEDS_REVIEW,
                                   evidence={"review_code": "LA"})])[0]
        self.assertEqual(a.score_breakdown["review_code"], "INSUFFICIENT_EVIDENCE")

    def test_does_not_touch_other_pillars(self):
        a = priority.assign([weakness("uac", 36.6)])[0]
        self.assertEqual(a.score, 36.6)

    def test_internal_label(self):
        self.assertIn("nội bộ", priority.KIND)
        self.assertNotIn("MITRE", priority.KIND)


if __name__ == "__main__":
    unittest.main()
