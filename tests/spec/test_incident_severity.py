"""WinGuard Incident Severity = 100 x T x C x W (kế hoạch §5)."""
import unittest

from tests.helpers import ev, failed_logon
from winguard import incident
from winguard.detectors import bruteforce, evasion


class Formula(unittest.TestCase):
    def test_100_only_when_all_one(self):
        self.assertEqual(incident.severity(1, 1, 1), 100.0)
        self.assertLess(incident.severity(1, 1, 0.99), 100.0)

    def test_half_up_rounding(self):
        self.assertEqual(incident.severity(0.75, 1.0, 0.85), 63.8)   # 63.75
        self.assertEqual(incident.severity(0.9, 0.95, 0.9), 77.0)    # 76.95
        self.assertEqual(incident.severity(0.6, 0.8, 0.75), 36.0)

    def test_boundaries(self):
        self.assertEqual(incident.severity(1e-9, 1, 1), 0.0)  # gần 0 (miền mở nên không đạt đúng 0)
        for bad in (0, -0.1, 1.01, None, "0.5", True):
            with self.assertRaises(ValueError):
                incident.severity(bad, 1, 1)
            with self.assertRaises(ValueError):
                incident.severity(1, bad, 1)
            with self.assertRaises(ValueError):
                incident.severity(1, 1, bad)

    def test_internal_label(self):
        self.assertIn("nội bộ", incident.KIND)
        self.assertNotIn("MITRE", incident.KIND)


class DetectorScores(unittest.TestCase):
    def test_1102(self):
        a = evasion.detect([ev(1102, record_id=7)])[0]
        self.assertEqual((a.score, a.score_breakdown["T"], a.score_breakdown["C"], a.score_breakdown["W"]),
                         (77.0, 0.9, 0.95, 0.9))
        self.assertEqual(a.score_breakdown["record_ids"], [7])

    def test_bruteforce_heuristic(self):
        a = bruteforce.detect([failed_logon("u", i) for i in range(6)])[0]
        self.assertEqual((a.score, a.score_breakdown["confidence"]), (36.0, "heuristic"))
        self.assertFalse(a.unverified)

    def test_every_event_alert_explains_tcw(self):
        events = [failed_logon(f"s{u}", u * 4 + k) for u in range(6) for k in range(2)] + [ev(1102)]
        for a in bruteforce.detect(events) + evasion.detect(events):
            for key in ("T", "C", "W", "reason", "event_ids", "model"):
                self.assertIn(key, a.score_breakdown, a.title)


if __name__ == "__main__":
    unittest.main()
