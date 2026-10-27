"""Ngưỡng mật khẩu theo profile (kế hoạch §8)."""
import unittest

from tests.spec.test_attack_mapping import lan_cfg
from winguard import profiles
from winguard.detectors import config_audit
from winguard.models import CONFIRMED_WEAKNESS, NEEDS_REVIEW

CIS = "CIS_WINDOWS_11_ENTERPRISE_V3_L1"
LAB = "WINGUARD_LAB"


def run(length, profile, lockout=5):
    policy = {"min_password_length": length, "lockout_threshold": lockout, "lockout_duration_min": 10}
    return config_audit.detect(lan_cfg(accounts_policy=policy), profile=profile)


def pw(length, profile):
    return [a for a in run(length, profile) if a.root_cause == "min_password_length"]


class LabProfile(unittest.TestCase):
    def test_7_8_9(self):
        self.assertEqual([a.pillar for a in pw(7, LAB)], [CONFIRMED_WEAKNESS])
        self.assertEqual(pw(8, LAB), [])  # bằng đúng ngưỡng là đạt
        self.assertEqual(pw(9, LAB), [])

    def test_lab_not_called_cis(self):
        self.assertFalse(profiles.PROFILES[LAB]["external_standard"])


class CisProfile(unittest.TestCase):
    def test_cis_13_is_weakness(self):  # KNOWN-ISSUE-5 (đã sửa ở P4)
        alerts = pw(13, CIS)
        self.assertEqual([(a.pillar, a.cwe) for a in alerts], [("CONFIRMED_WEAKNESS", "CWE-521")])

    def test_14_15_pass(self):
        self.assertEqual(pw(14, CIS), [])
        self.assertEqual(pw(15, CIS), [])

    def test_title_uses_profile_threshold(self):
        a = pw(13, CIS)[0]
        self.assertIn("< 14", a.title)
        self.assertNotIn("< 8", a.title)
        self.assertEqual((a.evidence["profile"], a.evidence["expected"], a.evidence["observed"]),
                         (CIS, ">= 14", 13))

    def test_cis_lockout_unverified_is_review(self):
        alerts = [a for a in run(14, CIS, lockout=0) if a.root_cause == "lockout_threshold"]
        self.assertEqual([a.pillar for a in alerts], [NEEDS_REVIEW])


class MissingValue(unittest.TestCase):
    def test_missing_min_length_title_has_no_none(self):
        cfg = lan_cfg(accounts_policy={"lockout_threshold": 5})
        alerts = [a for a in config_audit.detect(cfg, profile=LAB) if a.root_cause == "min_password_length"]
        self.assertEqual([a.pillar for a in alerts], [NEEDS_REVIEW])
        self.assertNotIn("None", alerts[0].title)


class MissingProfile(unittest.TestCase):
    def test_missing_profile(self):
        alerts = [a for a in run(3, None) if a.root_cause == "min_password_length"]
        self.assertEqual([(a.pillar, a.evidence["review_code"]) for a in alerts],
                         [(NEEDS_REVIEW, "PROFILE_UNDEFINED")])

    def test_wrong_profile_name(self):
        alerts = [a for a in run(3, "CIS_V9") if a.root_cause == "min_password_length"]
        self.assertEqual([a.pillar for a in alerts], [NEEDS_REVIEW])
        self.assertIn("CIS_V9", alerts[0].detail)


if __name__ == "__main__":
    unittest.main()
