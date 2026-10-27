"""Ngưỡng mật khẩu theo profile (kế hoạch §8)."""
import unittest

from tests.spec.test_attack_mapping import lan_cfg
from winguard.detectors import config_audit


def pw(length, profile):
    policy = {"min_password_length": length, "lockout_threshold": 5, "lockout_duration_min": 10}
    return [a for a in config_audit.detect(lan_cfg(accounts_policy=policy), profile=profile)
            if a.root_cause == "min_password_length"]


class CisProfile(unittest.TestCase):
    @unittest.expectedFailure  # KNOWN-ISSUE-5
    def test_cis_13_is_weakness(self):
        alerts = pw(13, "CIS_WINDOWS_11_ENTERPRISE_V3_L1")
        self.assertEqual([(a.pillar, a.cwe) for a in alerts], [("CONFIRMED_WEAKNESS", "CWE-521")])


if __name__ == "__main__":
    unittest.main()
