"""Defender: phân biệt RTP với trạng thái chống mã độc tổng thể (kế hoạch §9.5) và PasswordRequired (§8)."""
import unittest

from tests.spec.test_attack_mapping import lan_cfg
from winguard.detectors import config_audit
from winguard.models import CONFIRMED_WEAKNESS, NEEDS_REVIEW

DEFENDER_OFF = {"RealTimeProtectionEnabled": False, "AntivirusSignatureAge": 0}
DEFENDER_SC = {"displayName": "Windows Defender", "productState": 393472}


def defender(cfg):
    return [a for a in config_audit.detect(cfg, profile="WINGUARD_LAB") if a.root_cause == "defender_rtp"]


class DefenderWithOtherAv(unittest.TestCase):
    def test_other_av_active_is_not_weakness(self):  # KNOWN-ISSUE-7 (đã sửa ở P4)
        cfg = lan_cfg(defender=DEFENDER_OFF, security_center={
            "antivirus": [DEFENDER_SC, {"displayName": "Other AV", "productState": 266240}], "firewall": []})
        alerts = config_audit.detect(cfg, profile="WINGUARD_LAB")
        self.assertFalse([a for a in alerts if getattr(a, "pillar", "") == "CONFIRMED_WEAKNESS"])

    def test_no_other_av_confirmed_with_collected_ec(self):
        alerts = defender(lan_cfg(defender=DEFENDER_OFF,
                                  security_center={"antivirus": [DEFENDER_SC], "firewall": []}))
        self.assertEqual([a.pillar for a in alerts], [CONFIRMED_WEAKNESS])
        self.assertEqual(alerts[0].score_breakdown["metric_sources"]["EC"], "collected")
        self.assertEqual(alerts[0].score, 75.5)

    def test_security_center_error_is_review(self):
        cfg = lan_cfg(defender=DEFENDER_OFF)
        cfg["_status"] = {"security_center": "error"}
        self.assertEqual([a.pillar for a in defender(cfg)], [NEEDS_REVIEW])

    def test_rtp_field_missing_is_review(self):
        alerts = defender(lan_cfg(defender={"AntivirusSignatureAge": 0}))
        self.assertEqual([a.pillar for a in alerts], [NEEDS_REVIEW])

    def test_rtp_on_no_alert(self):
        self.assertEqual(defender(lan_cfg()), [])


class PasswordRequired(unittest.TestCase):
    def users(self, **u):
        return lan_cfg(local_users=[{"Name": "HP", "SID": "S-1-5-21-1-1001", "Disabled": False, **u}])

    def alerts(self, cfg):
        return [a for a in config_audit.detect(cfg, profile="WINGUARD_LAB")
                if a.root_cause == "password_required"]

    def test_flag_is_review_not_cwe_258(self):
        alerts = self.alerts(self.users(PasswordRequired=False))
        self.assertEqual([(a.pillar, a.cwe, a.severity) for a in alerts], [(NEEDS_REVIEW, "", "INFO")])

    def test_disabled_or_required_ignored(self):
        self.assertEqual(self.alerts(self.users(PasswordRequired=False, Disabled=True)), [])
        self.assertEqual(self.alerts(self.users(PasswordRequired=True)), [])


if __name__ == "__main__":
    unittest.main()
