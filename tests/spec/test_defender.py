"""Defender: phân biệt RTP với trạng thái chống mã độc tổng thể (kế hoạch §9.5)."""
import unittest

from tests.spec.test_attack_mapping import lan_cfg
from winguard.detectors import config_audit

DEFENDER_OFF = {"RealTimeProtectionEnabled": False, "AntivirusSignatureAge": 0}


class DefenderWithOtherAv(unittest.TestCase):
    @unittest.expectedFailure  # KNOWN-ISSUE-7
    def test_other_av_active_is_not_weakness(self):
        cfg = lan_cfg(defender=DEFENDER_OFF, security_center={
            "antivirus": [{"displayName": "Windows Defender", "productState": 393472},
                          {"displayName": "Other AV", "productState": 266240}], "firewall": []})
        alerts = config_audit.detect(cfg, profile="WINGUARD_LAB")
        self.assertFalse([a for a in alerts if getattr(a, "pillar", "") == "CONFIRMED_WEAKNESS"])


if __name__ == "__main__":
    unittest.main()
