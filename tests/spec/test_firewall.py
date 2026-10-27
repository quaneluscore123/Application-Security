"""Firewall theo profile đang hoạt động (kế hoạch §9)."""
import unittest

from tests.helpers import base_cfg
from winguard.detectors import config_audit
from winguard.models import CONFIRMED_WEAKNESS, NEEDS_REVIEW

ALL_ON = {"Domain": True, "Private": True, "Public": True}


def cfg(firewall=None, nets=None, sc=None, status=None):
    c = base_cfg(firewall=ALL_ON.copy() if firewall is None else firewall,
                 network_profiles=[] if nets is None else nets,
                 security_center={"antivirus": [], "firewall": []} if sc is None else sc)
    c["_status"] = status or {}
    return c


def off(profile):
    return {**ALL_ON, profile: False}


def net(alias, category):
    return {"InterfaceAlias": alias, "NetworkCategory": category}


def fw(c):
    return [a for a in config_audit.detect(c, profile="WINGUARD_LAB") if a.root_cause == "firewall"]


def pillars(c):
    return sorted(a.pillar for a in fw(c))


class ActiveProfile(unittest.TestCase):
    def test_domain_authenticated_maps_to_domain(self):
        alerts = fw(cfg(off("Domain"), [net("LAN", "DomainAuthenticated")]))
        self.assertEqual([(a.pillar, a.evidence["observed"]) for a in alerts],
                         [(CONFIRMED_WEAKNESS, {"Enabled": False})])
        self.assertIn("Domain", alerts[0].title)

    def test_private_and_public(self):
        for category in ("Private", "Public"):
            self.assertEqual(pillars(cfg(off(category), [net("Wi-Fi", category)])), [CONFIRMED_WEAKNESS])

    def test_numeric_category_from_powershell(self):
        self.assertEqual(pillars(cfg(off("Public"), [net("VPN", 0)])), [CONFIRMED_WEAKNESS])
        self.assertEqual(pillars(cfg(off("Domain"), [net("LAN", 2)])), [CONFIRMED_WEAKNESS])

    def test_inactive_profile_off_is_only_review(self):  # KNOWN-ISSUE-4 (đã sửa ở P4)
        alerts = fw(cfg(off("Domain"), [net("Wi-Fi", "Private")]))
        self.assertEqual([a.pillar for a in alerts], [NEEDS_REVIEW])
        self.assertEqual(alerts[0].evidence["review_code"], "FIREWALL_INACTIVE_PROFILE_OFF")

    def test_multiple_connections_all_profiles_considered(self):
        nets = [net("Wi-Fi", "Private"), net("ZeroTier", "Public"), net("Radmin VPN", "Public")]
        alerts = fw(cfg({"Domain": True, "Private": True, "Public": False}, nets))
        self.assertEqual([a.pillar for a in alerts], [CONFIRMED_WEAKNESS])
        self.assertIn("ZeroTier", alerts[0].title)
        self.assertIn("Radmin VPN", alerts[0].title)
        self.assertNotIn("Wi-Fi", alerts[0].title)  # profile Private đang bật, không bị chọn nhầm

    def test_two_active_profiles_off(self):
        c = cfg({"Domain": True, "Private": False, "Public": False},
                [net("Wi-Fi", "Private"), net("VPN", "Public")])
        self.assertEqual(pillars(c), [CONFIRMED_WEAKNESS, CONFIRMED_WEAKNESS])

    def test_all_on_no_alert(self):
        self.assertEqual(fw(cfg(nets=[net("Wi-Fi", "Private")])), [])


class MissingOrBadData(unittest.TestCase):
    def test_no_connection(self):
        alerts = fw(cfg(off("Public"), []))
        self.assertEqual([a.pillar for a in alerts], [NEEDS_REVIEW])
        self.assertIn("không có kết nối", alerts[0].detail)

    def test_connection_profile_collector_error(self):
        alerts = fw(cfg(off("Public"), [], status={"network_profiles": "error"}))
        self.assertEqual([a.pillar for a in alerts], [NEEDS_REVIEW])
        self.assertEqual(alerts[0].evidence["raw"]["firewall"], off("Public"))  # giữ dữ liệu lệnh còn lại

    def test_old_cfg_without_network_profiles(self):
        self.assertEqual([a.pillar for a in fw(base_cfg(firewall=off("Public")))], [NEEDS_REVIEW])

    def test_firewall_collector_error(self):
        alerts = fw(cfg({}, [net("Wi-Fi", "Private")], status={"firewall": "error"}))
        self.assertEqual([a.pillar for a in alerts], [NEEDS_REVIEW])
        self.assertEqual(alerts[0].evidence["review_code"], "COLLECTOR_ERROR")

    def test_firewall_empty(self):
        self.assertEqual(pillars(cfg({}, [net("Wi-Fi", "Private")])), [NEEDS_REVIEW])

    def test_enabled_unreadable_is_review_not_off(self):
        alerts = fw(cfg({"Domain": True, "Private": None, "Public": True}, [net("Wi-Fi", "Private")]))
        self.assertEqual([(a.pillar, a.evidence["review_code"]) for a in alerts],
                         [(NEEDS_REVIEW, "COLLECTOR_ERROR")])

    def test_unmapped_category(self):
        alerts = fw(cfg(off("Private"), [net("Wi-Fi", "Private"), net("Khac", "Unknown")]))
        self.assertEqual(sorted(a.pillar for a in alerts), [CONFIRMED_WEAKNESS, NEEDS_REVIEW])
        review = [a for a in alerts if a.pillar == NEEDS_REVIEW][0]
        self.assertEqual(review.evidence["review_code"], "NETWORK_CATEGORY_UNKNOWN")


class SecurityCenterForIC(unittest.TestCase):
    def test_sc2_ok_ic_collected(self):
        a = fw(cfg(off("Private"), [net("Wi-Fi", "Private")]))[0]
        self.assertEqual((a.score_breakdown["vector"]["IC"], a.score_breakdown["metric_sources"]["IC"]),
                         ("N", "collected"))
        self.assertEqual(a.score, 38.5)

    def test_sc2_error_ic_unknown(self):
        a = fw(cfg(off("Private"), [net("Wi-Fi", "Private")], status={"security_center": "error"}))[0]
        self.assertEqual(a.pillar, CONFIRMED_WEAKNESS)
        self.assertEqual(a.score_breakdown["vector"]["IC"], "UK")
        self.assertEqual(a.score, 19.2)

    def test_other_firewall_active_is_review(self):
        sc = {"antivirus": [], "firewall": [{"displayName": "Other FW", "productState": 266240}]}
        alerts = fw(cfg(off("Private"), [net("Wi-Fi", "Private")], sc))
        self.assertEqual([a.evidence["review_code"] for a in alerts], ["OTHER_PRODUCT_ACTIVE"])

    def test_description_does_not_claim_all_ports_open(self):
        a = fw(cfg(off("Private"), [net("Wi-Fi", "Private")]))[0]
        self.assertNotIn("mọi cổng", a.detail.lower())


if __name__ == "__main__":
    unittest.main()
