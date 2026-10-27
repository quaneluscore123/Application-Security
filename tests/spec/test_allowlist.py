"""Allowlist chỉ miễn trừ tạo tài khoản, không miễn trừ thêm vào Administrators (kế hoạch §7)."""
import unittest

from tests.helpers import ADMINS_SID, base_cfg, ev
from winguard.detectors import accounts
from winguard.models import NEEDS_REVIEW

LAB_SID, USER_SID = "S-1-5-21-1-2001", "S-1-5-21-1-2002"


def create(sid, name):
    return ev(4720, 0, TargetSid=sid, TargetUserName=name)


def add(sid, group=ADMINS_SID):
    return ev(4732, 5, TargetSid=group, MemberSid=sid)


def cfg_with_admins(*members):
    return base_cfg(admin_members=[{"Name": "quan", "SID": "S-1-5-21-1-1001"}, *members])


def codes(alerts):
    return sorted(a.mitre.split()[0] for a in alerts if a.mitre)


class Allowlist(unittest.TestCase):
    def test_allowlisted_creation_silent(self):
        self.assertEqual(accounts.detect([create(LAB_SID, "sim_testuser")], base_cfg(), None), [])
        self.assertEqual(accounts.detect([create(LAB_SID, "sim_spray3")], base_cfg(), None), [])

    def test_other_creation_alerts(self):
        self.assertEqual(codes(accounts.detect([create(USER_SID, "hacker")], base_cfg(), None)), ["T1136.001"])

    def test_allowlisted_added_to_admins_alerts_with_formula_score(self):
        cfg = cfg_with_admins({"Name": "sim_testuser", "SID": LAB_SID})
        alerts = accounts.detect([create(LAB_SID, "sim_testuser"), add(LAB_SID)], cfg, None)
        self.assertEqual(codes(alerts), ["T1098"])
        a = alerts[0]
        self.assertTrue(a.alert_required)
        self.assertEqual(a.score_breakdown["policy"], "PRIVILEGED_GROUP_CHANGE")
        # điểm theo công thức (một nguồn vì không có baseline), không ép 100
        self.assertEqual(a.score, 100 * a.score_breakdown["T"] * a.score_breakdown["C"] * a.score_breakdown["W"])
        self.assertEqual(a.score, 95.0)

    def test_other_added_to_admins(self):
        cfg = cfg_with_admins({"Name": "hacker", "SID": USER_SID})
        self.assertEqual(codes(accounts.detect([create(USER_SID, "hacker"), add(USER_SID)], cfg, None)),
                         ["T1098", "T1136.001"])

    def test_non_privileged_group(self):
        alerts = accounts.detect([create(LAB_SID, "sim_testuser"), add(LAB_SID, "S-1-5-32-545")],
                                 base_cfg(), None)
        self.assertEqual(alerts, [])

    def test_admin_add_missing_evidence_kept(self):
        alerts = accounts.detect([add("")], base_cfg(), None)
        self.assertEqual(codes(alerts), ["T1098"])
        self.assertTrue(alerts[0].unverified)
        self.assertIn(NEEDS_REVIEW, [a.pillar for a in alerts])


if __name__ == "__main__":
    unittest.main()
