"""Trường gom cụm và tương quan sự kiện (kế hoạch §6)."""
import unittest

from tests.helpers import ADMINS_SID, EVENT_XML, base_cfg, ev
from winguard import correlation
from winguard.collectors import eventlog
from winguard.detectors import accounts

SID_A, SID_B = "S-1-5-21-1-2001", "S-1-5-21-1-2002"


def create(sid, t, pc="LAB-PC", rid=None, name="sim_user"):
    return ev(4720, t, computer=pc, record_id=rid, TargetSid=sid, TargetUserName=name)


def add(sid, t, pc="LAB-PC", rid=None):
    return ev(4732, t, computer=pc, record_id=rid, TargetSid=ADMINS_SID, MemberSid=sid)


def admin_cfg(*sids):
    return base_cfg(admin_members=[{"Name": "quan", "SID": "S-1-5-21-1-1001"}]
                    + [{"Name": f"u{i}", "SID": s} for i, s in enumerate(sids)])


def t1098(alerts):
    return [a for a in alerts if a.mitre.startswith("T1098")]


class EventFields(unittest.TestCase):
    def test_parse_keeps_computer_and_record_id(self):  # KNOWN-ISSUE-6 (đã sửa ở P4)
        e = eventlog.parse_event(EVENT_XML)
        self.assertEqual((e["computer"], e["record_id"]), ("LAB-PC", 42))


class Correlation(unittest.TestCase):
    def match(self, addition, creations):
        return correlation.match_creation(addition, creations)[0]

    def test_chain_same_machine_same_sid(self):
        c = create(SID_A, 0)
        self.assertIs(self.match(add(SID_A, 10), [c]), c)

    def test_two_machines_same_username(self):
        # cùng tên 'sim_user' nhưng khác máy và khác SID -> không ghép
        self.assertIsNone(self.match(add(SID_B, 10, pc="PC-2"), [create(SID_A, 0, pc="PC-1")]))

    def test_two_accounts_same_machine(self):
        self.assertIsNone(self.match(add(SID_B, 10), [create(SID_A, 0)]))

    def test_same_account_two_machines(self):
        self.assertIsNone(self.match(add(SID_A, 10, pc="PC-2"), [create(SID_A, 0, pc="PC-1")]))

    def test_out_of_order(self):
        result, note = correlation.match_creation(add(SID_A, 0), [create(SID_A, 10)])
        self.assertIsNone(result)
        self.assertIn("thứ tự bất thường", note)

    def test_duplicates_removed(self):
        events = [add(SID_A, 10, rid=5), add(SID_A, 10, rid=5), create(SID_A, 0, rid=4)]
        self.assertEqual(len(correlation.dedupe(events)), 2)
        alerts = t1098(accounts.detect(events, admin_cfg(SID_A), None))
        self.assertEqual(len(alerts), 1)

    def test_missing_sid(self):
        result, note = correlation.match_creation(add("", 10), [create(SID_A, 0)])
        self.assertIsNone(result)
        self.assertTrue(note)

    def test_outside_window(self):
        self.assertIsNone(self.match(add(SID_A, 301), [create(SID_A, 0)]))
        self.assertIsNotNone(self.match(add(SID_A, 300), [create(SID_A, 0)]))


class ConfidenceLevels(unittest.TestCase):
    def test_full_chain_with_baseline_is_100(self):
        alerts = t1098(accounts.detect([create(SID_A, 0), add(SID_A, 12)], admin_cfg(SID_A), admin_cfg()))
        self.assertEqual((alerts[0].score, alerts[0].score_breakdown["confidence"]), (100.0, "corroborated"))
        self.assertIn("root_cause_id", alerts[0].score_breakdown)

    def test_only_4732_is_95(self):
        alerts = t1098(accounts.detect([add(SID_A, 12)], admin_cfg(SID_A), admin_cfg()))
        self.assertEqual(alerts[0].score, 95.0)

    def test_single_event_chain_without_baseline_is_95(self):
        alerts = t1098(accounts.detect([create(SID_A, 0), add(SID_A, 12)], admin_cfg(SID_A), None))
        self.assertEqual(alerts[0].score, 95.0)

    def test_contradiction_is_unverified(self):
        alerts = accounts.detect([add(SID_A, 12)], admin_cfg(), None)  # SID không còn trong Administrators
        admin = t1098(alerts)[0]
        self.assertEqual((admin.score, admin.unverified), (60.0, True))
        self.assertIn("PRIVILEGED_UNVERIFIED", [a.root_cause for a in alerts])

    def test_baseline_only(self):
        alerts = t1098(accounts.detect([], admin_cfg(SID_A), admin_cfg()))
        self.assertEqual((alerts[0].score, alerts[0].score_breakdown["event_ids"]), (95.0, []))


if __name__ == "__main__":
    unittest.main()
