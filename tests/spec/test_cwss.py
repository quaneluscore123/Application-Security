"""MITRE CWSS v1.0.1 (kế hoạch §3, §13.1)."""
import itertools
import unittest
from pathlib import Path

from tests.helpers import base_cfg
from winguard import cwss, cwss_vectors
from winguard.cwss_weights import (CWSS_MANUAL_CHECK, EXAMPLES, WEIGHTS, manual_check_problems,
                                   manual_check_status)
from winguard.detectors import config_audit
from winguard.evidence import Finding, classify
from winguard.models import CONFIRMED_WEAKNESS

ALL_NA = "/".join(f"{m}:NA" for m in cwss.METRICS)


def independent(vector: str) -> float:
    """Tính lại bằng float thuần, không dùng code của cwss.compute (kiểm tra breakdown)."""
    w = {m: WEIGHTS[m][c] for m, c in cwss.parse(vector).items()}
    base = (10 * w["TI"] + 5 * (w["AP"] + w["AL"]) + 5 * w["FC"]) * (w["TI"] != 0) * w["IC"] * 4
    surface = (20 * (w["RP"] + w["RL"] + w["AV"]) + 20 * w["SC"] + 15 * w["IN"] + 5 * w["AS"]) / 100
    env = (10 * w["BI"] + 3 * w["DI"] + 4 * w["EX"] + 3 * w["P"]) * (w["BI"] != 0) * w["EC"] / 20
    return base * surface * env


class OfficialExamples(unittest.TestCase):
    def test_example_4_2_primary(self):
        ex = EXAMPLES["4.2"]
        r = cwss.compute(ex["vector"])
        self.assertEqual((r["base"], r["attack_surface"], r["environmental"], r["score"]),
                         (ex["base"], ex["attack_surface"], ex["environmental"], ex["score"]))

    def test_example_4_1_discrepancy_recorded_not_used_as_standard(self):
        ex = EXAMPLES["4.1"]
        # Không sửa nguồn: ghi nhận rằng trọng số mã C (1.0) và trọng số in kèm (0.9) cho kết quả khác nhau
        self.assertEqual(ex["status"], "DISCREPANCY_PENDING_MANUAL_CHECK")
        self.assertNotEqual(WEIGHTS["BI"]["C"], ex["printed_bi_weight"])
        self.assertEqual(cwss.compute(ex["vector"])["score"], ex["score"])
        with_printed = ex["base"] * ex["attack_surface"] * (10 * 0.9 + 3 + 4 + 3) / 20
        self.assertNotAlmostEqual(with_printed, ex["score"], places=1)


class Properties(unittest.TestCase):
    def test_gating_ti_none(self):
        r = cwss.compute(ALL_NA.replace("TI:NA", "TI:N"))
        self.assertEqual((r["base"], r["score"]), (0.0, 0.0))

    def test_gating_bi_none(self):
        r = cwss.compute(ALL_NA.replace("BI:NA", "BI:N"))
        self.assertEqual((r["environmental"], r["score"]), (0.0, 0.0))

    def test_all_na_is_100(self):
        self.assertEqual(cwss.compute(ALL_NA)["score"], 100.0)

    def test_range_on_samples(self):
        codes = {m: list(WEIGHTS[m]) for m in cwss.METRICS}
        for i, combo in enumerate(itertools.product(*[codes[m][:2] for m in cwss.METRICS])):
            if i > 3000:
                break
            r = cwss.compute(dict(zip(cwss.METRICS, combo)))
            self.assertTrue(0.0 <= r["score"] <= 100.0)

    def test_order_independent(self):
        v = cwss.parse(EXAMPLES["4.2"]["vector"])
        self.assertEqual(cwss.compute(dict(reversed(list(v.items())))), cwss.compute(v))

    def test_breakdown_matches_independent_calculation(self):
        for name in ("4.1", "4.2"):
            r = cwss.compute(EXAMPLES[name]["vector"])
            self.assertAlmostEqual(r["base"] * r["attack_surface"] * r["environmental"],
                                   independent(EXAMPLES[name]["vector"]), places=9)


class Parser(unittest.TestCase):
    def test_missing_metric(self):
        with self.assertRaises(ValueError):
            cwss.parse(ALL_NA.replace("/P:NA", ""))

    def test_wrong_code(self):
        with self.assertRaises(ValueError):
            cwss.parse(ALL_NA.replace("TI:NA", "TI:X"))

    def test_none_value(self):
        v = cwss.parse(ALL_NA)
        v["TI"] = None
        with self.assertRaises(ValueError):
            cwss.parse(v)

    def test_unknown_metric(self):
        with self.assertRaises(ValueError):
            cwss.parse(ALL_NA + "/ZZ:H")

    def test_quantified_not_supported(self):
        with self.assertRaises(ValueError):
            cwss.parse(ALL_NA.replace("TI:NA", "TI:Q"))

    def test_av_unknown_code_is_U(self):
        self.assertEqual(cwss.parse(ALL_NA.replace("AV:NA", "AV:U"))["AV"], "U")
        with self.assertRaises(ValueError):
            cwss.parse(ALL_NA.replace("AV:NA", "AV:UK"))

    def test_re_ignored(self):
        self.assertNotIn("RE", cwss.parse(ALL_NA + "/RE:NA"))

    def test_weight_codes_distinct(self):
        self.assertEqual((WEIGHTS["TI"]["N"], WEIGHTS["TI"]["NA"], WEIGHTS["TI"]["UK"], WEIGHTS["TI"]["D"]),
                         (0.0, 1.0, 0.5, 0.6))


class ManualCheck(unittest.TestCase):
    def test_structure_and_pending(self):
        for key in ("status", "reviewer", "date", "formulas", "weight_table", "example_4_1",
                    "example_4_2", "weight_table_screenshots", "notes"):
            self.assertIn(key, CWSS_MANUAL_CHECK)
        self.assertTrue(CWSS_MANUAL_CHECK["reviewer"])

    def test_verified_requires_evidence(self):
        fake = {**CWSS_MANUAL_CHECK, "status": "VERIFIED"}
        self.assertTrue(manual_check_problems(fake, Path(".")))

    def test_status_not_verified_while_pending(self):
        if CWSS_MANUAL_CHECK["status"] == "PENDING":
            self.assertEqual(manual_check_status(), "PENDING")
            self.assertEqual(cwss.compute(ALL_NA)["weights_manual_check"], "PENDING")


class WinGuardVectors(unittest.TestCase):
    def f(self, root, **kw):
        return classify(Finding(root, root, "x", **kw), True)

    def test_every_template_valid(self):
        for root in cwss_vectors.TEMPLATES:
            v = cwss_vectors.build(self.f(root))
            cwss.parse(v["vector"])
            self.assertEqual(set(v["metric_sources"]), set(cwss.METRICS))
            self.assertTrue(all(v["rationale"].values()))

    def test_unverified_metrics_are_unknown(self):
        for root in cwss_vectors.TEMPLATES:
            v = cwss_vectors.build(self.f(root))
            for m, src in v["metric_sources"].items():
                if src == "unknown":
                    self.assertIn(v["vector"][m], ("UK", "U"), (root, m))

    def test_published_estimates(self):
        # Ước tính §3.4 của kế hoạch (EC = Unknown; firewall chưa có SecurityCenter2 -> IC Unknown)
        expect = {"firewall": 19.2, "lockout_threshold": 27.8, "min_password_length": 25.0,
                  "uac": 36.6}
        for root, score in expect.items():
            self.assertEqual(cwss.compute(cwss_vectors.build(self.f(root))["vector"])["score"], score, root)
        fw = self.f("firewall", context={"other_firewall": False})
        self.assertEqual(cwss.compute(cwss_vectors.build(fw)["vector"])["score"], 38.5)
        av = self.f("defender_rtp", context={"other_av": False})
        self.assertEqual(cwss.compute(cwss_vectors.build(av)["vector"])["score"], 75.5)

    def test_config_alert_carries_cwss(self):
        alerts = config_audit.detect(base_cfg(uac_enabled=False), profile="WINGUARD_LAB")
        uac = [a for a in alerts if a.root_cause == "uac"][0]
        self.assertEqual((uac.pillar, uac.score, uac.score_kind), (CONFIRMED_WEAKNESS, 36.6, "CWSS"))
        self.assertEqual(uac.score_breakdown["vector_chosen_by"], "WinGuard")
        self.assertEqual(uac.score_breakdown["metric_sources"]["EC"], "unknown")


if __name__ == "__main__":
    unittest.main()
