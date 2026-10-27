"""Đo độ phủ của luật phát hiện (detection engineering) bằng số đếm, không trọng số.

Ba phép đo:
1. Tỷ lệ phát hiện: chạy mỗi kịch bản N lần, đếm số lần luật bắt đúng mã MITRE.
2. Báo động giả: quét N lần trên máy KHÔNG mô phỏng gì, đếm cảnh báo sự kiện xuất hiện.
3. Thử né luật: chạy password spraying, quét CÙNG bộ log bằng luật v1 (trước khi vá) và v2.

Cách dùng (terminal quyền Administrator, đã chạy tools\\prepare.ps1):
    python -m simulator.benchmark --runs 3
Kết quả in dạng bảng Markdown và lưu vào data/benchmark.json.
"""
import argparse
import sys
import time
from datetime import datetime

from simulator.__main__ import SCENARIOS
from winguard import scoring
from winguard.__main__ import analyze, save_baseline
from winguard.utils import is_admin, save_json

# Mã MITRE chính mà kịch bản phải bị phát hiện, và mã phụ được phép xuất hiện kèm theo.
EXPECTED = {
    "bruteforce": ("T1110", set()),
    "spray": ("T1110.003", set()),
    "new_account": ("T1136.001", set()),
    "admin_group": ("T1098", {"T1136.001"}),  # phải tạo tài khoản trước khi thêm vào nhóm
    "runkey": ("T1547.001", set()),
    "scheduled_task": ("T1053.005", set()),
}
SETTLE = 2  # giây chờ Windows ghi xong log trước khi quét


def _codes(alerts) -> list[str]:
    """Mã kỹ thuật (VD 'T1110.003') của các cảnh báo SỰ KIỆN; bỏ qua cảnh báo cấu hình."""
    return [a.mitre.split()[0] for a in alerts if a.category == "event" and a.mitre]


def _scan(since: datetime, rules: str = "v2") -> list[str]:
    time.sleep(SETTLE)
    _, alerts = analyze(None, since=since, rules=rules)
    return _codes(alerts)


def _start() -> datetime:
    time.sleep(1.1)  # sang giây mới để log của lượt trước không lọt vào cửa sổ quét
    return datetime.now()


def measure_detection(runs: int) -> list[dict]:
    rows = []
    for name, (primary, extra) in EXPECTED.items():
        detected, unexpected = 0, []
        for _ in range(runs):
            start = _start()
            SCENARIOS[name].run_scenario()
            codes = _scan(start)
            SCENARIOS[name].cleanup()
            detected += primary in codes
            unexpected += [c for c in codes if c != primary and c not in extra]
        rows.append({"scenario": name, "mitre": primary, "runs": runs,
                     "detected": detected, "unexpected": sorted(set(unexpected))})
    return rows


def measure_false_positives(runs: int) -> dict:
    alerts = []
    for _ in range(runs):
        alerts += _scan(_start())
    return {"runs": runs, "false_alerts": len(alerts), "codes": sorted(set(alerts))}


def measure_evasion(runs: int) -> dict:
    caught = {"v1": 0, "v2": 0}
    for _ in range(runs):
        start = _start()
        SCENARIOS["spray"].run_scenario()
        for rules in caught:
            caught[rules] += "T1110.003" in _scan(start, rules)
        SCENARIOS["spray"].cleanup()
    return {"runs": runs, **caught}


def _print_tables(det: list[dict], fp: dict, ev: dict) -> None:
    print("\n### Tỷ lệ phát hiện\n")
    print("| Kịch bản | MITRE | Phát hiện | Cảnh báo ngoài dự kiến |")
    print("|---|---|---|---|")
    for r in det:
        print(f"| {r['scenario']} | {r['mitre']} | {r['detected']}/{r['runs']} | "
              f"{', '.join(r['unexpected']) or 'không'} |")
    total = sum(r["detected"] for r in det)
    print(f"\nTổng: {total}/{sum(r['runs'] for r in det)} lần mô phỏng được phát hiện.")
    print("\n### Báo động giả (quét khi không mô phỏng gì)\n")
    print(f"{fp['false_alerts']} cảnh báo sự kiện sau {fp['runs']} lần quét sạch"
          + (f" (mã: {', '.join(fp['codes'])})" if fp["codes"] else "") + ".")
    print("\n### Thử né luật: password spraying\n")
    print("| Bộ luật | Phát hiện |")
    print("|---|---|")
    print(f"| v1 (trước khi vá) | {ev['v1']}/{ev['runs']} |")
    print(f"| v2 (sau khi vá) | {ev['v2']}/{ev['runs']} |")


def main() -> None:
    parser = argparse.ArgumentParser(prog="simulator.benchmark", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runs", type=int, default=3, help="số lần lặp mỗi phép đo (mặc định 3)")
    args = parser.parse_args()
    if not is_admin():
        sys.exit("Cần chạy terminal bằng quyền Administrator (và đã chạy tools\\prepare.ps1).")

    print("[*] Dọn dẹp và lấy baseline mới")
    for s in SCENARIOS.values():
        s.cleanup()
    cfg, alerts = analyze(None, include_events=False)
    save_baseline(cfg, scoring.score(alerts))

    print(f"[*] Đo tỷ lệ phát hiện ({args.runs} lần mỗi kịch bản)")
    det = measure_detection(args.runs)
    print(f"[*] Đo báo động giả ({args.runs} lần quét sạch)")
    fp = measure_false_positives(args.runs)
    print(f"[*] Thử né luật ({args.runs} lần password spraying, luật v1 và v2)")
    ev = measure_evasion(args.runs)

    save_json("benchmark.json", {"time": datetime.now(), "detection": det,
                                 "false_positives": fp, "evasion": ev})
    _print_tables(det, fp, ev)
    print("\nĐã lưu data/benchmark.json. Nhớ chạy tools\\restore.ps1 khi xong.")


if __name__ == "__main__":
    main()
