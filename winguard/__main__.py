"""WinGuard - công cụ giám sát và đánh giá bảo mật Windows.

Cách dùng (chạy terminal bằng quyền Administrator):
    python -m winguard --baseline   # lưu trạng thái "bình thường" của máy
    python -m winguard --scan       # quét, so với baseline, xuất báo cáo
"""
import argparse
import sys
from datetime import datetime, timedelta

from winguard import reporter, scoring
from winguard.collectors import config, eventlog
from winguard.detectors import bruteforce, config_audit
from winguard.utils import is_admin, load_json, save_json

EVENT_IDS = [bruteforce.FAILED_LOGON, bruteforce.ACCOUNT_LOCKED]


def scan_start(hours: int | None) -> datetime:
    """Mốc bắt đầu đọc log: --hours nếu có, nếu không thì lần chạy simulator gần nhất
    (để kết quả trước/sau phòng thủ không lẫn vào nhau), mặc định 1 giờ."""
    if hours is None:
        runs = load_json("sim_log.json", [])
        if runs:
            return datetime.fromisoformat(runs[-1]["start"])
        hours = 1
    return datetime.now() - timedelta(hours=hours)


def analyze(hours: int | None):
    cfg = config.collect()
    alerts = config_audit.detect(cfg)
    if is_admin():
        since = scan_start(hours)
        print(f"Đọc Security Event Log từ {since:%Y-%m-%d %H:%M:%S}")
        alerts += bruteforce.detect(eventlog.query_security(EVENT_IDS, since))
    else:
        print("[CẢNH BÁO] Không chạy bằng quyền Admin -> bỏ qua Security Event Log.", file=sys.stderr)
    return cfg, alerts


def main() -> None:
    parser = argparse.ArgumentParser(prog="winguard", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--baseline", action="store_true", help="lưu trạng thái baseline")
    mode.add_argument("--scan", action="store_true", help="quét và xuất báo cáo")
    parser.add_argument("--hours", type=int,
                        help="số giờ log cần quét (mặc định: từ lần chạy simulator gần nhất, hoặc 1 giờ)")
    args = parser.parse_args()

    cfg, alerts = analyze(args.hours)
    score = scoring.score(alerts)

    if args.baseline:
        save_json("baseline.json", {"time": datetime.now(), "config": cfg, "score": score})
        reporter.print_console(alerts, score)
        print("Đã lưu baseline vào data/baseline.json")
        return

    baseline = load_json("baseline.json")
    base_score = baseline["score"] if baseline else None
    save_json("alerts.json", {"time": datetime.now(), "score": score,
                              "alerts": [a.to_dict() for a in alerts]})
    reporter.print_console(alerts, score, base_score)
    print(f"Báo cáo HTML: {reporter.write_html(alerts, score, base_score)}")


if __name__ == "__main__":
    main()
