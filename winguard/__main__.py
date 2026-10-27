"""WinGuard - công cụ giám sát và đánh giá bảo mật Windows.

Cách dùng (chạy terminal bằng quyền Administrator):
    python -m winguard --baseline   # lưu trạng thái "bình thường" của máy
    python -m winguard --scan       # quét, so với baseline, xuất báo cáo
"""
import argparse
import sys
from datetime import datetime, timedelta

from winguard import integrity, profiles, reporter, scoring
from winguard.collectors import config, eventlog
from winguard.detectors import (accounts, bruteforce, collector_health, config_audit,
                                evasion, persistence)
from winguard.utils import is_admin, load_json, save_json

EVENT_IDS = [bruteforce.FAILED_LOGON, bruteforce.ACCOUNT_LOCKED,
             accounts.ACCOUNT_CREATED, accounts.MEMBER_ADDED, persistence.TASK_CREATED,
             evasion.LOG_CLEARED]


def scan_start(hours: int | None) -> datetime:
    """Mốc bắt đầu đọc log: --hours nếu có, nếu không thì lần chạy simulator gần nhất
    (để kết quả trước/sau phòng thủ không lẫn vào nhau), mặc định 1 giờ."""
    if hours is None:
        runs = load_json("sim_log.json", [])
        if runs:
            return datetime.fromisoformat(runs[-1]["start"])
        hours = 1
    return datetime.now() - timedelta(hours=hours)


# v1 = bộ luật trước khi vá (chưa có spraying, Event 1102, UNKNOWN, kiểm tra chữ ký baseline)
# v2 = bộ luật hiện tại. Dùng để so sánh "thử né luật" trên CÙNG một bộ log.
RULESETS = ("v1", "v2")


def analyze(hours: int | None, include_events: bool = True,
            since: datetime | None = None, rules: str = "v2",
            profile: str = profiles.DEFAULT_PROFILE):
    new_rules = rules == "v2"
    cfg = config.collect()
    alerts = config_audit.detect(cfg, profile)
    if new_rules:
        alerts += collector_health.detect(cfg)  # collector lỗi -> UNKNOWN (cả baseline lẫn scan)
    if not include_events:
        return cfg, alerts
    events = []
    if is_admin():
        since = since or scan_start(hours)
        print(f"Đọc Security Event Log từ {since:%Y-%m-%d %H:%M:%S} (bộ luật {rules})")
        events = eventlog.query_security(EVENT_IDS, since)
    else:
        print("[CẢNH BÁO] Không chạy bằng quyền Admin -> bỏ qua Security Event Log.", file=sys.stderr)
    baseline = load_json("baseline.json")
    alerts += bruteforce.detect(events, spray=new_rules)
    if new_rules:
        alerts += evasion.detect(events)
        alerts += integrity.check(baseline)  # baseline.json có bị sửa không
    # So sánh baseline vẫn chạy khi không có quyền Admin / log bị xóa
    baseline_cfg = baseline["config"] if baseline else None
    alerts += accounts.detect(events, cfg, baseline_cfg)
    alerts += persistence.detect(events, cfg, baseline_cfg)
    return cfg, alerts


def save_baseline(cfg: dict, score: int) -> None:
    save_json("baseline.json", {"time": datetime.now(), "config": cfg, "score": score,
                                "signature": integrity.sign(cfg)})


def main() -> None:
    parser = argparse.ArgumentParser(prog="winguard", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--baseline", action="store_true", help="lưu trạng thái baseline")
    mode.add_argument("--scan", action="store_true", help="quét và xuất báo cáo")
    parser.add_argument("--hours", type=int,
                        help="số giờ log cần quét (mặc định: từ lần chạy simulator gần nhất, hoặc 1 giờ)")
    parser.add_argument("--rules", choices=RULESETS, default="v2",
                        help="bộ luật: v1 = trước khi vá, v2 = hiện tại (mặc định)")
    parser.add_argument("--profile", choices=sorted(profiles.PROFILES), default=profiles.DEFAULT_PROFILE,
                        help=f"ngưỡng cấu hình (mặc định {profiles.DEFAULT_PROFILE}; "
                             "CIS_WINDOWS_11_ENTERPRISE_V3_L1 = ngưỡng CIS)")
    args = parser.parse_args()

    # Baseline chỉ đo cấu hình; sự kiện tấn công cũ không được tính vào trạng thái "bình thường"
    cfg, alerts = analyze(args.hours, include_events=args.scan, rules=args.rules, profile=args.profile)
    score = scoring.score(alerts)

    if args.baseline:
        save_baseline(cfg, score)
        reporter.print_console(alerts, score)
        print("Đã lưu baseline (đã ký HMAC) vào data/baseline.json")
        return

    baseline = load_json("baseline.json")
    base_score = baseline["score"] if baseline else None
    save_json("alerts.json", {"time": datetime.now(), "score": score,
                              "alerts": [a.to_dict() for a in alerts]})
    reporter.print_console(alerts, score, base_score)
    print(f"Báo cáo HTML: {reporter.write_html(alerts, score, base_score)}")


if __name__ == "__main__":
    main()
