"""Simulator - mô phỏng VÔ HẠI các hành vi tấn công để kiểm tra khả năng phát hiện.

Cách dùng (chạy terminal bằng quyền Administrator):
    python -m simulator --list
    python -m simulator --run bruteforce [--attempts 6]
    python -m simulator --cleanup            # dọn dẹp mọi kịch bản
"""
import argparse
import sys
from datetime import datetime

from simulator.scenarios import bruteforce
from winguard.utils import is_admin, load_json, save_json

SCENARIOS = {s.NAME: s for s in [bruteforce]}


def confirm(msg: str, assume_yes: bool) -> bool:
    return assume_yes or input(f"{msg} [y/N]: ").strip().lower() == "y"


def main() -> None:
    parser = argparse.ArgumentParser(prog="simulator", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--list", action="store_true", help="liệt kê kịch bản")
    mode.add_argument("--run", choices=SCENARIOS, help="chạy một kịch bản")
    mode.add_argument("--cleanup", action="store_true", help="hoàn tác mọi kịch bản")
    parser.add_argument("--attempts", type=int, default=6, help="số lần thử (kịch bản bruteforce)")
    parser.add_argument("-y", "--yes", action="store_true", help="không hỏi xác nhận")
    args = parser.parse_args()

    if args.list:
        for s in SCENARIOS.values():
            print(f"{s.NAME:<12} {s.DESCRIPTION}")
        return
    if not is_admin():
        sys.exit("Cần chạy terminal bằng quyền Administrator.")

    if args.cleanup:
        if confirm("Hoàn tác mọi thay đổi của simulator?", args.yes):
            for s in SCENARIOS.values():
                s.cleanup()
        return

    scenario = SCENARIOS[args.run]
    if not confirm(f"Chạy kịch bản '{scenario.NAME}': {scenario.DESCRIPTION}?", args.yes):
        return
    start = datetime.now()
    print(f"[*] Bắt đầu kịch bản {scenario.NAME}")
    result = scenario.run_scenario(args.attempts)
    log = load_json("sim_log.json", [])
    log.append({"scenario": scenario.NAME, "start": start, "end": datetime.now(), "result": result})
    save_json("sim_log.json", log)
    print("[*] Xong. Chạy `python -m winguard --scan` để kiểm tra khả năng phát hiện.")


if __name__ == "__main__":
    main()
