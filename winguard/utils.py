"""Tiện ích dùng chung: chạy lệnh, kiểm tra quyền Admin, đọc/ghi JSON."""
import ctypes
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    """Chạy lệnh console Windows (net, auditpol...). Output dùng bảng mã OEM."""
    # stdin=DEVNULL: lệnh nào hỏi xác nhận sẽ nhận EOF thay vì treo chờ bàn phím
    return subprocess.run(cmd, capture_output=True, text=True, encoding="oem", errors="replace",
                          stdin=subprocess.DEVNULL)


def powershell_json(expr: str):
    """Chạy biểu thức PowerShell và trả kết quả dưới dạng đối tượng Python (qua JSON)."""
    script = (
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
        f"$r = {expr}; ConvertTo-Json -InputObject $r -Depth 4 -Compress"
    )
    r = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    out = r.stdout.strip()
    if r.returncode != 0 or not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def powershell(script: str) -> subprocess.CompletedProcess:
    """Chạy lệnh PowerShell để thực hiện thay đổi (không cần kết quả JSON)."""
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, text=True, encoding="oem", errors="replace",
                          stdin=subprocess.DEVNULL)


def save_json(name: str, obj) -> Path:
    DATA_DIR.mkdir(exist_ok=True)
    path = DATA_DIR / name
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return path


def load_json(name: str, default=None):
    path = DATA_DIR / name
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))
