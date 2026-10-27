"""Ký và kiểm tra toàn vẹn baseline bằng HMAC-SHA256.

Baseline là "sự thật" để so sánh; nếu kẻ tấn công sửa baseline.json thì mọi
phát hiện dựa trên nó đều vô nghĩa. Ta ký nội dung config bằng một khóa bí mật
lưu riêng (data/baseline.key, không đưa lên Git). Khi quét, nếu nội dung không
khớp chữ ký -> báo HIGH; nếu thiếu chữ ký/khóa -> báo UNKNOWN.
"""
import hashlib
import hmac
import json
import secrets

from winguard.attack import label
from winguard.models import NEEDS_REVIEW, Alert
from winguard.utils import DATA_DIR

KEY_FILE = "baseline.key"
MITRE = label("T1565.001")


def _canon(config) -> bytes:
    """Chuẩn hóa config thành bytes ổn định (sort_keys) để ký/kiểm tra nhất quán."""
    return json.dumps(config, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")


def _load_key() -> bytes | None:
    path = DATA_DIR / KEY_FILE
    try:
        return bytes.fromhex(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _create_key() -> bytes:
    DATA_DIR.mkdir(exist_ok=True)
    key = secrets.token_bytes(32)
    (DATA_DIR / KEY_FILE).write_text(key.hex(), encoding="utf-8")
    return key


def sign(config) -> str:
    """Ký config, tạo khóa mới nếu chưa có. Trả về chữ ký HMAC-SHA256 dạng hex."""
    key = _load_key() or _create_key()
    return hmac.new(key, _canon(config), hashlib.sha256).hexdigest()


def verify(baseline: dict) -> bool | None:
    """True: khớp. False: bị sửa. None: chưa ký hoặc mất khóa (không kết luận được)."""
    sig = baseline.get("signature")
    key = _load_key()
    if not sig or key is None:
        return None
    expected = hmac.new(key, _canon(baseline["config"]), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


def check(baseline: dict | None) -> list[Alert]:
    """Trả về cảnh báo về tính toàn vẹn của baseline khi quét."""
    if not baseline:
        return []
    result = verify(baseline)
    if result is True:
        return []
    if result is None:
        return [Alert("UNKNOWN", "Baseline chưa được ký (không kiểm tra được toàn vẹn)",
                      "Thiếu chữ ký HMAC hoặc khóa data/baseline.key.",
                      "Chạy lại: python -m winguard --baseline", MITRE, "config",
                      pillar=NEEDS_REVIEW, root_cause="BASELINE_UNSIGNED",
                      evidence={"review_code": "BASELINE_UNSIGNED"})]
    return [Alert("HIGH", "Baseline đã bị sửa (chữ ký HMAC không khớp)",
                  "Nội dung baseline.json không khớp chữ ký đã lưu -> không còn đáng tin.",
                  "Chạy lại baseline trên máy sạch: python -m winguard --baseline", MITRE, "config",
                  pillar=NEEDS_REVIEW, root_cause="HMAC_MISMATCH",
                  evidence={"review_code": "HMAC_MISMATCH"})]
