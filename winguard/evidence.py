"""Luồng xử lý phát hiện cấu hình (kế hoạch v7.2 §2), mỗi bước độc lập:

1. Thu thập thô (collectors)          -> cfg + cfg["_status"]
2. Xác minh dữ liệu đủ để kết luận    -> Finding.missing
3. Phân loại trạng thái               -> CONFIRMED_WEAKNESS / NOT_PRESENT / NEEDS_REVIEW
4. Ánh xạ CWE (chỉ khi đã xác nhận)   -> cwe_map
5. Chọn vector CWSS                   -> cwss_vectors
6. Tính điểm và breakdown             -> cwss
7. Báo cáo                            -> reporter

cwss_vector / breakdown là ĐẦU RA của bước 5-6, không phải điều kiện xác nhận ở bước 2-3.
Bước 5-6 lỗi -> giữ nguyên phát hiện + bằng chứng, ghi scoring_error (không biến thành "không có lỗi").
"""
from dataclasses import dataclass, field

from winguard.models import CONFIRMED_WEAKNESS, NEEDS_REVIEW

NOT_PRESENT = "NOT_PRESENT"


@dataclass
class Finding:
    root_cause: str               # thiết lập cấu hình, VD "firewall"
    key: str                      # duy nhất trong một lần quét, VD "firewall:Public"
    title: str
    status: str = ""              # do classify() đặt
    observed: object = None
    expected: object = None
    profile: str = ""
    source: str = ""              # lệnh / API đã dùng
    raw: object = None
    missing: list = field(default_factory=list)   # lý do dữ liệu chưa đủ
    context: dict = field(default_factory=dict)   # dữ liệu phụ cho bước chọn vector

    def evidence(self) -> dict:
        return {"observed": self.observed, "expected": self.expected, "profile": self.profile,
                "source": self.source, "raw": self.raw, "missing": list(self.missing)}


def classify(finding: Finding, violated: bool | None) -> Finding:
    """Bước 3. violated=None nghĩa là không đủ dữ liệu để biết."""
    if finding.missing or violated is None:
        if not finding.missing:
            finding.missing.append("không đủ dữ liệu để kết luận")
        finding.status = NEEDS_REVIEW
    else:
        finding.status = CONFIRMED_WEAKNESS if violated else NOT_PRESENT
    return finding


def score(finding: Finding, cwe_lookup, build_vector, compute) -> dict:
    """Bước 4-6 cho một phát hiện ĐÃ xác nhận. Không bao giờ ném lỗi ra ngoài:
    lỗi ở bước 5-6 được trả về trong 'scoring_error', CWE và bằng chứng vẫn giữ."""
    if finding.status != CONFIRMED_WEAKNESS:
        raise ValueError(f"chỉ chấm điểm phát hiện đã xác nhận, nhận {finding.status!r}")
    result = {"cwe": "", "cwe_status": "", "cwe_rationale": "", "cwss": {}, "scoring_error": ""}
    ref = cwe_lookup(finding.root_cause)
    if ref:
        result.update(cwe=ref["cwe"], cwe_status=ref["status"], cwe_rationale=ref["rationale"])
    else:
        result["cwe_rationale"] = "chưa có căn cứ ánh xạ CWE cho thiết lập này"
    if compute is None:
        return result
    try:
        vector = build_vector(finding)
        result["cwss"] = {**vector, **compute(vector["vector"])}
    except Exception as exc:  # noqa: BLE001 - lỗi bộ tính không được làm mất phát hiện
        result["scoring_error"] = f"{type(exc).__name__}: {exc}"
        result["cwss"] = {}
    return result
