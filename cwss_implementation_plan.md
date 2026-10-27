# Đặc tả Thiết kế & Kế hoạch Triển khai: Hệ thống Đánh giá Bảo mật WinGuard
*(Phiên bản v7.2 — bản sửa 1: Chốt ATT&CK Enterprise v20.0, tách luồng Bằng chứng → Trạng thái → CWE → CWSS, làm rõ phạm vi áp dụng CWSS, nâng độ tin cậy collector Firewall, bổ sung test nhất quán; chốt 3 quyết định: bỏ T1548.002 khỏi cảnh báo UAC, bắt buộc kiểm tra CWSS thủ công bởi người, giữ thứ tự P0 → P8)*

> **Trạng thái tài liệu:** KẾ HOẠCH — **chưa sửa code**. Theo yêu cầu của nhóm, code chỉ được sửa sau khi bản kế hoạch này được duyệt.
> **Mốc repository rà soát:** commit `80fa1c1` (nhánh `main`).
> **Ngày rà soát nguồn ngoài:** 28/10/2026.
> Hạng mục chỉ được đánh dấu hoàn tất theo §14.

---

## 0. Lịch sử Quyết định & Hiện trạng

### 0.1. Lịch sử các quyết định quan trọng

| Phiên bản | Quyết định | Lý do |
| :--- | :--- | :--- |
| v7 | Ba trụ cột: CWSS (cấu hình), Incident Severity (sự kiện), Investigation Priority (sự cố kỹ thuật). | Không trộn thang đo chuẩn ngoài với chỉ số nội bộ. |
| v7 | Allowlist chỉ miễn trừ cảnh báo *tạo* tài khoản. | Không tạo điểm mù đặc quyền. |
| v7.1 | Đặt lại checklist v7 "7/7 hoàn tất" thành *chưa hoàn tất*. | Code chưa có CWSS, Incident Severity, gom cụm, `tests/`. |
| v7.1 | Bỏ ép `Severity = 100.0`; tách `alert_required` khỏi `severity_score`. | Không giả mạo kết quả công thức. |
| v7.1 | Bỏ `entity_sid`; dùng `asset_id`, `actor_sid`, `target_sid`, `member_sid`, `group_sid`, `record_id`. | Trường mơ hồ gây gom cụm sai. |
| v7.1 | Profile mật khẩu `CIS_WINDOWS_11_ENTERPRISE_V3_L1` (14) và `WINGUARD_LAB` (8). | Không trộn chuẩn ngoài với chính sách nội bộ. |
| v7.1 | Metric CWSS chưa kiểm chứng → `UK`. | Không tự chọn giá trị thuận lợi. |
| **v7.2** | **Chốt ATT&CK Enterprise v20.0**; thay T1070.001 → T1685.005, T1562.004 → T1686.003, T1562.001 → T1685 (xem §4). | v19.0 tái cấu trúc Defense Evasion; T1070.001 không còn trong T1070 của v20.0. |
| **v7.2** | Tách luồng 7 bước; `cwss_vector`/`cwss_breakdown` là **đầu ra**, không phải điều kiện xác nhận. | Tránh phát hiện hợp lệ bị đẩy nhầm sang `NEEDS_REVIEW` (lỗi của §2.1 v7.1). |
| **v7.2** | Thêm trạng thái `SCORING_ERROR` (lỗi tính điểm tách khỏi kết luận phát hiện). | Lỗi bộ tính không được xóa phát hiện/bằng chứng. |
| **v7.2** | AI trích công thức + bảng trọng số CWSS v1.0.1 từ tài liệu gốc (kiểm tra thủ công: xem QĐ2). | Điểm phải tái lập được. |
| **v7.2** | Xác định profile Firewall theo **tập** kết nối đang hoạt động; `DomainAuthenticated` → `Domain`. | Máy có nhiều card/kết nối. |
| **v7.2** | Firewall dùng `root\SecurityCenter2` (`FirewallProduct`) cho `IC`; Defender dùng `AntiVirusProduct`. | Thay giả định bằng dữ liệu khi có thể. |
| **v7.2 sửa 1 — QĐ1** | Bỏ `T1548.002` khỏi cảnh báo cấu hình `EnableLUA == 0`; chỉ gắn khi có bằng chứng hành vi bypass UAC. Giữ dạng *ứng viên tham khảo chưa xác nhận* (`attack_candidates`), không hiển thị như kỹ thuật đã phát hiện. CWE-250 vẫn là *đề xuất*. | "UAC đang tắt" là trạng thái cấu hình, không khớp định nghĩa kỹ thuật *Bypass User Account Control*. |
| **v7.2 sửa 1 — QĐ2** | Bắt buộc **một người** đối chiếu trực tiếp trang CWSS v1.0.1 gốc (bảng trọng số + Example 4.1); ghi tên, ngày, kết quả vào `winguard/cwss_weights.py`. Chưa có người kiểm tra → `PENDING`. Example 4.2 là chuẩn chính khi 4.1 chưa giải thích được. | Bản trích bằng công cụ đọc web (do AI thực hiện) **không** thay thế việc con người kiểm tra nguồn. |
| **v7.2 sửa 1 — QĐ3** | Giữ thứ tự P0 → P8. P0 tách *test mô tả hành vi hiện tại* với *test theo đặc tả*; lỗi có sẵn được ghi nhận, không làm yếu/xóa test. | Có mốc regression trước khi thay đổi code. |

### 0.2. Hiện trạng repository (kiểm tra trực tiếp)

| Thành phần | File | Hiện trạng |
| :--- | :--- | :--- |
| Mô hình cảnh báo | `winguard/models.py` | `Alert(severity, title, detail, recommendation, mitre, category, status)`; chưa có CWE, bằng chứng có cấu trúc, breakdown. |
| Điểm /100 | `winguard/scoring.py` | 100 − (HIGH 15, MEDIUM 8, LOW 3, UNKNOWN 5). Quy ước nội bộ (Legacy Score). |
| Luật cấu hình | `detectors/config_audit.py` | Hard-code lockout 0 / > 5, min password < 8; firewall: **mọi** profile tắt → HIGH; gắn `T1562.004`, `T1562.001`, `T1548.002`, `T1110`. |
| Collector cấu hình | `collectors/config.py` | `Get-NetFirewallProfile` (Name, Enabled) — **chưa** đọc `Get-NetConnectionProfile`, `SecurityCenter2`, `PasswordRequired`. Lỗi → `cfg["_errors"]`. |
| Luật sự kiện | `bruteforce.py`, `accounts.py`, `persistence.py`, `evasion.py` | T1110, T1110.003, T1136.001, T1098, T1547.001, T1053.005, **T1070.001** (Event 1102). |
| Toàn vẹn baseline | `integrity.py` | HMAC-SHA256; **T1565.001**. |
| Collector sự kiện | `collectors/eventlog.py` | Giữ `EventID`, `TimeCreated`, `EventData`; **chưa** giữ `Computer`, `EventRecordID`. |
| Benchmark | `simulator/benchmark.py` | 6 kịch bản; chỉ đếm mã ATT&CK của cảnh báo *sự kiện*. |
| CWSS | `winguard/cwss.py` | 1 dòng placeholder. |
| Kiểm thử | — | Chưa có `tests/`. |

**Vị trí đang dùng mã ATT&CK cần sửa** (`grep` toàn repo): `config_audit.py:29` (T1562.004 → T1686.003), `config_audit.py:35` (T1562.001 → T1685), `config_audit.py:43` (T1548.002 → **bỏ**, theo QĐ1), `evasion.py:3,10` (T1070.001 → T1685.005), `integrity.py:17` (T1565.001, giữ nguyên, lấy từ `ATTACK_MAP`). Ngoài repo: báo cáo (Claude Doc) và slide cũng dùng T1070.001 — phải đồng bộ ở bước P8.

---

## 1. Kiến trúc Ba Trụ cột

| Tiêu chí | Trụ cột 1: `CONFIRMED_WEAKNESS` | Trụ cột 2: `ATTACK_OBSERVED` | Trụ cột 3: `NEEDS_REVIEW` |
| :--- | :--- | :--- | :--- |
| **Đối tượng** | Khiếm khuyết cấu hình được chứng minh bằng dữ liệu collector. | Hành vi ghi nhận qua Security Event Log. | Lỗi collector, dữ liệu không đủ để kết luận, baseline bất thường, profile không xác định. |
| **Mã hóa** | **CWE**; ATT&CK chỉ là `related_attack` (tham chiếu, đã xác minh trong `ATTACK_MAP`). Ứng viên chưa xác nhận để ở `attack_candidates`, không hiển thị như kỹ thuật đã phát hiện. | **ATT&CK Enterprise v20.0**. | Mã nội bộ WinGuard. |
| **Thang đo** | MITRE CWSS v1.0.1 — *áp dụng bởi WinGuard* (§3.1). | WinGuard Incident Severity (nội bộ). | WinGuard Investigation Priority (nội bộ). |
| **Tổng hợp** | WinGuard Posture Score (nội bộ). | — | — |

Trạng thái phụ `SCORING_ERROR`: gắn **thêm** vào một phát hiện đã xác nhận khi bộ tính điểm lỗi; phát hiện vẫn giữ trụ cột gốc (§2.3).

| Loại | Thành phần |
| :--- | :--- |
| Chuẩn bên ngoài | MITRE CWSS v1.0.1 (công thức + bảng trọng số), MITRE ATT&CK Enterprise v20.0, CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 |
| Phương pháp áp dụng của WinGuard | Chọn CWE và vector CWSS cho từng cấu hình Windows |
| Chính sách nội bộ | WinGuard Baseline, `WINGUARD_LAB`, Incident Severity, Investigation Priority, Posture Score, Legacy Score |

**Tương thích ngược:** giữ `Alert`, `scoring.score()`, `--rules v1/v2`, `simulator.benchmark`. Trường mới được **thêm** với giá trị mặc định; không đổi chữ ký hàm hiện có.

---

## 2. Luồng Xử lý Bằng chứng → Trạng thái → CWE → CWSS

### 2.1. Bảy bước độc lập

| Bước | Module dự kiến | Đầu vào | Đầu ra | Khi lỗi |
| :--- | :--- | :--- | :--- | :--- |
| 1. Thu thập thô | `collectors/*` | Hệ thống | `raw` + `collector_status` (`ok` / `empty` / `error`) + thông điệp lỗi | Ghi `collector_status=error`, giữ thông điệp; **không** trả rỗng như "an toàn". |
| 2. Xác minh đủ dữ liệu | `evidence.py` | `raw`, profile | `sufficient: bool` + `missing: [lý do]` | — |
| 3. Phân loại trạng thái | `evidence.py` | Bước 2 | `CONFIRMED_WEAKNESS` / `NOT_PRESENT` / `NEEDS_REVIEW` | Thiếu dữ liệu → `NEEDS_REVIEW` kèm `raw` + `missing`. |
| 4. Ánh xạ CWE | `cwe_map.py` | Chỉ phát hiện `CONFIRMED_WEAKNESS` | `cwe` + `cwe_rationale` | Không có căn cứ → `cwe = None`, vẫn giữ phát hiện, ghi lý do. |
| 5. Chọn vector | `cwss_vectors.py` | CWE, threat model, dữ liệu | `cwss_vector` + `metric_sources` (`collected` / `assumed` / `unknown`) + `rationale` | Không chọn được → `SCORING_ERROR`. |
| 6. Tính điểm | `cwss.py` | Vector | `base`, `attack_surface`, `environmental`, `score` | Lỗi → `SCORING_ERROR`, `score = None`. |
| 7. Báo cáo | `reporter.py` | Tất cả trên | Console / HTML / JSON | — |

### 2.2. Phân loại trường

| Loại | Trường | Bắt buộc ở bước |
| :--- | :--- | :--- |
| **Đầu vào xác nhận** | `observed_state`, `expected_state`, `profile`, `evidence.source` (lệnh/API), `evidence.raw`, `collector_status` | Bước 2–3 |
| **Tham chiếu sau xác nhận** | `cwe`, `cwe_status` (`proposed` / `verified`), `cwe_rationale`, `related_attack`, `attack_candidates` | Bước 4 (không ảnh hưởng xác nhận) |
| **Đầu ra bộ tính** | `cwss_vector`, `metric_sources`, `rationale`, `base`, `attack_surface`, `environmental`, `score`, `scoring_error` | Bước 5–6 (**không** là điều kiện xác nhận) |

> Sửa lỗi v7.1 §2.1: v7.1 yêu cầu `cwss_vector`, `cwss_breakdown` để xác nhận phát hiện — sai vì đó là đầu ra của bước sau.

### 2.3. Quy tắc nhánh
- **Thiếu dữ liệu xác nhận:** không kết luận; giữ `raw` + `missing`; trạng thái `NEEDS_REVIEW`.
- **Collector lỗi:** `NEEDS_REVIEW` (điểm mù), không bao giờ `NOT_PRESENT`.
- **Đủ bằng chứng nhưng bộ tính CWSS lỗi:** giữ `CONFIRMED_WEAKNESS` + bằng chứng + CWE; thêm `scoring_error`; `score = None`; báo cáo ghi "chưa tính được điểm"; đưa một mục `SCORING_ERROR` vào trụ cột 3. Posture Score khi có `SCORING_ERROR` → hiển thị "không xác định" kèm danh sách phát hiện chưa có điểm, không lặng lẽ bỏ qua.
- **Có CWE nhưng không có vector phù hợp:** như trên.

### 2.4. Kiểm thử luồng (`tests/test_evidence_pipeline.py`)
Đủ bằng chứng + vi phạm → `CONFIRMED_WEAKNESS` + có điểm; đủ bằng chứng + đạt → `NOT_PRESENT`; thiếu trường → `NEEDS_REVIEW` (giữ `raw`, `missing`); collector `error` / `empty` → `NEEDS_REVIEW`; bộ tính ném lỗi (giả lập) → phát hiện + bằng chứng còn nguyên, `scoring_error` có, `score = None`; không có CWE → phát hiện vẫn còn.

---

## 3. MITRE CWSS v1.0.1

### 3.1. Phạm vi áp dụng
- CWSS được thiết kế để chấm **điểm yếu phần mềm** (CWE). Việc dùng CWSS để chấm **cấu hình Windows** là **phương pháp áp dụng của WinGuard**, dựa trên CWE và threat model công bố trong tài liệu này.
- MITRE **không** chứng nhận các vector hay điểm do WinGuard chọn. Báo cáo ghi: *"Điểm tính theo công thức MITRE CWSS v1.0.1; vector do WinGuard lựa chọn."*
- Không đổi metric hay trọng số để tạo điểm mong muốn.

### 3.2. Trích nguồn bởi AI (28/10/2026) — chưa kiểm tra thủ công
- **Nguồn:** https://cwe.mitre.org/cwss/cwss_v1.0.1.html
- **Công thức** (khớp v7.1):
  - $\text{Base} = [(10\,TI + 5(AP+AL) + 5\,FC) \cdot f(TI) \cdot IC] \cdot 4$; $f(TI)=0$ nếu $TI=0$, ngược lại 1.
  - $\text{AS} = [20(RP+RL+AV) + 20\,SC + 15\,IN + 5\,AS_{auth}] / 100$.
  - $\text{Env} = [(10\,BI + 3\,DI + 4\,EX + 3\,P) \cdot f(BI) \cdot EC] / 20$; $f(BI)=0$ nếu $BI=0$.
  - $\text{CWSS} = \text{Base} \times \text{AS} \times \text{Env}$, thang 0–100.
- **Bảng trọng số** đã trích (lưu nguyên vào `winguard/cwss_weights.py` kèm URL + ngày). Các giá trị dùng trong tài liệu này:

| Metric | Giá trị (mã: trọng số) |
| :--- | :--- |
| TI / BI | C 1.0, H 0.9, M 0.6, L 0.3, N 0.0, D 0.6, UK 0.5, NA 1.0 |
| AP | A 1.0, P 0.9, RU 0.7, L 0.6, N 0.1, D 0.7, UK 0.5, NA 1.0 |
| AL / RL | A 1.0, S 0.9, N 0.7, E 1.0, D 0.9, UK 0.5, NA 1.0 |
| IC | N 1.0, L 0.9, M 0.7, I 0.5, B 0.3, C 0.0, D 0.6, UK 0.5, NA 1.0 |
| EC | N 1.0, L 0.9, M 0.7, I 0.5, B 0.3, C 0.1, D 0.6, UK 0.5, NA 1.0 |
| FC | T 1.0, LT 0.8, F 0.0, D 0.8, UK 0.5, NA 1.0 |
| RP | N 1.0, L 0.9, RU 0.7, P 0.6, A 0.1, D 0.7, UK 0.5, NA 1.0 |
| AV | I 1.0, R 0.8, V 0.8, A 0.7, L 0.5, P 0.2, D 0.75, **U** 0.5, NA 1.0 |
| AS (auth) | S 0.7, M 0.8, W 0.9, N 1.0, D 0.85, UK 0.5, NA 1.0 |
| IN | A 1.0, T 0.9, M 0.8, O 0.3, H 0.1, NI 0.0, D 0.55, UK 0.5, NA 1.0 |
| SC | A 1.0, M 0.9, R 0.5, P 0.1, D 0.7, UK 0.5, NA 1.0 |
| DI | H 1.0, M 0.6, L 0.2, D 0.6, UK 0.5, NA 1.0 |
| EX | H 1.0, M 0.6, L 0.2, N 0.0, D 0.6, UK 0.5, NA 1.0 |
| P | W 1.0, H 0.9, C 0.8, L 0.7, D 0.85, UK 0.5, NA 1.0 |

  Lưu ý: AV dùng mã Unknown là `U` (không phải `UK`) theo tài liệu; parser phải chấp nhận đúng mã của từng metric.

- **Ví dụ chuẩn:**

| Ví dụ | Base | AS | Env | Điểm tài liệu | Tính lại | Kết luận |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| 4.2 (Wiki) | 84.0 | 0.935 | 0.65 | 51.1 | 51.1 | **Khớp** |
| 4.1 (Business-critical) | 96.0 | 0.965 | 1.0 | 92.6 | 92.6 nếu BI = C = **1.0**; 88.0 nếu BI = 0.9 | **Chưa giải thích — chờ kiểm tra thủ công (§3.2a)**: bản trích vector ghi "BI:C,0.9" nhưng Env = 1.0 chỉ đúng khi BI = 1.0 |

  Ví dụ 4.2 có thêm `RE:NA` (không phải metric của CWSS 1.0) — parser bỏ qua `RE` có cảnh báo, không lỗi.
- **Trạng thái xác minh: `PENDING`.** Công thức và bảng trọng số ở trên do AI trích bằng công cụ đọc web ngày 28/10/2026. Đây **không** phải kiểm tra thủ công và không được ghi là đã xác minh.

### 3.2a. Kiểm tra thủ công bắt buộc (QĐ2)
- **Người kiểm tra:** một thành viên nhóm, tự mở trang https://cwe.mitre.org/cwss/cwss_v1.0.1.html và đối chiếu. AI chỉ chuẩn bị checklist và ghi lại kết quả người kiểm tra báo; AI **không** điền tên ai và không tự nhận đã kiểm tra.
- **Checklist cho người kiểm tra:**
  1. Ba công thức Base / Attack Surface / Environmental và công thức cuối khớp §3.2.
  2. Từng dòng bảng trọng số §3.2 khớp bảng gốc (đặc biệt mã Unknown của AV là `U` hay `UK`).
  3. Example 4.1: chép nguyên văn vector, ba subscore và điểm cuối; ghi giá trị BI trong vector (`0.9` hay `1.0`) và Environmental (`1.0` hay `0.95`).
  4. Example 4.2: chép nguyên văn vector, ba subscore, điểm cuối; ghi cách tài liệu xử lý `RE:NA`.
  5. Chụp màn hình bảng trọng số và hai ví dụ, lưu vào `docs/audit/` (không đưa dữ liệu cá nhân), ghi đường dẫn vào các trường `screenshot` / `weight_table_screenshots`.
- **Ghi kết quả** vào `winguard/cwss_weights.py`:
  ```python
  CWSS_SOURCE = "https://cwe.mitre.org/cwss/cwss_v1.0.1.html"
  CWSS_EXTRACTED = {"by": "AI (công cụ đọc web)", "date": "2026-10-28"}
  CWSS_MANUAL_CHECK = {
      "status": "PENDING",        # PENDING | VERIFIED | DISCREPANCY
      "reviewer": "PENDING",      # tên người thật đã mở trang gốc
      "date": "PENDING",          # YYYY-MM-DD
      "source_url": "https://cwe.mitre.org/cwss/cwss_v1.0.1.html",
      "formulas": "PENDING",      # MATCH | MISMATCH + mô tả (checklist mục 1)
      "weight_table": "PENDING",  # MATCH | MISMATCH + danh sách dòng lệch (mục 2)
      "example_4_1": {            # checklist mục 3
          "status": "PENDING",    # MATCH | DISCREPANCY
          "vector_as_published": "PENDING",
          "base": "PENDING", "attack_surface": "PENDING",
          "environmental": "PENDING", "score": "PENDING",
          "bi_value_in_vector": "PENDING",
          "screenshot": "PENDING",  # VD docs/audit/cwss_example_4_1.png
      },
      "example_4_2": {            # checklist mục 4
          "status": "PENDING",
          "vector_as_published": "PENDING",
          "base": "PENDING", "attack_surface": "PENDING",
          "environmental": "PENDING", "score": "PENDING",
          "re_handling": "PENDING",  # tài liệu xử lý RE:NA thế nào
          "screenshot": "PENDING",   # VD docs/audit/cwss_example_4_2.png
      },
      "weight_table_screenshots": [],  # đường dẫn ảnh bảng trọng số
      "notes": "",
  }
  ```
- `status = "VERIFIED"` chỉ hợp lệ khi `reviewer`, `date`, `formulas`, `weight_table`, `example_4_2.status` đều khác `PENDING` và mỗi ví dụ có `screenshot` trỏ tới file tồn tại. Test `test_cwss.py` kiểm tra ràng buộc này.
- **Example 4.1:** **không** sửa dữ liệu nguồn để ép kết quả khớp. Nếu người kiểm tra xác nhận vector ghi `BI:C,0.9` trong khi Env = 1.0, ghi `DISCREPANCY` kèm mô tả; test 4.1 khi đó chỉ kiểm tra *mâu thuẫn được ghi nhận*, không dùng làm chuẩn.
- **Example 4.2** là test chuẩn chính cho tới khi 4.1 được giải thích.
- Điểm CWSS trong báo cáo chỉ được ghi *"đã xác minh"* khi `CWSS_MANUAL_CHECK.status == "VERIFIED"`; nếu `PENDING`/`DISCREPANCY`, báo cáo ghi *"bảng trọng số chưa được kiểm tra thủ công"*.

### 3.3. Quy tắc Unknown (công bố)
- Mỗi metric có `metric_sources[m] ∈ {collected, assumed, unknown}` và `rationale[m]`.
- `collected`: có dữ liệu collector cụ thể. `assumed`: giả định threat model ghi rõ (VD "kẻ tấn công cùng mạng LAN"). `unknown`: không kiểm chứng được → mã `UK` (AV: `U`) = 0.5.
- **Không** dùng `D` (Default) để thay `UK` khi lý do là thiếu dữ liệu.
- Không chọn giá trị thuận lợi để tăng/giảm điểm.

### 3.4. Vector áp dụng v7.2 (điểm *ước tính* — kết quả chính thức do code + test sinh ra)

| Điểm yếu | CWE (đề xuất) | Metric khác v7 | Base | AS | Env | CWSS v7 | **CWSS v7.2** |
| :--- | :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| Firewall profile active tắt | CWE-284 *(ứng viên CWE-693)* | `IC` = N chỉ khi SecurityCenter2 xác nhận không có firewall khác (lỗi → UK); `EC` = UK (firewall biên/NAT không kiểm chứng) | 88.0 | 0.920 | 0.475 | 76.9 | **38.5** |
| Lockout = 0 | CWE-307 | `EC` = UK | 76.0 | 0.915 | 0.400 | 55.6 | **27.8** |
| Min password < ngưỡng profile | CWE-521 | `EC` = UK | 68.4 | 0.915 | 0.400 | 50.1 | **25.0** |
| Defender RTP tắt + SecurityCenter2 xác nhận không có AV khác | CWE-693 | `EC` = N (collected) | 94.0 | 0.845 | 0.950 | 75.5 | **75.5** |
| UAC tắt | CWE-250 *(đề xuất, chưa xác minh)* | `EC` = UK (AppLocker/WDAC không kiểm chứng) | 94.0 | 0.820 | 0.475 | 73.2 | **36.6** |
| Mật khẩu rỗng (Admin) | CWE-258 | Không bật mặc định (§8) | — | — | — | 78.6 | — |

Ghi chú: điểm giảm mạnh vì `UK` = 0.5 là trọng số chính thức; đây là hệ quả của việc **không giả định** chứ không phải chỉnh để ra điểm thấp. Nếu Firewall có SecurityCenter2 lỗi thì `IC` = UK → Base = 44.0, CWSS ≈ 19.2.

---

## 4. MITRE ATT&CK — chốt Enterprise v20.0

### 4.1. Phiên bản & nguồn
- **`ATTACK_VERSION = "Enterprise v20.0"`**, phát hành 13/10/2026 (trang *attack.mitre.org/resources/versions* ghi là bản hiện hành).
- **Ngày xác minh:** 28/10/2026, do AI đối chiếu bằng công cụ đọc web trên trang kỹ thuật attack.mitre.org và changelog v18.1 → v19.0. Cột "Trạng thái xác minh" ở §4.2 mang nghĩa này; xác minh cuối cùng bằng STIX ở P1 (khác với CWSS, ATT&CK được kiểm lại tự động bằng dữ liệu máy đọc).
- **Nguồn dữ liệu máy đọc dùng khi code:** bản STIX `ATT&CK-v20.0` tại https://github.com/mitre/cti/releases/tag/ATT%26CK-v20.0 — ghi checksum file vào `winguard/attack.py`. Test mapping đọc ID từ bảng tĩnh `ATTACK_MAP`, không tải mạng khi chạy test.
- Thay đổi cấu trúc quan trọng (v19.0): tactic *Defense Evasion* được tách; xuất hiện tactic **Defense Impairment (TA0112)** và tactic **Stealth** (ví dụ T1070 nay thuộc Stealth). Mã TA của Stealth **chưa xác minh**.

### 4.2. `ATTACK_MAP` (kết quả đối chiếu)

| Dùng trong WinGuard | Mã cũ trong code | **Mã v20.0** | Tên v20.0 | Tactic v20.0 | Có Windows | Trạng thái xác minh |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- |
| Brute force | T1110 | **T1110** | Brute Force | Credential Access (TA0006) | ✔ | Đã xác minh, v2.8 |
| Password spraying | T1110.003 | **T1110.003** | Password Spraying | Credential Access (TA0006) | ✔ | Đã xác minh, v1.8 |
| Tạo tài khoản | T1136.001 | **T1136.001** | Create Account: Local Account | Persistence | ✔ | Đã xác minh, v1.5 |
| Thêm vào Administrators | T1098 | **T1098** | Account Manipulation | Persistence (TA0003), Privilege Escalation (TA0004) | ✔ | Đã xác minh, v2.8 |
| Run key | T1547.001 | **T1547.001** | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation | ✔ | Đã xác minh, v2.1 |
| Scheduled Task | T1053.005 | **T1053.005** | Scheduled Task | Execution, Persistence, Privilege Escalation | ✔ | Đã xác minh, v1.8 |
| Event 1102 | T1070.001 | **T1685.005** | Disable or Modify Tools: Clear Windows Event Logs | Defense Impairment (TA0112) | ✔ | Đã xác minh, v1.0 (tạo 14/04/2026). T1070.001 **không còn** trong danh sách sub-technique của T1070 (v3.0). |
| Firewall tắt (`related_attack`) | T1562.004 | **T1686.003** | Disable or Modify System Firewall: Windows Host Firewall | Defense Impairment | ✔ | Đã xác minh, T1686 v1.0 |
| Defender tắt (`related_attack`) | T1562.001 | **T1685** | Disable or Modify Tools | Defense Impairment (TA0112) | ✔ | Đã xác minh T1685. Changelog thay liên kết T1562/001 → T1685; **chưa thấy** thông báo `revoked-by` chính thức. Không dùng T1685.007 khi chưa đọc định nghĩa. |
| UAC tắt (`EnableLUA == 0`) | T1548.002 | **— (không gắn)** | — | — | — | **QĐ1:** bỏ khỏi mapping trực tiếp. Cảnh báo là trạng thái cấu hình, không phải hành vi bypass. |
| *(Dự phòng)* Hành vi bypass UAC | — | **T1548.002** | Abuse Elevation Control Mechanism: Bypass User Account Control | Privilege Escalation (TA0004) | ✔ | Đã xác minh ID/tên, v3.0. **Chỉ** gắn khi có bằng chứng hành vi bypass khớp định nghĩa kỹ thuật. Chưa có detector. |
| Baseline bị sửa | T1565.001 | **T1565.001** | Data Manipulation: Stored Data Manipulation | Impact (TA0040) | ✔ | Đã xác minh, v1.1 |
| (Dự phòng) Tắt ghi log | — (v7.1 ghi T1562.002) | **T1685.001** | Disable or Modify Windows Event Log | Defense Impairment | ✔ | Đã xác minh tên/ID. Chưa có detector. |

**Còn phải xác minh bằng STIX khi code:** quan hệ `revoked-by` chính thức của T1070.001, T1562.001, T1562.002, T1562.004; mã TA của Stealth. Nếu STIX cho kết quả khác bảng trên → cập nhật bảng trước rồi mới sửa code.

### 4.2a. Ứng viên tham khảo chưa xác nhận (`ATTACK_CANDIDATES`)
- Bảng riêng, tách khỏi `ATTACK_MAP`; mỗi mục có `technique`, `reason`, `status = "unconfirmed"`.
- Mục dự kiến (chưa có trong code): cảnh báo UAC tắt → `{"technique": "T1548.002", "reason": "UAC tắt làm giảm rào cản nâng quyền; chưa có bằng chứng hành vi bypass", "status": "unconfirmed"}`.
- Báo cáo: **không** in ứng viên trong cột/nhãn ATT&CK; nếu hiển thị, chỉ ở phần chi tiết với nhãn *"Ứng viên tham khảo — chưa phát hiện hành vi"*.
- Benchmark và test nhất quán **không** đếm ứng viên là kỹ thuật được phát hiện.

### 4.3. Mapping lịch sử
- Lưu riêng trong `ATTACK_LEGACY` (metadata), **không** dùng cho kết quả hiện hành:
  `{"T1070.001": "T1685.005", "T1562.004": "T1686.003", "T1562.001": "T1685", "T1562.002": "T1685.001"}` kèm ghi chú "≤ v18.1".
- Dữ liệu cũ (`data/alerts.json`, báo cáo/slide đã nộp) giữ nguyên; khi đọc lại, hiển thị dạng "T1070.001 (≤ v18.1) → T1685.005 (v20.0)".
- Kết quả mới **không bao giờ** chứa mã trong `ATTACK_LEGACY`.

### 4.4. Đồng bộ
`evasion.py`, `config_audit.py` (đổi mã firewall/Defender, **bỏ** T1548.002 khỏi cảnh báo UAC), `integrity.py` (lấy mã từ `ATTACK_MAP`), `simulator/benchmark.py` (`EXPECTED` dùng mã từ `ATTACK_MAP`), `reporter.py`, `alerts.json`/`benchmark.json` (thêm `attack_version`), README, báo cáo, slide, test.

### 4.5. Kiểm thử (`tests/test_attack_mapping.py`)
Event 1102 → T1685.005; mọi mã detector sinh ra ∈ `ATTACK_MAP`; không mã nào ∈ `ATTACK_LEGACY`; sự kiện tắt ghi log (giả lập) → T1685.001, không phải T1685.005, và ngược lại; mỗi mục `ATTACK_MAP` có tên, tactic, nền tảng chứa Windows; cảnh báo `EnableLUA == 0` có `related_attack` rỗng và không chứa T1548.002 trong trường ATT&CK; T1548.002 chỉ xuất hiện ở `attack_candidates` với `status = "unconfirmed"`; không mục `ATTACK_CANDIDATES` nào được tính là kỹ thuật phát hiện.

---

## 5. Trụ cột 2: WinGuard Incident Severity (nội bộ)

$$\text{Incident Severity} = 100 \times T \times C \times W$$

> Công thức **nội bộ WinGuard**, không phải của MITRE. Trọng số là quy tắc nội bộ, **chưa hiệu chỉnh thực nghiệm**.

### 5.1. Miền & làm tròn
- $T, C, W \in (0, 1]$; ngoài miền/thiếu → `ValueError`.
- Kết quả $\in [0, 100]$; làm tròn 1 chữ số, `ROUND_HALF_UP`, thống nhất mọi đầu ra.
- 100 chỉ khi $T = C = W = 1.0$ theo bằng chứng; không có nhánh gán thẳng 100.
- `score_breakdown = {T, C, W, lý do, event_ids, record_ids}`.

### 5.2. Hệ số
- **$T$** (mức nghiêm trọng hành vi): 1.00 thay đổi Administrators; 0.90 xóa Security Log; 0.75 Run key/Scheduled Task; 0.60 brute force/spraying.
- **$C$** (độ tin cậy bằng chứng/tương quan — *không phải* ý đồ): 1.00 chuỗi tương quan đầy đủ + baseline diff; 0.95 một nguồn xác nhận đầy đủ trường (VD 1102); 0.80 vượt ngưỡng heuristic; 0.60 thiếu SID/mâu thuẫn → `unverified`.
- **$W$** (tactic của hành vi quan sát được, theo `ATTACK_MAP` v20.0):

| Tactic | Kỹ thuật | $W$ |
| :--- | :--- | :---: |
| Privilege Escalation | T1098 (vào Administrators) | 1.00 |
| Defense Impairment | T1685.005 | 0.90 |
| Persistence | T1136.001, T1547.001, T1053.005 | 0.85 |
| Credential Access | T1110, T1110.003 | 0.75 |

  Kỹ thuật nhiều tactic → chọn tactic khớp bằng chứng, ghi lý do.

### 5.3. Bảng ví dụ (kết quả thật do test sinh)

| Chuỗi | ATT&CK v20.0 | $T$ | $C$ | $W$ | Severity |
| :--- | :--- | :---: | :---: | :---: | :---: |
| 4720 + 4732 cùng SID, Administrators, ≤ 300 s, khớp baseline | T1136.001 → T1098 | 1.00 | 1.00 | 1.00 | 100.0 |
| Chỉ 4732 vào Administrators | T1098 | 1.00 | 0.95 | 1.00 | 95.0 |
| 4732 thiếu `MemberSid` | T1098 | 1.00 | 0.60 | 1.00 | 60.0 (`unverified`) |
| Event 1102 | T1685.005 | 0.90 | 0.95 | 0.90 | 77.0 |
| Run key / Task (event + baseline) | T1547.001 / T1053.005 | 0.75 | 1.00 | 0.85 | 63.8 |
| Brute force / spraying | T1110 / T1110.003 | 0.60 | 0.80 | 0.75 | 36.0 |

**Test (`tests/test_incident_severity.py`):** hệ số biên; 0 / > 1 → lỗi; 100; half-up (63.75 → 63.8, 76.95 → 77.0); thiếu bằng chứng; mâu thuẫn; chuỗi một sự kiện.

---

## 6. Gom cụm Sự kiện (Asset-Aware)

| Trường | Ý nghĩa | Nguồn |
| :--- | :--- | :--- |
| `asset_id` | Máy | `System/Computer` (phải thêm vào `eventlog.parse_event`) |
| `actor_sid` | Chủ thể | `SubjectUserSid` |
| `target_sid` | Tài khoản bị tạo (4720) | `TargetSid` |
| `member_sid` | Thành viên được thêm (4732) | `MemberSid` |
| `group_sid` | Nhóm bị đổi (4732) | `TargetSid` |
| `event_id`, `record_id`, `timestamp` | — | `EventID`, `EventRecordID`, `TimeCreated` |
| `root_cause_id` | Chuỗi, chỉ khi đủ căn cứ | hash(`asset_id`, `target_sid`, thời điểm đầu) |

- Ghép 4720 ↔ 4732 khi cùng `asset_id`, `target_sid == member_sid`, `group_sid == S-1-5-32-544`, $|\Delta t| \le$ `CORRELATION_WINDOW_S` (mặc định 300).
- SID là khóa; username chỉ hiển thị. Sắp theo thời gian trước khi ghép; khử trùng theo (`asset_id`, `record_id`); thiếu SID → không ghép, `unverified`, vẫn cảnh báo.
- Phạm vi: chạy **một máy**; đa máy chỉ kiểm thử bằng dữ liệu tổng hợp.

**Test (`tests/test_clustering.py`):** hai máy cùng username; hai tài khoản cùng máy; cùng tài khoản hai máy; sai thứ tự; trùng; thiếu SID; ngoài cửa sổ.

---

## 7. Allowlist & Quyền Quản trị

- Allowlist chỉ miễn trừ cảnh báo **tạo** tài khoản (đúng như code hiện tại).
- Mọi lần thêm vào Administrators → cảnh báo T1098; `alert_required = True` (quy tắc nội bộ `PRIVILEGED_GROUP_CHANGE`); `severity_score` tính theo §5, nhãn không ghi đè điểm.
- Không xác minh được chủ thể/đích/nhóm → giữ sự kiện, $C = 0.60$, `unverified`, thêm mục `NEEDS_REVIEW`.
- Nhóm không đặc quyền: ngoài phạm vi hiện tại (chỉ theo dõi `S-1-5-32-544`).

**Test (`tests/test_allowlist.py`):** tạo tài khoản allowlist / không allowlist; thêm allowlist vào Administrators; thêm không allowlist vào Administrators; thêm vào nhóm không đặc quyền; 4732 thiếu bằng chứng.

---

## 8. Profile Ngưỡng Mật khẩu

| Profile | `min_password_length` | Nguồn | Ghi chú |
| :--- | :---: | :--- | :--- |
| `CIS_WINDOWS_11_ENTERPRISE_V3_L1` | 14 | CIS Windows 11 Enterprise v3.0.0, Rec. 1.1.4 (L1) | Số hiệu cần đối chiếu PDF CIS. |
| `WINGUARD_LAB` | 8 | Nội bộ | Không gọi là CIS-compliant. |

- Profile chọn bằng `--profile` hoặc file cấu hình; thiếu/sai → `NEEDS_REVIEW` "profile chưa xác định", không đoán.
- Vi phạm khi `observed < threshold`. Tiêu đề sinh từ ngưỡng thực.
- Lockout cũng chuyển vào profile; giá trị CIS phải đối chiếu.
- `PasswordRequired=False` → `NEEDS_REVIEW`, không gán CWE-258 (collector phải bổ sung thuộc tính).
- `EMPTY_PASSWORD_CONFIRMED` (CWE-258): không bật mặc định; chỉ lab được ủy quyền, cờ riêng, một lần mỗi tài khoản.

**Test (`tests/test_password_profile.py`):** 7/8/9 (Lab); 13/14/15 (CIS); thiếu/sai profile; báo cáo hiển thị profile + ngưỡng.

---

## 9. Collector & Kết luận cho Firewall, UAC, Defender

### 9.1. Firewall — thu thập
- `Get-NetFirewallProfile` → `{Domain, Private, Public: Enabled}`.
- `Get-NetConnectionProfile` → danh sách kết nối `{InterfaceAlias, InterfaceIndex, NetworkCategory, IPv4Connectivity, IPv6Connectivity}`.
- `root\SecurityCenter2` → `FirewallProduct` (tên, trạng thái) để xác định có firewall khác đăng ký với Windows Security Center hay không.

### 9.2. Ánh xạ NetworkCategory → profile

| `NetworkCategory` | Profile Firewall |
| :--- | :--- |
| `DomainAuthenticated` | `Domain` |
| `Private` | `Private` |
| `Public` | `Public` |
| Giá trị khác / rỗng | **Không ánh xạ được** → `NEEDS_REVIEW` |

### 9.3. Quy tắc kết luận
- **Tập profile active** = hợp các profile ánh xạ từ **mọi** kết nối. Không chọn một profile duy nhất khi có nhiều kết nối.
- Với mỗi profile active có `Enabled == False` và profile yêu cầu bật → `CONFIRMED_WEAKNESS` riêng (cùng `root_cause = firewall` khi tính Posture).
- Profile tắt nhưng **không** active → `NEEDS_REVIEW` mức thấp (rủi ro khi đổi mạng), không tính CWSS.
- `Get-NetConnectionProfile` rỗng (không có kết nối) → không kết luận vi phạm; ghi "không có kết nối mạng đang hoạt động" + giữ trạng thái profile.
- Một trong hai lệnh lỗi → `NEEDS_REVIEW`, giữ dữ liệu của lệnh còn lại.
- Có kết nối không ánh xạ được → các profile ánh xạ được vẫn đánh giá bình thường; kết nối lạ → `NEEDS_REVIEW`.
- Mô tả: *"Lớp lọc lưu lượng của Windows Firewall cho profile X (đang dùng bởi kết nối Y) đang tắt; dịch vụ đang lắng nghe có thể tiếp nhận kết nối nếu không có lớp lọc khác."* Không nói "mọi cổng đã mở".

**Test (`tests/test_firewall.py`):** Domain/Private/Public active + tắt; nhiều kết nối (Private + Public, một tắt); không kết nối; `Get-NetConnectionProfile` lỗi; `Get-NetFirewallProfile` lỗi; dữ liệu rỗng; `NetworkCategory` lạ; profile tắt nhưng không active; SecurityCenter2 lỗi → `IC` = UK.

### 9.4. UAC
`EnableLUA == 0` → `CONFIRMED_WEAKNESS` (nhóm điểm yếu cấu hình), mô tả *"UAC bị vô hiệu hóa: Admin Approval Mode tắt; tài khoản Administrators chạy với token đầy đủ không cần xác nhận; một số cơ chế bảo vệ liên quan bị suy yếu."* Không kết luận Standard User có quyền quản trị. Registry đọc lỗi → `NEEDS_REVIEW`.
- CWE: **CWE-250, `cwe_status = "proposed"`** (chưa tuyên bố đã xác minh).
- ATT&CK: **không gắn** kỹ thuật (QĐ1); T1548.002 chỉ là ứng viên trong `attack_candidates`.

### 9.5. Defender
RTP tắt **và** `SecurityCenter2.AntiVirusProduct` đọc thành công **và** không có AV khác active → `CONFIRMED_WEAKNESS`. RTP tắt nhưng có AV khác → không phải điểm yếu (ghi INFO). WMI lỗi/không xác định → `NEEDS_REVIEW`. Khả năng đọc SecurityCenter2 trên Windows 11 Home phải chạy thử.

---

## 10. Trụ cột 3: Investigation Priority (nội bộ)

$$\text{Priority} = 100 \times \text{OperationalImpact} \times \text{UncertaintyMultiplier}$$

| Tình huống | Impact | Uncertainty | Priority |
| :--- | :---: | :---: | :---: |
| HMAC baseline không khớp | 0.80 | 1.0 | 80.0 |
| Sự kiện đặc quyền `unverified` | 0.70 | 1.0 | 70.0 |
| Baseline chưa ký / mất khóa | 0.60 | 1.0 | 60.0 |
| `PasswordRequired=False` | 0.60 | 1.0 | 60.0 |
| `SCORING_ERROR` | 0.60 | 1.0 | 60.0 |
| Collector lỗi | 0.50 | 1.0 | 50.0 |
| Profile ngưỡng chưa xác định / NetworkCategory lạ | 0.50 | 1.0 | 50.0 |
| Profile firewall tắt nhưng không active | 0.30 | 1.0 | 30.0 |

Quy tắc nội bộ, chưa hiệu chỉnh thực nghiệm. **Không phải điểm MITRE.**

---

## 11. WinGuard Posture Score (nội bộ)

$$\text{Posture} = \max\left(0,\ 100 - \text{Peak CWSS} - 0.1 \times \sum_{k \in \text{cụm độc lập còn lại}} \text{CWSS}_k\right)$$

- Không phải điểm MITRE CWSS.
- Cụm = một `root_cause` (thiết lập cấu hình); nhiều profile firewall tắt → một cụm (lấy CWSS cao nhất).
- Có `SCORING_ERROR` trong phát hiện xác nhận → Posture = "không xác định" + danh sách.
- Ví dụ minh họa với điểm ước tính §3.4 (firewall active tắt, lockout 0, min password 0, profile Lab):
  $100 - 38.5 - 0.1 \times (27.8 + 25.0) = 56.22 \to 56.2$.

**Test (`tests/test_posture.py`):** không phát hiện → 100; một; nhiều độc lập; cùng nguyên nhân gốc; chặn 0; ∈ [0, 100]; có `SCORING_ERROR`.

---

## 12. Kiểm thử Tính nhất quán (`tests/test_consistency.py`)

| # | Kiểm tra |
| :---: | :--- |
| 1 | Mọi ATT&CK ID xuất hiện trong console/HTML/JSON ∈ `ATTACK_MAP` (v20.0). |
| 2 | Không ID nào ∈ `ATTACK_LEGACY` trong kết quả hiện hành. |
| 3 | `profile` in trong báo cáo == profile detector đã dùng. |
| 4 | `cwss.score` == Base × AS × Env tính độc lập từ `cwss_vector` + `cwss_weights`. |
| 5 | Incident Severity, Investigation Priority, Posture, Legacy Score luôn kèm nhãn "nội bộ WinGuard"; không xuất hiện cạnh chữ "MITRE". |
| 6 | Phát hiện `NEEDS_REVIEW` không nằm trong mục `CONFIRMED_WEAKNESS`. |
| 7 | Console, HTML, JSON cùng tập phát hiện, cùng điểm, cùng bằng chứng (so khớp theo `id`). |
| 8 | Collector lỗi không bao giờ cho `NOT_PRESENT` hay điểm tốt hơn khi collector chạy được. |
| 9 | Bộ tính điểm lỗi (giả lập) → phát hiện + bằng chứng vẫn có trong cả ba đầu ra. |
| 10 | Mục trong `attack_candidates` không xuất hiện trong trường/nhãn ATT&CK của bất kỳ đầu ra nào. |
| 11 | Khi `CWSS_MANUAL_CHECK.status != "VERIFIED"`, không đầu ra nào ghi điểm CWSS là "đã xác minh". |
| 12 | CWE có `cwe_status = "proposed"` không được hiển thị là "đã xác minh". |

---

## 13. Bộ Kiểm thử, Benchmark & Báo cáo

### 13.1. Bộ kiểm thử
- `unittest` (thư viện chuẩn); lệnh: `python -m unittest discover -s tests -t . -v`. Không cần quyền Admin.

**Hai loại test (QĐ3):**

| Loại | Vị trí | Mục đích | Khi code cũ sai đặc tả |
| :--- | :--- | :--- | :--- |
| **Test mô tả hành vi hiện tại** (characterization) | `tests/current/` | Ghi lại đúng hành vi code ở commit `80fa1c1` để phát hiện thay đổi ngoài ý muốn | Test vẫn mô tả hành vi thật (kể cả hành vi sai), có chú thích `# KNOWN-ISSUE-n`. Khi sửa lỗi có chủ đích, cập nhật test này **cùng commit** và ghi lý do. |
| **Test theo đặc tả** (specification) | `tests/spec/` | Yêu cầu hành vi đúng theo kế hoạch này | Đánh dấu `@unittest.expectedFailure` + `# KNOWN-ISSUE-n`, **không** sửa điều kiện kiểm tra cho dễ qua, không xóa. Bỏ `expectedFailure` khi lỗi được sửa. |

- **Kiểm tra mốc commit trước khi viết `tests/current/`:** chạy `git rev-parse HEAD` và `git status --porcelain`.
  - Nếu HEAD == `80fa1c173b5ae425b66818cda0bf5310552a0f72` và cây làm việc không có thay đổi ở file đã theo dõi → viết test, ghi hash vào docstring của `tests/current/__init__.py` và vào §14.
  - Nếu HEAD khác (VD đã có commit mới trên `main`): **dừng và báo lại** nhóm; chỉ tiếp tục khi nhóm chọn (a) tạo nhánh P0 từ đúng `80fa1c1`, hoặc (b) chấp nhận mốc mới và cập nhật hash trong tài liệu này trước. Không được ghi rằng test mô tả hành vi của `80fa1c1` khi chạy trên commit khác.
  - Nếu có thay đổi chưa commit ở file code đã theo dõi: dừng và báo lại. (File chưa theo dõi như `winguard/cwss.py` placeholder không ảnh hưởng hành vi nhưng phải ghi chú.)
  - *Kiểm tra lúc cập nhật kế hoạch (28/10/2026):* HEAD = `80fa1c173b5ae425b66818cda0bf5310552a0f72` trên `main`; chỉ có 2 file chưa theo dõi (`cwss_implementation_plan.md`, `winguard/cwss.py`). Phải kiểm tra lại ngay trước khi bắt đầu P0.
- Lỗi có sẵn phát hiện ở P0 ghi vào bảng **Lỗi đã biết** (§14.1), mỗi lỗi có mã `KNOWN-ISSUE-n`, mô tả, test liên quan, bước dự kiến sửa.
- **Không** làm yếu điều kiện hay xóa test chỉ để code cũ vượt qua.
- Mọi thay đổi sau P0 phải: có test mới/cập nhật tương ứng; chạy lại toàn bộ `tests/current/` và `tests/spec/`; ghi kết quả vào §14.
- Tại P8: không còn `expectedFailure` nào, trừ lỗi được nhóm quyết định *chấp nhận* và ghi rõ trong §14.1.
- File: `test_regression.py`, `test_attack_mapping.py`, `test_evidence_pipeline.py`, `test_cwss.py`, `test_firewall.py`, `test_password_profile.py`, `test_incident_severity.py`, `test_clustering.py`, `test_allowlist.py`, `test_posture.py`, `test_consistency.py`, `test_report.py`.
- `test_cwss.py`: **Ví dụ 4.2 → 51.1 là test chuẩn chính**; ràng buộc `VERIFIED` của `CWSS_MANUAL_CHECK` (§3.2a); Ví dụ 4.1 theo kết quả kiểm tra thủ công §3.2a (khi `PENDING`/`DISCREPANCY`: chỉ kiểm tra mâu thuẫn đã ghi nhận, không dùng làm chuẩn, không sửa vector nguồn); gating TI = 0 / BI = 0; miền; metric thiếu/sai mã → `ValueError`; mã Unknown của AV theo kết quả kiểm tra thủ công; bỏ qua `RE`; `CWSS_MANUAL_CHECK` có đủ khóa và `reviewer` không rỗng (giá trị `PENDING` hợp lệ).
- `test_regression.py` (thuộc `tests/current/`, mô tả **đúng hành vi hiện tại** ở `80fa1c1`): brute force → T1110; spraying → T1110.003; spraying > 5 phút → không; 1102 → HIGH với mã **T1070.001** (hành vi hiện tại, `# KNOWN-ISSUE`: mã không còn trong v20.0 — test này được cập nhật cùng commit P1 khi đổi mã); collector lỗi → UNKNOWN, không "an toàn"; HMAC hợp lệ/sửa/chưa ký; `--rules v1` không bắt spraying, `v2` bắt.
- Bản theo đặc tả tương ứng nằm ở `tests/spec/test_attack_mapping.py` (1102 → T1685.005, `expectedFailure` cho tới P1).
- **Phân bổ file:** `tests/current/`: `test_regression.py` và các test mô tả hành vi hiện tại khác. `tests/spec/`: các file còn lại trong danh sách trên. Hai thư mục và `tests/` đều có `__init__.py` để `unittest discover` tìm thấy.
- Test âm tính: đăng nhập sai lẻ tẻ; tài khoản allowlist; Run key/task có trong baseline.

### 13.2. Benchmark & tên chỉ số
| Chỉ số | Định nghĩa | Dữ liệu hiện có |
| :--- | :--- | :--- |
| `test pass rate` | test đạt / tổng | Chưa có `tests/` |
| `scenario detection rate` | lần phát hiện đúng mã / lần chạy | 18/18 (6 kịch bản × 3, 27/10/2026, commit `80fa1c1`, mã ≤ v18.1) |
| Cảnh báo khi quét sạch | cảnh báo sự kiện khi không mô phỏng | 0 sau 3 lần quét ngắn |
| Thử né luật | spraying bắt bởi v1 / v2 | v1 0/3, v2 3/3 |
| `false positive rate` / `false negative rate` | cần dữ liệu gán nhãn | **Không tuyên bố** |

- Chỉ áp dụng cho **6 kịch bản tự mô phỏng** trên một máy Windows 11 Home. Không tuyên bố độ chính xác 100%.
- Benchmark hiện không có kịch bản 1102 → mapping T1685.005 chỉ được kiểm bằng unit test; ghi rõ.
- Sau khi đổi mapping: chạy lại benchmark (Admin) vì `EXPECTED` dùng mã từ `ATTACK_MAP`.

### 13.3. Báo cáo
Hiển thị: `ATT&CK Enterprise v20.0`; profile + ngưỡng; ba trụ cột + `SCORING_ERROR`; mỗi phát hiện có bằng chứng, `metric_sources`, breakdown/T-C-W, lý do; câu "vector do WinGuard lựa chọn"; nhãn "nội bộ WinGuard". Bố cục minh họa (số là ví dụ):

```
================================================================================
                    WINGUARD SECURITY ASSESSMENT REPORT
 ATT&CK Enterprise v20.0 | Profile: WINGUARD_LAB (min password >= 8)
================================================================================
 [1] CONFIRMED WEAKNESSES — công thức MITRE CWSS v1.0.1, vector do WinGuard chọn
     Posture Score (nội bộ WinGuard): <tính> / 100
     - [CWE-284] CWSS <điểm> (Base <b>, AS <a>, Env <e>; Unknown: EC)
       Quan sát: Public (Wi-Fi) Enabled=False | Yêu cầu: True
       Nguồn: Get-NetFirewallProfile, Get-NetConnectionProfile, SecurityCenter2
 [2] ATTACK OBSERVED — Incident Severity (nội bộ WinGuard)
     - [T1136.001 → T1098] <điểm> (T=1.00, C=1.00, W=1.00)
     - [T1685.005] <điểm> — Security Event Log bị xóa (Event 1102)
 [3] NEEDS REVIEW — Investigation Priority (nội bộ WinGuard)
     - [SCORING_ERROR] CWE-307: chưa tính được điểm (<lỗi>)
================================================================================
```

---

## 14. Điều kiện Hoàn thành & Nhật ký Kiểm thử

Một hạng mục chỉ `[x]` khi: (1) code + tài liệu đồng bộ; (2) có test; (3) test đã chạy và ghi vào bảng dưới; (4) không regression; (5) giả định chưa xác minh được liệt kê ở §16.

| Ngày | Commit | Lệnh | Kết quả (đạt/tổng) | Ghi chú |
| :--- | :--- | :--- | :--- | :--- |
| 27/10/2026 | `80fa1c1` | `python -m simulator.benchmark --runs 3` (Admin) | 18/18 phát hiện; 0 cảnh báo quét sạch; spray v1 0/3, v2 3/3 | Trước khi đổi mapping v20.0 |
| 28/10/2026 | `80fa1c1` (mốc P0, nhánh `feature/v7.2-cwss`) | `python -m unittest discover -s tests -t . -v` | 42 test: 34 đạt, 8 `expectedFailure` (KNOWN-ISSUE-1…7), 0 lỗi | P0: chưa sửa code ứng dụng. HEAD đã kiểm tra = `80fa1c173b5a…`, cây làm việc sạch (chỉ có file chưa theo dõi: kế hoạch, `winguard/cwss.py` placeholder) |

| — | — | Kiểm tra thủ công CWSS (§3.2a) | **PENDING** — chưa có người kiểm tra | AI đã trích nguồn ngày 28/10/2026; không tính là kiểm tra thủ công |

**Test chưa chạy được và lý do:** toàn bộ unit test (chưa viết — chờ duyệt kế hoạch); benchmark sau thay đổi (chưa đổi code); đọc `SecurityCenter2` trên máy lab (cần chạy thử); kiểm tra thủ công CWSS (chưa có người thực hiện).

### 14.1. Lỗi đã biết

| Mã | Mô tả | Test liên quan | Bước sửa | Trạng thái |
| :--- | :--- | :--- | :--- | :--- |
| KNOWN-ISSUE-1 | Event 1102 gắn `T1070.001` — STIX v20.0: `revoked-by` T1685.005 | `current/test_regression.py::Evasion.test_1102_high`, `spec/test_attack_mapping.py::Event1102.test_1102_maps_to_v20` | P1 | Đã xác nhận bằng test (P0) |
| KNOWN-ISSUE-2 | Cảnh báo UAC tắt gắn `T1548.002` (trái QĐ1) | `current/...ConfigAudit.test_uac_off`, `spec/test_attack_mapping.py::ConfigReferences.test_uac_has_no_direct_attack_mapping` | P1 + P2 | Đã xác nhận (P0) |
| KNOWN-ISSUE-3 | Firewall gắn `T1562.004`, Defender gắn `T1562.001` — STIX v20.0: `revoked-by` T1686 / T1685 | `current/...test_any_firewall_profile_off_is_high`, `test_defender_off`; `spec/test_attack_mapping.py::ConfigReferences` | P1 + P2 | Đã xác nhận (P0) |
| KNOWN-ISSUE-4 | Firewall cảnh báo HIGH cho **mọi** profile tắt, không xét profile đang hoạt động | `current/...test_any_firewall_profile_off_is_high`, `spec/test_firewall.py` | P4 | Đã xác nhận (P0) |
| KNOWN-ISSUE-5 | Ngưỡng mật khẩu viết cứng 8, không theo profile | `current/...test_min_password_hardcoded_8`, `spec/test_password_profile.py` | P4 | Đã xác nhận (P0) |
| KNOWN-ISSUE-6 | `parse_event` không giữ `Computer`, `EventRecordID` | `current/...EventLogParser.test_parse`, `spec/test_clustering.py` | P4 | Đã xác nhận (P0) |
| KNOWN-ISSUE-7 | Defender: RTP tắt → HIGH mà không kiểm tra AV khác (SecurityCenter2) | `current/...test_defender_off`, `spec/test_defender.py` | P4 | Đã xác nhận (P0) |

---

## 15. Lộ trình & Checklist v7.2

| Ưu tiên | Bước | Nội dung | Phụ thuộc |
| :---: | :--- | :--- | :--- |
| 0 | P0 | `tests/current/` (mô tả hành vi hiện tại, gồm `test_regression.py`) + `tests/spec/` (theo đặc tả, lỗi có sẵn → `expectedFailure` + `KNOWN-ISSUE-n`); điền §14.1; **không sửa code ứng dụng** | — |
| 1 | P1 | `attack.py` (`ATTACK_VERSION`, `ATTACK_MAP`, `ATTACK_CANDIDATES`, `ATTACK_LEGACY`), xác minh STIX `revoked-by`, đổi mã trong detector/benchmark, bỏ T1548.002 khỏi cảnh báo UAC; `test_attack_mapping.py` | P0 |
| 2 | P2 | Luồng bằng chứng 7 bước (`evidence.py`), `SCORING_ERROR`; `test_evidence_pipeline.py` | P0 |
| 3 | P3 | `cwss_weights.py` (trạng thái `PENDING` cho tới khi người kiểm tra §3.2a), `cwss.py`, `cwss_vectors.py`; `test_cwss.py` (chuẩn chính: Ví dụ 4.2) | P2 |
| 4 | P4 | Collector Firewall/SecurityCenter2/PasswordRequired/Computer/EventRecordID; profile mật khẩu; `test_firewall.py`, `test_password_profile.py` | P2 |
| 5 | P5 | Incident Severity + gom cụm + allowlist; test tương ứng | P1, P4 |
| 5 | P6 | Investigation Priority + Posture; `test_posture.py` | P3, P5 |
| 5 | P7 | Báo cáo console/HTML/JSON; `test_consistency.py`, `test_report.py` | P6 |
| 5 | P8 | Chạy toàn bộ test + benchmark (Admin); cập nhật README, báo cáo, slide (T1070.001 → T1685.005, bỏ T1548.002 khỏi UAC) | P7 |

Mỗi bước sau P0: có test tương ứng + chạy lại toàn bộ `tests/current/` và `tests/spec/` + ghi vào §14.

**Quy trình Git khi triển khai:**
- Không commit trực tiếp lên `main`. Tạo nhánh mới từ mốc đã kiểm tra ở P0 (VD `feature/v7.2-cwss`), mọi bước P0–P8 làm trên nhánh này.
- Chia **nhiều commit nhỏ**, ít nhất một commit cho mỗi bước P0…P8 (bước lớn có thể tách thêm); mỗi commit chạy được test của chính nó.
- **Tác giả commit chỉ là chủ repo** (`quaneluscore123`, theo `git config` của máy). Không thêm dòng `Co-Authored-By` hay bất kỳ ghi công nào cho AI trong commit message.
- Đẩy nhánh lên GitHub (`git push -u origin <nhánh>`); việc gộp vào `main` do nhóm quyết định sau khi xem lại.
- Ghi hash commit của từng bước vào bảng §14.

**P8 chỉ hoàn tất khi đủ cả:** (1) toàn bộ test đã chạy, kết quả thực tế ghi ở §14; (2) benchmark (Admin) đã chạy lại với mã v20.0, kết quả ghi ở §14; (3) README, báo cáo, slide đã đồng bộ; (4) mọi mục §14.1 đã sửa hoặc được nhóm quyết định chấp nhận có ghi lý do; (5) không còn `expectedFailure` ngoài các lỗi được chấp nhận.

**Quyết định đã chốt (chưa triển khai):** QĐ1 bỏ T1548.002 khỏi cảnh báo UAC; QĐ2 kiểm tra CWSS thủ công bởi người; QĐ3 giữ thứ tự P0 → P8.

- [x] **P0 Test nền:** 42 test (34 đạt, 8 `expectedFailure`), chạy 28/10/2026 tại mốc `80fa1c1`, kết quả ở §14; 7 lỗi đã biết ở §14.1.
- [ ] **§4 ATT&CK v20.0:** đối chiếu trang web xong (28/10/2026); còn: STIX `revoked-by`, mã TA Stealth, sửa code (gồm bỏ T1548.002 khỏi UAC theo QĐ1), test.
- [ ] **§2 Luồng bằng chứng:** thiết kế xong; còn code + test.
- [ ] **§3 CWSS:** AI đã trích công thức + trọng số (28/10/2026, không tính là xác minh); còn: **kiểm tra thủ công bởi người (`PENDING`)**, kết luận Ví dụ 4.1, code + test.
- [ ] **§9 Firewall/UAC/Defender:** thiết kế xong; còn: chạy thử SecurityCenter2, code + test.
- [ ] **§8 Profile mật khẩu**, **§5 Incident Severity**, **§6 Gom cụm**, **§7 Allowlist**, **§10 Priority**, **§11 Posture**, **§12 Nhất quán**, **§13 Test/benchmark/báo cáo**: chưa triển khai.

---

## 16. Giả định & Điểm Chưa Xác minh

1. Bảng trọng số CWSS do AI trích bằng công cụ đọc web; kiểm tra thủ công bởi người: **`PENDING`** (§3.2a).
2. Ví dụ CWSS 4.1: mâu thuẫn BI (0.9 trong vector, 1.0 theo Env) — chưa giải thích; **`PENDING`** kiểm tra thủ công. Ví dụ 4.2 là chuẩn chính.
3. Quan hệ `revoked-by` chính thức của T1070.001, T1562.001, T1562.002, T1562.004 trong STIX v20.0 — chưa đọc; bảng §4.2 dựa trên trang kỹ thuật + changelog.
4. Mã TA của tactic Stealth — chưa xác minh.
5. ~~T1548.002 cho "UAC đang tắt"~~ — **đã quyết (QĐ1)**: không gắn; chỉ là ứng viên chưa xác nhận.
6. Số hiệu CIS Rec. 1.1.4 và khuyến nghị lockout — cần đối chiếu PDF CIS v3.0.0.
7. Lựa chọn CWE (CWE-284 hay CWE-693 cho firewall, CWE-250 cho UAC…) — tất cả `cwe_status = "proposed"`, chưa xác minh.
8. Mọi trọng số nội bộ ($T$, $C$, $W$, Impact, Uncertainty, hệ số 0.1) — chưa hiệu chỉnh thực nghiệm.
9. `root\SecurityCenter2` (`FirewallProduct`, `AntiVirusProduct`) trên Windows 11 Home — cần chạy thử.
10. Đa máy chỉ kiểm thử bằng dữ liệu tổng hợp.
