"""Test mô tả hành vi hiện tại (characterization tests).

Mốc: commit 80fa1c173b5ae425b66818cda0bf5310552a0f72 (nhánh main, kiểm tra bằng
`git rev-parse HEAD` ngày 2026-10-28 trước khi viết test; cây làm việc không có
thay đổi ở file đã theo dõi).

Các test ở đây ghi lại ĐÚNG hành vi của code tại mốc trên, kể cả hành vi sai
(đánh dấu `# KNOWN-ISSUE-n`, xem cwss_implementation_plan.md §14.1). Khi một
bước sau sửa lỗi có chủ đích, test tương ứng được cập nhật trong cùng commit.
"""
