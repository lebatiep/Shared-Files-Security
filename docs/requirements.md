# Phạm vi và tiêu chí đạt

Tóm tắt từ proposal 1.0 (09/11/2026) và kế hoạch nhóm 1.1. Trạng thái các tiêu chí do người chạy độc lập ghi vào bảng kết quả; tài liệu này không khẳng định tiêu chí nào đã đạt.

## Vấn đề

Chia sẻ tệp qua kênh không đáng tin cậy (USB, ứng dụng nhắn tin) mà không gửi kèm mật khẩu dùng chung, sao cho người có bản sao gói không đọc được nội dung nếu thiếu khóa của người nhận, và người nhận xác minh được người ký và phát hiện dữ liệu bị sửa.

## Phạm vi bắt buộc

| Hạng mục | Nội dung |
|---|---|
| Vai trò | Alice gửi, Bob nhận, Mallory thử đọc/sửa/gửi giả; ba hồ sơ và thư mục tách biệt |
| Dữ liệu | Mọi định dạng xử lý như byte, từ 0 đến 10.485.760 byte; không tự mở hoặc chạy tệp sau giải mã |
| Chức năng | Hồ sơ và khóa; liên hệ tin cậy; mã hóa và xuất gói; kiểm tra và giải mã; trạng thái kết quả |
| Gói | Một tệp `.sfile`, không kèm khóa AES thô, khóa riêng hay mật khẩu |
| Tin cậy | Đối chiếu fingerprint khóa công khai qua kênh độc lập rồi ghim vào danh bạ cục bộ |
| Mật mã | AES-GCM, RSA-OAEP, RSA-PSS; hai cặp khóa RSA riêng theo mục đích cho mỗi hồ sơ |
| Triển khai | Python, Tkinter; ứng dụng cục bộ, không máy chủ |

Ngoài phạm vi (cần thiết kế và kiểm thử riêng): nhiều người nhận, tệp lớn theo luồng, máy chủ phân phối khóa hoặc chứng thư.

## Tiêu chí đạt

1. Tệp khôi phục khớp từng byte và SHA-256 với tệp gốc ở mọi ca thành công.
2. Người không có đúng khóa riêng không xuất được bản rõ; gói sai chữ ký hoặc chưa có danh tính tin cậy bị chặn.
3. Tệp đúng 10 MiB được chấp nhận; 10 MiB + 1 byte bị chặn trước khi mã hóa. Gói tối đa 15 MiB; có giới hạn riêng từng trường.
4. Không ghi mật khẩu, khóa AES, khóa riêng hay nội dung tệp vào log. Thông báo thành công chỉ xuất hiện sau khi lưu xong.
5. Các ca hủy và lỗi không làm hỏng tệp nguồn, khóa hoặc tệp đích cũ.
6. Bộ kiểm thử ghi kết quả thực tế; ca chưa chạy không được ghi đạt.

## Ca kiểm thử

60 ID gốc: I01–I10 (khóa và danh tính), S01–S09 (gửi), R01–R07 (nhận và lưu), A01–A12 (tấn công và lỗi mật mã), P01–P08 (parser), O01–O08 (thao tác và lưu), L01–L06 (vòng đời và giới hạn). Mỗi biến thể cần kết quả và bằng chứng riêng; không đánh dấu đạt chung khi còn biến thể chưa chạy. `python -m tools.case_report` cho biết ID nào đã có test gắn marker `case`; đó chỉ là liên kết, không phải kết quả đạt.

## Giới hạn phải nói khi bảo vệ

Người nhận chuyển tiếp được bản rõ; không thu hồi hay hết hạn offline; gửi nhầm một liên hệ hợp lệ vẫn mở được; xác minh fingerprint sai có thể gửi bí mật cho kẻ khác; không có forward secrecy; không có dấu thời gian tin cậy; gói lộ dung lượng gần đúng và fingerprint. Không chống thiết bị nhiễm mã độc hay sửa danh bạ cục bộ. Chi tiết: `docs/threat_model.md`.
