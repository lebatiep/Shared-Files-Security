# Chương 1. Vấn đề, mục tiêu, phạm vi và tổ chức

Bản nháp dưới đây ghi phạm vi v1 ban đầu. Xem luồng Shamir hiện tại trong [README](../../README.md).

**Bản nháp** do Hoàng soạn từ proposal, kế hoạch nhóm và mã hiện tại để Tiệp (chủ chương) đọc, sửa và nhận. Chưa ai duyệt. Người đối chiếu bằng chứng theo kế hoạch: Quang. Chương này chưa nêu kết quả nghiệm thu vì 60 ca kiểm thử chưa có trạng thái do người chạy độc lập ghi.

## 1.1. Vấn đề

Làm thế nào để chia sẻ một tệp qua kênh truyền không đáng tin cậy (USB, ứng dụng nhắn tin) sao cho người có bản sao gói không đọc được nội dung nếu thiếu khóa của người nhận, đồng thời người nhận xác minh được người ký và phát hiện dữ liệu bị sửa. Cách phổ biến là gửi tệp mã hóa kèm mật khẩu qua cùng kênh, nhưng khi đó kênh lộ mật khẩu là lộ tệp.

## 1.2. Mục tiêu và đóng góp

- Kết hợp mã hóa đối xứng cho nội dung với mật mã khóa công khai cho việc chuyển khóa.
- Bổ sung chữ ký số và xác minh fingerprint để xử lý giả mạo người gửi và thay thế khóa.
- Thiết kế quy trình rõ ràng cho thành công, từ chối, hủy thao tác, lỗi dữ liệu và lỗi lưu tệp.
- Chứng minh bằng kiểm thử có thể tái lập và ghi nhận cả giới hạn của mô hình offline.

## 1.3. Phạm vi

Ứng dụng desktop cục bộ (Python, Tkinter), một định dạng gói `.sfile`, một người nhận mỗi gói, tệp 0 đến 10.485.760 byte, không máy chủ. Tiêp gửi, Nhật Minh nhận, Quang đóng vai người thử đọc, sửa hay gửi giả. Cơ chế: AES-256-GCM, RSA-3072 OAEP, RSA-3072 PSS, hai cặp khóa theo vai trò, ghim fingerprint trong danh bạ cục bộ.

Ngoài phạm vi: nhiều người nhận, tệp lớn theo luồng, máy chủ phân phối khóa, chứng thư PKI, thu hồi gói, xác nhận đã đọc. Chi tiết ở `docs/requirements.md`.

## 1.4. Kiến trúc tóm tắt

Giao diện gọi `FileShareService`; service gọi quản lý khóa, danh bạ tin cậy, mật mã/định dạng gói và lưu trữ qua các cổng. Các lớp dưới không gọi giao diện. Sơ đồ, đồ thị phụ thuộc và luồng gửi nhận ở `docs/architecture.md`; API và mã lỗi ở `docs/interfaces.md`.

## 1.5. Tổ chức nhóm

| Người | Phần |
|---|---|
| Tiệp (nhóm trưởng) | Điều phối, service, tích hợp, phát hành |
| Nhật | Khóa, fingerprint, hồ sơ, danh bạ tin cậy |
| Hoàng | Mật mã, framing, định dạng và parser |
| Việt | Giao diện, đọc/lưu tệp, trạng thái tác vụ |
| Quang | Kiểm thử độc lập, fixture, benchmark |

Mỗi người có phần triển khai và phần tài liệu của mình; một người khác review trước khi ghép. Lịch tham chiếu 20 ngày làm việc (D1–D20) với các mốc D2 hợp đồng, D5–D6 luồng thật, D10 nhánh bảo mật, D15 khóa tính năng, D18 bản ứng viên, D20 nộp.

## 1.6. Phương pháp kiểm chứng

60 ca kiểm thử có mã I, S, R, A, P, O, L, mỗi biến thể cần kết quả và bằng chứng riêng. Test tự động được gắn ID bằng marker; `python -m tools.case_report` liệt kê liên kết nhưng không chạy test và không ghi ca nào là đạt. Một ca chỉ đạt khi người chạy độc lập ghi kết quả thật. Gói lỗi sâu do bộ test tạo và ký bằng khóa test, không phải khả năng giả chữ ký của kẻ không có khóa.

## 1.7. Hiện trạng và giới hạn (cần Tiệp cập nhật khi chốt)

Điền số liệu thật vào đây khi có: số ca đã chạy, đạt, chưa đạt; phiên bản bản ứng viên; số đo benchmark; lỗi còn lại. Các giới hạn đã biết:

- Mật mã dữ liệu tự cài bằng Python nên rất chậm với tệp lớn; sinh và lưu khóa dùng thư viện `cryptography`.
- Tin cậy bằng ghim thủ công; không thu hồi; không forward secrecy; người nhận chuyển tiếp được bản rõ.
- Chưa kiểm toán bảo mật.

## 1.8. Kết luận (để trống, viết sau khi có kết quả thật)

Không dùng nhãn "hoàn thành" thay cho kiểm thử. Nêu rõ chức năng chưa chứng minh và phạm vi còn lại.
