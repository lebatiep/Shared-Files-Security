# Dàn ý 14 slide

Bản nháp theo kế hoạch nhóm. Mỗi người tự điền nội dung phần mình; chỉ đưa vào slide những điều đã có bằng chứng (kết quả test thật, ảnh thật, số đo thật).

| Slide | Nội dung | Người chuẩn bị |
|---|---|---|
| 1 | Tên đề tài, thành viên | Tiệp |
| 2 | Vấn đề: gửi tệp kèm mật khẩu qua cùng kênh | Tiệp |
| 3 | Mục tiêu, phạm vi, vai Alice – Bob – Mallory | Tiệp |
| 4 | Hai cặp khóa theo vai trò (mã hóa, ký) | Nhật |
| 5 | Fingerprint và trạng thái tin cậy; đối chiếu độc lập | Nhật |
| 6 | Hệ lai: AES-256-GCM cho nội dung, RSA-OAEP bọc khóa | Hoàng |
| 7 | Gói `.sfile`: H, W, N, C, S; framing; AAD và dữ liệu ký | Hoàng |
| 8 | Thứ tự kiểm tra khi nhận; vì sao PSS trước GCM | Hoàng |
| 9 | Giao diện: ba tab, xác minh người liên hệ | Việt |
| 10 | Gửi và nhận thành công; so byte và hash; hủy lưu | Việt |
| 11 | Các ca lỗi đại diện: sai người nhận, sửa gói, người gửi chưa tin, tệp 10 MiB + 1 | Quang |
| 12 | Kết quả kiểm thử: số ca đã chạy, đạt, chưa đạt; số đo (nếu có) | Quang |
| 13 | Giới hạn: chuyển tiếp bản rõ, không thu hồi, không forward secrecy, tin cậy thủ công, mật mã tự cài chưa kiểm toán | Quang, nhận nội dung cả nhóm |
| 14 | Kết luận, đóng góp, hướng mở rộng có điều kiện | Tiệp |

## Người nào cũng cần trả lời được

Vì sao AES mã hóa tệp còn RSA chỉ bọc khóa? Vì sao vẫn cần chữ ký khi đã có GCM? Fingerprint gắn danh tính thế nào? Vì sao sửa ciphertext thường dừng ở PSS? Mất khóa thì sao? Người nhận có chuyển tiếp được không? Mỗi người học cả luồng, không chỉ phần mình viết.

## Phân vai trình bày và demo

Tiệp mở đầu 1–2 phút; Nhật thiết lập tin cậy và đối chiếu fingerprint đúng/sai 2 phút; Hoàng giải thích AES/OAEP/PSS và vì sao tách hai cặp khóa 2 phút; Việt gửi/nhận qua giao diện và so byte 3 phút; Quang cho Mallory mở/sửa/giả gói, fixture sâu, kết quả và giới hạn 3–4 phút. Không trình diễn cả 60 ca trực tiếp: chọn ca đại diện, phần còn lại có bằng chứng và bảng trạng thái. Vì AES tự cài chậm, demo trực tiếp dùng tệp nhỏ.
