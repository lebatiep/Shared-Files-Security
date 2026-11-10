# Dàn ý 14 slide

Bản nháp theo kế hoạch nhóm. Mỗi người tự điền nội dung phần mình; chỉ đưa vào slide những điều đã có bằng chứng (kết quả test thật, ảnh thật, số đo thật).

| Slide | Nội dung | Người chuẩn bị |
|---|---|---|
| 1 | Tên đề tài, thành viên | Tiệp |
| 2 | Bài toán chia quyền mở tệp giữa ba người giữ | Tiệp |
| 3 | Tiêp gửi gói cho Nhật Minh, Hoàng và Việt | Tiệp |
| 4 | Hai cặp khóa theo vai trò (mã hóa, ký) | Nhật |
| 5 | Fingerprint và trạng thái tin cậy; đối chiếu độc lập | Nhật |
| 6 | Chia khóa AES bằng Shamir và nội suy từ hai điểm | Hoàng |
| 7 | Gói `.sfile2`, ba phần đã bọc bằng RSA-OAEP và chữ ký RSA-PSS | Hoàng |
| 8 | Ràng buộc `.sapproval` với đúng gói và đúng khóa người mở | Hoàng |
| 9 | Giao diện: ba tab, xác minh người liên hệ | Việt |
| 10 | Tạo gói, góp phần, mở và so byte cùng SHA-256 | Việt |
| 11 | Ca thiếu phần, phần sai gói, sai đích và gói bị sửa | Quang |
| 12 | Kết quả kiểm thử: số ca đã chạy, đạt, chưa đạt; số đo (nếu có) | Quang |
| 13 | Giới hạn của xác minh khóa, dùng lại phần góp và chuyển tiếp bản rõ | Quang, nhận nội dung cả nhóm |
| 14 | Kết luận, đóng góp, hướng mở rộng có điều kiện | Tiệp |

## Người nào cũng cần trả lời được

Vì sao hai phần chia khôi phục được khóa AES? Vì sao mỗi phần cần được bọc riêng? Chữ ký ràng buộc danh sách người giữ với gói thế nào? Nếu một người vắng mặt thì cặp nào còn mở được? Điều gì xảy ra nếu có bản sao của phần đóng góp?

## Phân vai trình bày và demo

Tiệp mở đầu với bài toán quyền mở theo ngưỡng. Nhật trình bày cách đối chiếu fingerprint trước khi tạo gói. Hoàng vẽ đường thẳng Shamir và giải thích hai phần chia. Việt thao tác trên giao diện với kịch bản Tiêp tạo gói, Hoàng góp phần cho Nhật Minh, rồi Nhật Minh mở và đối chiếu tệp. Quang chạy các ca từ chối và trình bày kết quả kiểm thử. Dùng tệp giả nhỏ để các bước dễ theo dõi.
