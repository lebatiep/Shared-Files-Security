## Ticket

Mã và tên ticket (ví dụ T2.5), người review:

## Thay đổi

Tóm tắt ngắn: làm gì và vì sao.

## Cách kiểm tra

Lệnh đã chạy và kết quả thật (ví dụ `python -m pytest -q`: số đạt/lỗi). Ghi rõ phần chưa chạy.

## Ca nghiệm thu liên quan

ID (ví dụ A06, I10) và test nào gắn marker `case`. Không ghi "đạt" cho ca chưa được người chạy độc lập kiểm tra.

## Danh sách kiểm

- [ ] `python -m pytest -q` đạt và CI xanh
- [ ] Không có khóa, mật khẩu, dữ liệu thật, `*.pem`, `*.sfile` trong thay đổi
- [ ] Nếu đổi API, hằng số hoặc mã lỗi: đã báo Tiệp, Nhật, Hoàng, Quang, Việt và cập nhật tài liệu/test
- [ ] Tài liệu liên quan đã cập nhật
