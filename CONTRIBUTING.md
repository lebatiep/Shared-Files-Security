# Quy tắc đóng góp

## Nhánh, PR và review

1. Cập nhật `main` (`git fetch`, `git pull --ff-only`) trước khi bắt đầu.
2. Mỗi ticket một nhánh ngắn, ví dụ `feat/t2-5-key-roles`, `fix/desktop-test-ids`, `docs/key-management`.
3. Không commit hay push thẳng vào `main`. Gửi PR; một người khác chủ ticket đọc và chấp nhận; Tiệp ghép.
4. **CI phải xanh trước khi ghép** (`.github/workflows/tests.yml`: `--check`, pytest trên Ubuntu và Windows, demo).
5. Không sửa một tệp chung ở hai nhánh mà không báo nhau. Đổi API, hằng số hay mã lỗi chung cần Tiệp, Nhật và Hoàng đồng ý; Quang cập nhật test, Việt cập nhật giao diện nếu bị ảnh hưởng.
6. Khi gộp mã của người khác vào cấu trúc mới, đọc commit trên `origin/main` trước và báo chủ module.

## Commit

Một thay đổi, một mục đích. Thông điệp tiếng Anh, thể mệnh lệnh, có tiền tố `feat:`, `fix:`, `docs:`, `test:`, `refactor:`. Không đưa tệp cục bộ (`Document/`, `.claude/`, khóa, gói `.sfile`).

## Một ticket đủ rõ để bắt đầu

Có chủ, người review, hạn; đầu vào và đầu ra; biết ai dùng đầu ra; điều kiện đạt; ít nhất một ca thành công và một ca lỗi liên quan.

## Một ticket được coi là xong

- Mã chạy; test liên quan đã chạy và **bạn đã đọc kết quả thật** (không chỉ chép công thức vào test).
- Review được chấp nhận; tài liệu và hướng dẫn tương ứng đã cập nhật.
- Đã ghép vào bản chung và `python -m pytest -q` vẫn đạt.
- Không chứa khóa, mật khẩu, dữ liệu thật; không còn đường bỏ qua kiểm tra chỉ để demo.

## Kiểm thử và ID nghiệm thu

- Test mới gắn ID nghiệm thu bằng marker khi đúng ca: `@pytest.mark.case("A06")`. ID hợp lệ: I01–I10, S01–S09, R01–R07, A01–A12, P01–P08, O01–O08, L01–L06.
- `python -m tools.case_report` cho biết ID nào đã có test gắn, ID nào còn trống.
- Test gắn marker **không** có nghĩa ca nghiệm thu đã đạt. Ca chỉ đạt khi người chạy độc lập ghi kết quả thật. Không ghi "đạt" cho ca chưa chạy.
- Gói lỗi sâu (OAEP, GCM, payload) do bộ test tạo và ký bằng khóa test (`tools/make_fixtures.py`). Không mô tả đó là khả năng giả chữ ký.
- Test dùng thư mục tạm và khóa giả; không làm đầy ổ đĩa thật.

## Quy ước mã

- Lớp dưới không gọi giao diện, không đọc danh bạ, không tự quyết định lưu tệp. Giao diện chỉ gọi service.
- `crypto_ops.py` và `envelope.py` không import nhau; service chuyển AAD và dữ liệu ký từ envelope sang crypto.
- Thông báo lỗi cho người dùng chỉ lấy từ `ErrorCode` (`secure_share/errors.py`); không chép nội dung ngoại lệ của thư viện hay hệ điều hành vào giao diện.
- Không ghi log khóa, mật khẩu, nonce kèm khóa hay nội dung tệp.
- Kiểm giới hạn kích thước trước khi giải mã hoặc cấp phát.

## Báo lỗi

Dùng mẫu issue. Lỗi cần: phiên bản/commit, ca hoặc biến thể, fixture, bước tái hiện, kết quả mong đợi và thực tế, mức độ. Lỗi làm lộ bản rõ, nhận sai người gửi hoặc người nhận, hoặc mất dữ liệu là **lỗi chặn phát hành**.

## Thứ tự ưu tiên khi thiếu thời gian

Cắt theo thứ tự: trang trí giao diện, tiện ích danh bạ, biểu đồ, đóng gói `.exe`. **Không cắt**: xác minh khóa, PSS, OAEP/GCM đúng profile, bảo vệ khóa riêng, giới hạn đầu vào, lưu tệp an toàn.
