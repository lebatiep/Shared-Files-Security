# Quản lý khóa và danh bạ tin cậy: hướng dẫn thao tác

Hướng dẫn cho người dùng và người kiểm thử. Đặc tả kỹ thuật nằm ở `docs/key_spec.md`. Tất cả khóa, mật khẩu và tệp trong hướng dẫn này là dữ liệu giả.

## Mỗi hồ sơ có gì

Mỗi hồ sơ có hai cặp khóa RSA-3072 **khác nhau**: một cặp để mã hóa/giải mã, một cặp để ký/xác minh. Khóa riêng được lưu dạng PEM PKCS8 mã hóa bằng mật khẩu của bạn. Khóa công khai xuất ra `public bundle` gồm đúng: `version`, `display_name`, `encryption_public_key`, `signing_public_key`. Bundle không bao giờ chứa khóa riêng.

Mật khẩu: tối thiểu 12 ký tự, không chỉ toàn khoảng trắng, tối đa 1.024 byte; nhập lại khi tạo hồ sơ; không được lưu vào cấu hình hay log.

## Fingerprint

Fingerprint là SHA-256 của DER SubjectPublicKeyInfo của khóa công khai, viết bằng 64 ký tự hex. Mỗi hồ sơ có hai fingerprint (mã hóa và ký). Chỉ `keys.py` tính fingerprint; mọi nơi khác dùng kết quả đó.

## Thiết lập tin cậy lần đầu (Alice và Bob)

1. Mỗi người tạo hồ sơ trên máy của mình và xuất public bundle.
2. Hai người trao đổi bundle (qua USB hay ứng dụng nhắn tin đều được; bundle không bí mật).
3. Mỗi người nhập bundle của người kia. Liên hệ vào danh bạ ở trạng thái **chưa xác minh**; chưa gửi hay nhận được gì.
4. **Đối chiếu đầy đủ cả hai fingerprint** với chủ nhân qua một kênh độc lập đã xác thực: gặp trực tiếp hoặc cuộc gọi bạn nhận ra giọng. Cùng một cuộc trò chuyện đã nhận bundle **không** phải kênh độc lập.
5. Chỉ khi cả hai fingerprint khớp mới bấm xác minh. Liên hệ chuyển sang **đã xác minh** và dùng được để gửi, cũng như để chấp nhận người gửi.

Gói nhận được không bao giờ tự thêm khóa vào danh bạ. Khóa ký tự khai trong gói không được dùng làm nguồn tin cậy.

## Các trạng thái liên hệ

| Trạng thái | Gửi tới | Chấp nhận làm người gửi |
|---|---|---|
| Chưa xác minh | Không | Không |
| Đã xác minh | Có | Có |
| Vô hiệu hóa | Không | Không; nhập hoặc xác minh lại cũng không tự bật lại |

## Khi người liên hệ đổi khóa

- Nhập bundle cùng liên hệ nhưng **khác khóa** bị từ chối trừ khi chọn thay thế rõ ràng; thay thế đưa liên hệ về **chưa xác minh** và phải đối chiếu lại ngoài kênh.
- Giao diện dùng mã liên hệ mới cho khóa mới, nên pin cũ vẫn còn.
- Nhập lại **đúng** khóa cũ giữ nguyên tên, trạng thái và dữ liệu.
- Cảnh báo khi có liên hệ **cùng tên hiển thị nhưng khác khóa**. Trùng tên chỉ là cảnh báo, không phải bằng chứng danh tính.
- Hai vai trò dùng chung một khóa công khai bị chặn.

## Khi bạn đổi khóa của mình

Chức năng tạo cặp khóa mới thêm một thế hệ khóa; các thế hệ cũ vẫn được giữ (tối đa 10). Khóa mã hóa cũ vẫn mở được gói đã gửi cho khóa đó; gói mới dùng khóa hiện tại. Đổi khóa **không thu hồi** khả năng mở gói cũ và không ngăn người nhận chuyển tiếp bản rõ. Bạn phải gửi public bundle mới cho người liên hệ; họ phải đối chiếu fingerprint mới.

## Sao lưu và khôi phục

- **Sao lưu hồ sơ** tạo tệp `.sbackup` chứa khóa riêng đã mã hóa và metadata công khai. Đây là bản sao riêng, **không phải** public bundle; cất tách khỏi nơi trao đổi gói và không gửi cho ai.
- Trước khi sao lưu, đổi khóa hay khôi phục, mọi khóa riêng còn giữ đều được kiểm tra bằng mật khẩu, nên khóa hỏng hay sai mật khẩu bị phát hiện ngay.
- **Khôi phục** không ghi đè hồ sơ đang có và không khôi phục danh bạ: phải nhập lại và xác minh lại từng liên hệ trên máy mới.
- **Mất khóa hoặc mật khẩu không có cách bỏ qua.** Chỉ mở lại được gói cũ nếu còn bản sao lưu và đúng mật khẩu.

## Điều hệ thống không làm

- Không phải PKI đầy đủ: tin cậy dựa trên ghim fingerprint thủ công.
- Không có dấu thời gian tin cậy, nên khi vô hiệu hóa một liên hệ không kết luận được gói cũ được ký trước hay sau sự cố.
- Không bảo vệ nếu kẻ tấn công ghi được vào thư mục danh bạ cục bộ (ví dụ đổi trạng thái liên hệ sang đã xác minh) hoặc đã nhiễm mã độc trên máy.
- Mã hóa PEM và tính fingerprint dùng thư viện `cryptography`; phần này không tự cài.
