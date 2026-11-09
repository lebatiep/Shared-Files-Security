"""Safe domain errors shared by adapters, service and UI.

Never copy an exception raised by a library or the operating system into a UI
message. Such exceptions can contain paths, contents or secret values.
"""

from enum import StrEnum


class ErrorCode(StrEnum):
    READ_FAILED = "READ_FAILED"
    INPUT_TOO_LARGE = "INPUT_TOO_LARGE"
    INVALID_REQUEST = "INVALID_REQUEST"
    INVALID_JSON = "INVALID_JSON"
    INVALID_SCHEMA = "INVALID_SCHEMA"
    INVALID_BASE64 = "INVALID_BASE64"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    UNSUPPORTED_SUITE = "UNSUPPORTED_SUITE"
    INVALID_LENGTH = "INVALID_LENGTH"
    UNTRUSTED_RECIPIENT = "UNTRUSTED_RECIPIENT"
    UNTRUSTED_SENDER = "UNTRUSTED_SENDER"
    PROFILE_INVALID = "PROFILE_INVALID"
    RECIPIENT_KEY_NOT_FOUND = "RECIPIENT_KEY_NOT_FOUND"
    KEY_UNLOCK_FAILED = "KEY_UNLOCK_FAILED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    UNWRAP_FAILED = "UNWRAP_FAILED"
    AES_KEY_LENGTH_INVALID = "AES_KEY_LENGTH_INVALID"
    GCM_AUTH_FAILED = "GCM_AUTH_FAILED"
    PAYLOAD_INVALID = "PAYLOAD_INVALID"
    SAVE_FAILED = "SAVE_FAILED"
    DESTINATION_EXISTS = "DESTINATION_EXISTS"
    PROTECTED_PATH = "PROTECTED_PATH"
    SAVE_STATE_UNKNOWN = "SAVE_STATE_UNKNOWN"
    INVALID_HANDLE = "INVALID_HANDLE"
    BUSY = "BUSY"
    HISTORY_INVALID = "HISTORY_INVALID"
    HISTORY_TOO_LARGE = "HISTORY_TOO_LARGE"
    INTEGRATION_UNAVAILABLE = "INTEGRATION_UNAVAILABLE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


_SAFE_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.READ_FAILED: "Không đọc được tệp đã chọn.",
    ErrorCode.INPUT_TOO_LARGE: "Dữ liệu vượt giới hạn cho phép.",
    ErrorCode.INVALID_REQUEST: "Thông tin tác vụ không hợp lệ.",
    ErrorCode.INVALID_JSON: "Dữ liệu JSON không hợp lệ.",
    ErrorCode.INVALID_SCHEMA: "Cấu trúc dữ liệu không hợp lệ.",
    ErrorCode.INVALID_BASE64: "Dữ liệu Base64 không hợp lệ.",
    ErrorCode.UNSUPPORTED_VERSION: "Phiên bản gói chưa được hỗ trợ.",
    ErrorCode.UNSUPPORTED_SUITE: "Bộ thuật toán chưa được hỗ trợ.",
    ErrorCode.INVALID_LENGTH: "Độ dài dữ liệu không hợp lệ.",
    ErrorCode.UNTRUSTED_RECIPIENT: "Chưa xác minh khóa của người nhận.",
    ErrorCode.UNTRUSTED_SENDER: "Chưa xác minh khóa của người gửi.",
    ErrorCode.PROFILE_INVALID: "Hồ sơ hoặc vai trò khóa không hợp lệ.",
    ErrorCode.RECIPIENT_KEY_NOT_FOUND: "Không có khóa nhận phù hợp trong hồ sơ.",
    ErrorCode.KEY_UNLOCK_FAILED: "Không mở được khóa riêng.",
    ErrorCode.SIGNATURE_INVALID: "Không xác minh được chữ ký của gói.",
    ErrorCode.UNWRAP_FAILED: "Không mở được khóa của gói.",
    ErrorCode.AES_KEY_LENGTH_INVALID: "Khóa nội dung có độ dài không hợp lệ.",
    ErrorCode.GCM_AUTH_FAILED: "Không xác thực được nội dung gói.",
    ErrorCode.PAYLOAD_INVALID: "Nội dung đã giải mã không đúng cấu trúc.",
    ErrorCode.SAVE_FAILED: "Không lưu được tệp. Có thể chọn lại nơi lưu.",
    ErrorCode.DESTINATION_EXISTS: "Tệp đích đã tồn tại; cần xác nhận trước khi thay thế.",
    ErrorCode.PROTECTED_PATH: "Đường dẫn đích trùng dữ liệu cần bảo vệ.",
    ErrorCode.SAVE_STATE_UNKNOWN: "Chưa xác nhận được kết quả lưu; hãy kiểm tra thư mục đích trước khi thử lại.",
    ErrorCode.INVALID_HANDLE: "Kết quả chờ lưu không còn hợp lệ.",
    ErrorCode.BUSY: "Một tác vụ khác đang xử lý hoặc chờ lưu.",
    ErrorCode.HISTORY_INVALID: "Không đọc hoặc cập nhật được lịch sử hợp lệ.",
    ErrorCode.HISTORY_TOO_LARGE: "Lịch sử vượt giới hạn cho phép.",
    ErrorCode.INTEGRATION_UNAVAILABLE: "Một phần của ứng dụng chưa được kết nối.",
    ErrorCode.INTERNAL_ERROR: "Không hoàn tất được tác vụ.",
}


def safe_message(code: ErrorCode) -> str:
    """Return an application-owned message, without interpolating user data."""
    return _SAFE_MESSAGES.get(code, _SAFE_MESSAGES[ErrorCode.INTERNAL_ERROR])


class ShareError(Exception):
    """An adapter failure that can cross the service boundary safely.

    ``message`` is accepted for integration compatibility, but is deliberately
    discarded. UI messages come only from ``code``. An adapter must not signal
    a known pre-commit save failure after the output has actually committed.
    """

    def __init__(self, code: ErrorCode, message: str | None = None) -> None:
        # Reject unrecognised input without retaining or echoing it.
        self.code = code if isinstance(code, ErrorCode) else ErrorCode.INTERNAL_ERROR
        self.message = safe_message(self.code)
        super().__init__(self.message)
