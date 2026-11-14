"""Safe domain errors shared by adapters, service and UI.

Never copy an exception raised by a library or the operating system into a UI
message. Such exceptions can contain paths, contents or secret values.
"""

from enum import StrEnum


class ErrorCode(StrEnum):
    READ_FAILED = "READ_FAILED"
    INPUT_TOO_LARGE = "INPUT_TOO_LARGE"
    INVALID_REQUEST = "INVALID_REQUEST"
    INVALID_THRESHOLD_RECIPIENTS = "INVALID_THRESHOLD_RECIPIENTS"
    INVALID_SHARE = "INVALID_SHARE"
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
    ErrorCode.READ_FAILED: "Could not read the selected file.",
    ErrorCode.INPUT_TOO_LARGE: "The data exceeds the allowed size limit.",
    ErrorCode.INVALID_REQUEST: "The operation details are invalid.",
    ErrorCode.INVALID_THRESHOLD_RECIPIENTS: "Select three distinct key holders. When contributing, select another holder listed in the package.",
    ErrorCode.INVALID_SHARE: "The share is invalid or does not belong to this package and profile. Two distinct shares are required.",
    ErrorCode.INVALID_JSON: "Invalid JSON data.",
    ErrorCode.INVALID_SCHEMA: "Invalid data structure.",
    ErrorCode.INVALID_BASE64: "Invalid Base64 data.",
    ErrorCode.UNSUPPORTED_VERSION: "Unsupported package version.",
    ErrorCode.UNSUPPORTED_SUITE: "Unsupported cryptographic suite.",
    ErrorCode.INVALID_LENGTH: "Invalid data length.",
    ErrorCode.UNTRUSTED_RECIPIENT: "The recipient keys have not been verified.",
    ErrorCode.UNTRUSTED_SENDER: "The sender keys have not been verified.",
    ErrorCode.PROFILE_INVALID: "Invalid profile or key role.",
    ErrorCode.RECIPIENT_KEY_NOT_FOUND: "No matching recipient key was found in this profile.",
    ErrorCode.KEY_UNLOCK_FAILED: "Could not unlock the private key.",
    ErrorCode.SIGNATURE_INVALID: "Could not verify the package signature.",
    ErrorCode.UNWRAP_FAILED: "Could not unwrap the package key.",
    ErrorCode.AES_KEY_LENGTH_INVALID: "Invalid content key length.",
    ErrorCode.GCM_AUTH_FAILED: "Could not authenticate the package contents.",
    ErrorCode.PAYLOAD_INVALID: "The decrypted content has an invalid structure.",
    ErrorCode.SAVE_FAILED: "Could not save the file. You can choose another location.",
    ErrorCode.DESTINATION_EXISTS: "The destination file already exists. Confirm before replacing it.",
    ErrorCode.PROTECTED_PATH: "The destination overlaps protected data.",
    ErrorCode.SAVE_STATE_UNKNOWN: "The save result is uncertain. Check the destination before trying again.",
    ErrorCode.INVALID_HANDLE: "The pending save is no longer valid.",
    ErrorCode.BUSY: "Another operation is running or waiting to be saved.",
    ErrorCode.HISTORY_INVALID: "Could not read or update valid history.",
    ErrorCode.HISTORY_TOO_LARGE: "The history exceeds the allowed size limit.",
    ErrorCode.INTEGRATION_UNAVAILABLE: "An application component is unavailable.",
    ErrorCode.INTERNAL_ERROR: "Could not complete the operation.",
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
