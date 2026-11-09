import hashlib
import secrets

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import ErrorCode, ShareError


def validate_public_key(key):
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 3072 or key.public_numbers().e != 65537:
        raise ShareError(ErrorCode.PROFILE_INVALID)
    return key


def fingerprint(key):
    validate_public_key(key)
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def public_pem(key):
    validate_public_key(key)
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')


def load_public(pem):
    try:
        if not isinstance(pem, str) or len(pem) > 2048:
            raise ValueError
        return validate_public_key(serialization.load_pem_public_key(pem.encode('ascii')))
    except (ValueError, TypeError, UnicodeError):
        raise ShareError(ErrorCode.PROFILE_INVALID) from None


def oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b'')


def pss():
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


class CryptoOps:
    def generate_aes_key(self):
        return secrets.token_bytes(32)

    def generate_nonce(self):
        return secrets.token_bytes(12)

    def wrap_key(self, aes_key, public_key):
        if len(aes_key) != 32:
            raise ShareError(ErrorCode.AES_KEY_LENGTH_INVALID)
        return validate_public_key(public_key).encrypt(aes_key, oaep())

    def unwrap_key(self, wrapped_key, private_key):
        try:
            key = private_key.decrypt(wrapped_key, oaep())
        except ValueError:
            raise ShareError(ErrorCode.UNWRAP_FAILED) from None
        if len(key) != 32:
            raise ShareError(ErrorCode.AES_KEY_LENGTH_INVALID)
        return key

    def encrypt_payload(self, key, nonce, payload, aad):
        if len(key) != 32 or len(nonce) != 12:
            raise ShareError(ErrorCode.INVALID_LENGTH)
        return AESGCM(key).encrypt(nonce, payload, aad)

    def decrypt_payload(self, key, nonce, ciphertext, aad):
        if len(key) != 32 or len(nonce) != 12:
            raise ShareError(ErrorCode.INVALID_LENGTH)
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            raise ShareError(ErrorCode.GCM_AUTH_FAILED) from None

    def sign_package(self, message, private_key):
        return private_key.sign(message, pss(), hashes.SHA256())

    def verify_signature(self, signature, message, public_key):
        try:
            validate_public_key(public_key).verify(signature, message, pss(), hashes.SHA256())
        except (InvalidSignature, ValueError):
            raise ShareError(ErrorCode.SIGNATURE_INVALID) from None
