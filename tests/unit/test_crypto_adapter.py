import pytest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from secure_share import crypto_ops
from secure_share.crypto_ops import CryptoOps
from secure_share.errors import ErrorCode, ShareError


@pytest.fixture(scope='module')
def private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def test_crypto_adapter_interoperates_with_reference(private_key):
    crypto = CryptoOps()
    key, nonce = crypto.generate_aes_key(), crypto.generate_nonce()
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b'')
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    assert private_key.decrypt(crypto.wrap_key(key, private_key.public_key()), oaep) == key
    assert crypto.unwrap_key(private_key.public_key().encrypt(key, oaep), private_key) == key
    ciphertext = crypto.encrypt_payload(key, nonce, b'payload', b'aad')
    assert ciphertext == AESGCM(key).encrypt(nonce, b'payload', b'aad')
    assert crypto.decrypt_payload(key, nonce, ciphertext, b'aad') == b'payload'
    signature = crypto.sign_package(b'message', private_key)
    private_key.public_key().verify(signature, b'message', pss, hashes.SHA256())
    assert crypto.verify_signature(private_key.sign(b'message', pss, hashes.SHA256()), b'message', private_key.public_key()) is None


def test_app_reads_existing_python_backend_packets(private_key):
    crypto = CryptoOps()
    numbers = private_key.private_numbers()
    n, e = numbers.public_numbers.n, numbers.public_numbers.e
    key, nonce = crypto.generate_aes_key(), crypto.generate_nonce()
    wrapped = crypto_ops.wrap_key(key, n, e)
    ciphertext = crypto_ops.encrypt_payload(b'old package contents', key, nonce, b'header')
    signature = crypto_ops.sign_package(ciphertext, n, numbers.d)
    assert crypto.verify_signature(signature, ciphertext, private_key.public_key()) is None
    assert crypto.unwrap_key(wrapped, private_key) == key
    assert crypto.decrypt_payload(key, nonce, ciphertext, b'header') == b'old package contents'


def test_gcm_interoperates_with_reference_on_multiple_blocks():
    crypto = CryptoOps()
    key, nonce, aad = bytes(range(32)), bytes(range(12)), b'header'
    payload = bytes(range(256)) * 16 + b'partial block'
    expected = AESGCM(key).encrypt(nonce, payload, aad)
    assert crypto.encrypt_payload(key, nonce, payload, aad) == expected
    assert crypto.decrypt_payload(key, nonce, expected, aad) == payload


@pytest.mark.parametrize(('label', 'size'), [
    (b'SFILE2-RECIPIENT-SHARE', 67),
    (b'SFILE2-CONTRIBUTION', 99),
])
def test_threshold_oaep_interoperates_with_reference(private_key, label, size):
    secret = bytes(range(size))
    public_key = private_key.public_key()
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label)
    wrapped = crypto_ops.wrap_threshold_secret(secret, public_key, label)
    assert private_key.decrypt(wrapped, oaep) == secret
    assert crypto_ops.unwrap_threshold_secret(public_key.encrypt(secret, oaep), private_key, label) == secret
    with pytest.raises(ShareError) as error:
        crypto_ops.unwrap_threshold_secret(wrapped, private_key, b'wrong label')
    assert error.value.code is ErrorCode.INVALID_SHARE


def test_crypto_adapter_rejects_invalid_data(private_key):
    crypto = CryptoOps()
    operations = (
        (lambda: crypto.wrap_key(bytes(31), private_key.public_key()), ErrorCode.AES_KEY_LENGTH_INVALID),
        (lambda: crypto.unwrap_key(bytes(384), private_key), ErrorCode.UNWRAP_FAILED),
        (lambda: crypto.decrypt_payload(bytes(32), bytes(12), bytes(16), b''), ErrorCode.GCM_AUTH_FAILED),
        (lambda: crypto.verify_signature(bytes(384), b'message', private_key.public_key()), ErrorCode.SIGNATURE_INVALID),
        (lambda: crypto.wrap_key(bytes(32), object()), ErrorCode.PROFILE_INVALID),
    )
    for operation, code in operations:
        with pytest.raises(ShareError) as error:
            operation()
        assert error.value.code is code


@pytest.mark.parametrize('size', [0, 16, 31, 33])
def test_unwrapped_key_length_has_its_own_error(private_key, size):
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b'')
    wrapped = private_key.public_key().encrypt(bytes(size), oaep)
    with pytest.raises(ShareError) as error:
        CryptoOps().unwrap_key(wrapped, private_key)
    assert error.value.code is ErrorCode.AES_KEY_LENGTH_INVALID
