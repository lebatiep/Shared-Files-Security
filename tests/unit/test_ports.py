"""Ensure the built-in adapters retain the service's protocol shape."""

from secure_share.crypto_ops import CryptoOps
from secure_share.envelope import EnvelopeCodec as EnvelopeCodecAdapter
from secure_share.history import JsonHistoryStore, MemoryHistoryStore
from secure_share.keys import KeyStore
from secure_share.ports import (
    CryptoProvider,
    EnvelopeCodec as EnvelopeCodecPort,
    HistoryPort,
    KeyProvider,
    StoragePort,
    TrustProvider,
)
from secure_share.storage import LocalStorage
from secure_share.trust_store import TrustStore


def test_builtin_adapters_satisfy_service_protocols(tmp_path):
    storage = LocalStorage()
    keys = KeyStore(tmp_path)
    adapters = (
        (storage, StoragePort),
        (keys, KeyProvider),
        (TrustStore(tmp_path, keys), TrustProvider),
        (CryptoOps(), CryptoProvider),
        (EnvelopeCodecAdapter(), EnvelopeCodecPort),
        (JsonHistoryStore(tmp_path / "history", storage), HistoryPort),
        (MemoryHistoryStore(), HistoryPort),
    )

    for adapter, protocol in adapters:
        assert isinstance(adapter, protocol), f"{type(adapter).__name__} does not satisfy {protocol.__name__}"
