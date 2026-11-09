from dataclasses import dataclass
import os
from pathlib import Path

from .crypto_ops import CryptoOps
from .envelope import EnvelopeCodec
from .history import JsonHistoryStore
from .keys import KeyStore
from .service import FileShareService
from .storage import LocalStorage
from .trust_store import TrustStore


@dataclass
class Application:
    keys: KeyStore
    trust: TrustStore
    storage: LocalStorage
    service: FileShareService


def default_root():
    return Path(os.environ.get('LOCALAPPDATA', Path.home() / '.local' / 'share')) / 'Shared-Files-Security'


def create_application(root=None):
    root = Path(root if root is not None else default_root()).resolve()
    keys = KeyStore(root)
    trust = TrustStore(root, keys)
    storage = LocalStorage(protected_roots=(root,))
    history_root = root / 'history'
    history_root.mkdir(parents=True, exist_ok=True)
    history = JsonHistoryStore(history_root, LocalStorage())
    service = FileShareService(keys=keys, trust=trust, crypto=CryptoOps(),
                               envelope=EnvelopeCodec(), storage=storage, history=history)
    return Application(keys, trust, storage, service)
