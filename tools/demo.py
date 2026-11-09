"""Run with: python -m tools.demo. All demo keys live in a temporary folder."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from secure_share.application import create_application
from secure_share.errors import ErrorCode
from secure_share.models import OperationStatus, ReceiveRequest, SendRequest, WarningCode


def prepare_demo(root):
    app = create_application(root)
    password = b'Demo-only-password-123'
    for name in ('alice', 'bob', 'mallory'):
        app.keys.create_profile(name, name.title(), password)
    for owner, contact in [('alice', 'bob'), ('bob', 'alice'), ('mallory', 'alice')]:
        app.trust.import_contact(owner, contact, app.keys.public_bundle(contact))
        profile = app.keys.get_profile(contact)
        app.trust.verify_contact(owner, contact, profile.encryption_fingerprint, profile.signing_fingerprint)
    return app, password


def run_demo(root):
    root = Path(root)
    app, password = prepare_demo(root / 'private')
    source, package, output = root / 'survey.txt', root / 'survey.sfile', root / 'restored.txt'
    source.write_bytes('Dữ liệu khảo sát giả để demo.\n'.encode('utf-8'))
    outcomes = {}
    sent = app.service.send_file(SendRequest('alice', 'bob', source, package, password))
    outcomes['send'] = sent.status is OperationStatus.SUCCESS
    if not outcomes['send']:
        return outcomes
    received = app.service.prepare_receive(ReceiveRequest('bob', package, password))
    outcomes['receive'] = received.status is OperationStatus.PREPARED
    if received.prepared:
        saved = app.service.save_received(received.prepared.handle, output)
        outcomes['exact_content'] = saved.status is OperationStatus.SUCCESS and output.read_bytes() == source.read_bytes()
    wrong_user = app.service.prepare_receive(ReceiveRequest('mallory', package, password))
    outcomes['wrong_recipient_blocked'] = bool(wrong_user.error and wrong_user.error.code is ErrorCode.RECIPIENT_KEY_NOT_FOUND)
    wrong_password = app.service.prepare_receive(ReceiveRequest('bob', package, b'wrong'))
    outcomes['wrong_password_blocked'] = bool(wrong_password.error and wrong_password.error.code is ErrorCode.KEY_UNLOCK_FAILED)
    duplicate = app.service.prepare_receive(ReceiveRequest('bob', package, password))
    outcomes['duplicate_warning'] = WarningCode.DUPLICATE_TRANSFER in duplicate.warnings
    if duplicate.prepared:
        app.service.discard_prepared(duplicate.prepared.handle)
    import base64
    document = json.loads(package.read_bytes())
    signature = bytearray(base64.b64decode(document['signature_b64']))
    signature[0] ^= 1
    document['signature_b64'] = base64.b64encode(signature).decode('ascii')
    package.write_text(json.dumps(document), encoding='utf-8')
    tampered = app.service.prepare_receive(ReceiveRequest('bob', package, password))
    outcomes['tampering_blocked'] = bool(tampered.error and tampered.error.code is ErrorCode.SIGNATURE_INVALID)
    app.service.close()
    return outcomes


def main():
    with TemporaryDirectory(prefix='sfile-demo-') as temporary:
        outcomes = run_demo(temporary)
    print(json.dumps(outcomes, indent=2))
    return 0 if outcomes and all(outcomes.values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
