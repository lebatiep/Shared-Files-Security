# Key lifecycle and trust management

## Interfaces

`secure_share.keys.KeyStore` manages encrypted local profiles. Each generation
contains two different RSA-3072 keys with e=65537: encryption and signing.
Private keys use encrypted PKCS8 PEM; public keys use PEM SPKI. Fingerprints
are calculated only in `keys.py` as the project's SHA-256 of DER SPKI.

The existing APIs and schema are retained:

- `create_profile`, `get_profile`, `list_profiles`, `public_bundle`.
- `resolve_decryption_key` and `unlock_private_key` select the exact role and
  fingerprint, including retained historical encryption keys.
- `rotate_keys` preserves all generations, up to the existing limit of 10.
- `backup_profile` checks every retained private key before returning bytes.
- `restore_profile` checks every retained key before writing a new profile;
  it does not overwrite an existing profile or restore contact trust.

Profiles are version 1 JSON with `profile_id`, `display_name`, and `generations`.
Each generation has `encryption` and `signing` entries containing `public` and
encrypted `private` PEM. The profile limit remains 262,144 bytes.
Passphrases are UTF-8 bytes, at least the shared minimum of 12 characters,
at most 1,024 bytes, and cannot consist entirely of whitespace.

Public bundles contain exactly `version`, `display_name`,
`encryption_public_key`, and `signing_public_key`. Import validates the schema,
key type, size, exponent, and distinct roles. A public bundle is not proof of
identity and must never contain private PEM.

## Trust transitions

`secure_share.trust_store.TrustStore` keeps contacts separate for each profile.

1. `import_contact` creates an unverified contact.
2. `find_name_conflicts` finds other contacts with the same display name but
   different keys; the desktop UI warns before the new contact is trusted.
3. Both complete fingerprints must be compared with the owner through an
   independent authenticated channel before `verify_contact` is called.
4. `resolve_recipient` and `resolve_sender` only return verified contacts.
5. `disable_contact` prevents further use; importing or verifying that same
   contact cannot silently reenable it.

Reimporting an unchanged key pair preserves the original name, status, and file
bytes. Replacing a different pair requires explicit `replace=True` and resets
trust to unverified. The UI uses a new contact ID for a key change so old pins
remain available. Exact display-name matching is only a warning mechanism,
not identity verification or a full PKI.

## Persistence and errors

Profile and contact writes use the existing `LocalStorage.save_atomic`.
Known write failures preserve the old destination and clean the operation's
temporary file. Invalid JSON, duplicate fields, invalid roles, malformed PEM,
wrong passphrases, and mismatched private/public keys are rejected. Corrupt
profiles or trust files are not silently replaced or reset.

Backup, rotation, and restore all check every retained private key, not just
the current signing key. This prevents a corrupt historical or encryption key
from being silently carried into a new profile or backup. Unsupported private
key encryption is reported as `KEY_UNLOCK_FAILED` without library details.

Backups contain encrypted private PEM but readable public metadata. They are
private backups, not public bundles. Lost keys require a retained backup and
its passphrase; a lost passphrase has no bypass. Changing active keys does not
revoke old packages or prevent recipients from forwarding plaintext.

Storage and OS access controls must protect the local trust state: schema
validation does not detect an attacker with write access changing a stored
contact from unverified to verified. Crash-time temporary-file recovery and
platform-specific access-control auditing remain separate storage work.

## Application integration

The refactor had removed `CryptoOps`, `EnvelopeCodec`, and shared JSON helpers
while callers still imported them. Their interfaces are restored around the
current handwritten primitives. No AES/OAEP/PSS operations are delegated to a
cryptographic library; `cryptography` supplies key generation, PEM serialization,
and key objects. Signature verification returns `None` on success and raises a
domain error on failure, as required by the service port.

OAEP decoding rejects invalid padding separately from a valid OAEP payload
whose decoded AES key is not 32 bytes. The service receives `UNWRAP_FAILED` or
`AES_KEY_LENGTH_INVALID` respectively. GCM authentication completes before
plaintext is returned. Raw header bytes remain unchanged through parsing,
signature verification, and AAD construction.

## Verification

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Regression tests cover profile restart and recovery, retained historical keys,
corrupt or mismatched private keys, invalid public keys and passphrases, failed
atomic writes, pin preservation, disabled contacts, same-name key changes, and
the headless UI warning. Adapter tests compare the handwritten primitives with
an independent reference implementation and exercise the restored service APIs.

Tests use temporary profiles and test-only keys, not user identities. Automated
results do not replace independent review, the complete PDF acceptance matrix,
manual GUI checks, or a security audit. Python does not guarantee constant-time
private-key arithmetic or reliable erasure of secrets from memory.

For this change, the non-desktop suite passed 203 tests and 186 subtests.
After adding a UTF-8 display-name regression, the affected key/trust/UI subset
passed all 42 tests. Desktop tests excluding the five file-size round trips
passed all 76 cases. The four small round trips passed in the earlier run;
the 10 MiB round trip was interrupted after about 5 minutes 35 seconds and
remains unverified. This elapsed time is not a controlled benchmark.
