"""Credential storage interface for BankShield WebAuthn (Python).

A production deployment must replace ``InMemoryCredentialStore`` with a
database-backed store implementing the same interface. The interface
stores only what the server needs to verify later ceremonies:

- credential id
- public key (COSE-encoded bytes, as returned by the library)
- sign count (replay / clone detection)
- transports

It never stores private key material: the private key never leaves the
authenticator, and there is deliberately no field for it on
``CredentialRecord``.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CredentialRecord:
    """One registered WebAuthn credential, server side only."""

    credential_id: bytes
    user_id: bytes
    public_key: bytes  # COSE-encoded public key bytes from the library.
    sign_count: int = 0
    transports: tuple = ()
    attestation_format: str = "none"
    aaguid: str = ""
    credential_device_type: str = ""
    credential_backed_up: bool = False


class InMemoryCredentialStore:
    """Small in-memory store. Demo and tests only; not for production.

    Production must replace this with a database-backed store with the
    same methods, and with challenges that expire (see ``service.py``).
    """

    def __init__(self) -> None:
        self._by_id: dict = {}
        self._by_user: dict = {}

    def save(self, record: CredentialRecord) -> None:
        self._by_id[record.credential_id] = record
        user_creds = self._by_user.setdefault(record.user_id, [])
        if record.credential_id not in user_creds:
            user_creds.append(record.credential_id)

    def get(self, credential_id: bytes):
        """Return the record for a credential id, or ``None``."""
        return self._by_id.get(credential_id)

    def list_for_user(self, user_id: bytes):
        """Return all records registered for a user, in registration order."""
        return [
            self._by_id[cid]
            for cid in self._by_user.get(user_id, [])
            if cid in self._by_id
        ]

    def update_sign_count(self, credential_id: bytes, new_sign_count: int) -> None:
        record = self._by_id.get(credential_id)
        if record is None:
            raise KeyError(f"unknown credential id: {credential_id.hex()}")
        record.sign_count = new_sign_count
