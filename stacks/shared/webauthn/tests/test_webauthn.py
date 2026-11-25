"""Unit tests for the Python WebAuthn ceremonies.

The tests use a simulated authenticator, not a real one: each test
generates a fresh ES256 (P-256) credential keypair, runs a full
registration ceremony and then an authentication ceremony through
``WebAuthnService``, and asserts verification succeeds. Failure cases
assert a tampered signature fails, a wrong origin fails, and a replayed
challenge fails.

A real passkey check on a real phone or security key still needs a real
authenticator and is NOT covered by these tests.

Run from ``stacks/shared`` with the venv Python (the ``webauthn``
library lives in the venv, not in the system Python)::

    ~/workspace/bankshield-webauthn-venv/bin/python -m unittest discover -s webauthn/tests -v
"""
import base64
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )
    ),
)  # stacks/shared, so "webauthn" (this package) is importable

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from webauthn.gate_wiring import (
    passkey_proof_from_verified_authentication,
    signals_with_passkey_proof,
)
from webauthn.service import (
    ChallengeNotFoundError,
    VerificationFailedError,
    WebAuthnService,
)
from webauthn.store import InMemoryCredentialStore

# Test-only relying party. Not a production origin; the service takes
# rp_id and origin from the caller and nothing here is hardcoded in it.
RP_ID = "bankshield.example"
RP_NAME = "BankShield Test"
ORIGIN = "https://bankshield.example"
USER_ID = b"test-user-001"
USER_NAME = "rohan@example.test"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _client_data_json(challenge: bytes, origin: str, kind: str) -> bytes:
    return json.dumps(
        {
            "type": f"webauthn.{kind}",
            "challenge": _b64u(challenge),
            "origin": origin,
        },
        separators=(",", ":"),
    ).encode("utf-8")


class SimulatedAuthenticator:
    """A minimal in-test authenticator: generates a P-256 keypair and
    answers registration and authentication ceremonies with fmt "none"
    attestation, exactly as a platform authenticator with no attestation
    statement would. The private key never leaves this object."""

    def __init__(self) -> None:
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        public_numbers = self.private_key.public_key().public_numbers()
        self.credential_id = os.urandom(32)
        self._x = public_numbers.x.to_bytes(32, "big")
        self._y = public_numbers.y.to_bytes(32, "big")
        self.sign_count = 0

    def _auth_data(self, rp_id: str, flags: int, with_credential: bool) -> bytes:
        auth_data = hashlib.sha256(rp_id.encode("utf-8")).digest()
        auth_data += bytes([flags])
        auth_data += self.sign_count.to_bytes(4, "big")
        if with_credential:
            cose_key = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: self._x, -3: self._y})
            auth_data += b"\x00" * 16  # AAGUID: all zeroes, fmt "none"
            auth_data += len(self.credential_id).to_bytes(2, "big")
            auth_data += self.credential_id
            auth_data += cose_key
        return auth_data

    def registration_response(self, challenge: bytes, rp_id: str = RP_ID,
                              origin: str = ORIGIN) -> dict:
        client_data = _client_data_json(challenge, origin, "create")
        auth_data = self._auth_data(rp_id, flags=0x45, with_credential=True)
        attestation_object = cbor2.dumps(
            {"fmt": "none", "attStmt": {}, "authData": auth_data}
        )
        return {
            "id": _b64u(self.credential_id),
            "rawId": _b64u(self.credential_id),
            "type": "public-key",
            "response": {
                "attestationObject": _b64u(attestation_object),
                "clientDataJSON": _b64u(client_data),
                "transports": ["internal"],
            },
        }

    def authentication_response(self, challenge: bytes, rp_id: str = RP_ID,
                                origin: str = ORIGIN, sign_count=None,
                                tamper_signature: bool = False) -> dict:
        self.sign_count += 1
        count = self.sign_count if sign_count is None else sign_count
        client_data = _client_data_json(challenge, origin, "get")
        auth_data = hashlib.sha256(rp_id.encode("utf-8")).digest()
        auth_data += bytes([0x05])  # user present + user verified
        auth_data += count.to_bytes(4, "big")
        signature = self.private_key.sign(
            auth_data + hashlib.sha256(client_data).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
        if tamper_signature:
            signature = signature[:-1] + bytes([signature[-1] ^ 0x01])
        return {
            "id": _b64u(self.credential_id),
            "rawId": _b64u(self.credential_id),
            "type": "public-key",
            "response": {
                "authenticatorData": _b64u(auth_data),
                "clientDataJSON": _b64u(client_data),
                "signature": _b64u(signature),
                "userHandle": _b64u(USER_ID),
            },
        }


def _register(service, authenticator):
    options, challenge = service.begin_registration(
        USER_ID, USER_NAME, "Test User"
    )
    response = authenticator.registration_response(challenge)
    return service.finish_registration(USER_ID, response), options


class WebAuthnServiceTest(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryCredentialStore()
        self.service = WebAuthnService(
            rp_id=RP_ID, rp_name=RP_NAME, origin=ORIGIN, store=self.store
        )
        self.authenticator = SimulatedAuthenticator()

    def test_full_registration_then_authentication_succeeds(self):
        registered, _ = _register(self.service, self.authenticator)
        self.assertTrue(registered.verified)
        self.assertEqual(registered.credential_id, self.authenticator.credential_id)
        self.assertEqual(registered.attestation_format, "none")
        self.assertIn("no attestation statement", registered.trust_path)
        self.assertEqual(registered.sign_count, 0)

        stored = self.store.get(self.authenticator.credential_id)
        self.assertIsNotNone(stored)
        self.assertEqual(stored.user_id, USER_ID)
        self.assertTrue(stored.public_key)
        # No private key material is ever stored.
        self.assertFalse(hasattr(stored, "private_key"))

        _, challenge = self.service.begin_authentication(USER_ID)
        response = self.authenticator.authentication_response(challenge)
        verified = self.service.finish_authentication(USER_ID, response)
        self.assertTrue(verified.verified)
        self.assertEqual(verified.new_sign_count, 1)
        self.assertEqual(
            self.store.get(self.authenticator.credential_id).sign_count, 1
        )

    def test_tampered_signature_fails(self):
        _register(self.service, self.authenticator)
        _, challenge = self.service.begin_authentication(USER_ID)
        response = self.authenticator.authentication_response(
            challenge, tamper_signature=True
        )
        with self.assertRaises(VerificationFailedError):
            self.service.finish_authentication(USER_ID, response)

    def test_wrong_origin_fails_registration_and_authentication(self):
        _, challenge = self.service.begin_registration(
            USER_ID, USER_NAME, "Test User"
        )
        response = self.authenticator.registration_response(
            challenge, origin="https://evil.example"
        )
        with self.assertRaises(VerificationFailedError):
            self.service.finish_registration(USER_ID, response)

        _register(self.service, self.authenticator)
        _, challenge = self.service.begin_authentication(USER_ID)
        response = self.authenticator.authentication_response(
            challenge, origin="https://evil.example"
        )
        with self.assertRaises(VerificationFailedError):
            self.service.finish_authentication(USER_ID, response)

    def test_replayed_challenge_fails(self):
        # Registration challenge: same response verified twice.
        _, challenge = self.service.begin_registration(
            USER_ID, USER_NAME, "Test User"
        )
        response = self.authenticator.registration_response(challenge)
        self.service.finish_registration(USER_ID, response)
        with self.assertRaises(ChallengeNotFoundError):
            self.service.finish_registration(USER_ID, response)

        # Authentication challenge: same response verified twice.
        _, challenge = self.service.begin_authentication(USER_ID)
        response = self.authenticator.authentication_response(challenge)
        self.service.finish_authentication(USER_ID, response)
        with self.assertRaises(ChallengeNotFoundError):
            self.service.finish_authentication(USER_ID, response)

    def test_sign_count_that_does_not_advance_fails(self):
        _register(self.service, self.authenticator)
        _, challenge = self.service.begin_authentication(USER_ID)
        response = self.authenticator.authentication_response(challenge)
        self.service.finish_authentication(USER_ID, response)
        # Replay the same counter value (1) with a fresh challenge: the
        # signature is valid, but the counter did not advance.
        _, challenge = self.service.begin_authentication(USER_ID)
        response = self.authenticator.authentication_response(
            challenge, sign_count=1
        )
        with self.assertRaises(VerificationFailedError):
            self.service.finish_authentication(USER_ID, response)

    def test_unknown_credential_fails(self):
        _register(self.service, self.authenticator)
        stranger = SimulatedAuthenticator()
        _, challenge = self.service.begin_authentication(USER_ID)
        response = stranger.authentication_response(challenge)
        with self.assertRaises(VerificationFailedError):
            self.service.finish_authentication(USER_ID, response)

    def test_gate_wiring_turns_verified_auth_into_pk1(self):
        from gate_reference import decide

        _register(self.service, self.authenticator)
        _, challenge = self.service.begin_authentication(USER_ID)
        response = self.authenticator.authentication_response(challenge)
        verified = self.service.finish_authentication(USER_ID, response)

        self.assertEqual(passkey_proof_from_verified_authentication(verified), 1)
        base_signals = {
            "r": "pay", "pk": 0, "dp": 1, "dt": 1, "sk": 1, "nr": 0,
            "dm": 0, "hl": 0, "mb": 0, "dc": 0, "rpm": 12, "cov": 8,
            "tv": 1.4, "ov": 0, "np": 0, "amt": 45000,
        }
        self.assertEqual(decide(base_signals), "C")  # no passkey proof
        with_proof = signals_with_passkey_proof(base_signals, verified)
        self.assertEqual(with_proof["pk"], 1)
        self.assertEqual(base_signals["pk"], 0)  # caller dict untouched
        self.assertEqual(decide(with_proof), "A")  # full proof, low score

        class Unverified:
            verified = False

        with self.assertRaises(ValueError):
            passkey_proof_from_verified_authentication(Unverified())


if __name__ == "__main__":
    unittest.main()
