"""Wiring from a verified WebAuthn authentication to the gate (Python).

This is the only bridge between the WebAuthn ceremonies and the gate:
a verified authentication ceremony produces the gate's passkey proof
(``pk=1``) for a subsequent ``decide()`` call. Nothing here changes
any gate decision logic, weight, decision order, or test vector.

The rule is strict: ``pk=1`` is produced only from a
``VerifiedAuthenticationResult`` whose ``verified`` flag is true, which
only ``WebAuthnService.finish_authentication`` returns after the
library has verified the challenge, origin, relying party id,
signature, and sign count. An unverified or failed ceremony never
produces ``pk=1``.

Example (caller supplies ``decide`` from ``gate_reference.py``)::

    from gate_reference import decide
    from webauthn.gate_wiring import signals_with_passkey_proof

    verified = service.finish_authentication(user_id, credential)
    signals = signals_with_passkey_proof(base_signals, verified)
    decision = decide(signals)  # "A" only if the full proof holds
"""
from __future__ import annotations


def passkey_proof_from_verified_authentication(verified_result) -> int:
    """Return the gate's passkey proof (``pk=1``) for a verified
    authentication ceremony. Raises ``ValueError`` for anything that
    is not a verified result, so an unverified ceremony can never
    silently become a passkey proof."""
    if not getattr(verified_result, "verified", False):
        raise ValueError(
            "cannot produce a passkey proof from an unverified "
            "authentication result"
        )
    return 1


def signals_with_passkey_proof(signals, verified_result):
    """Return a copy of ``signals`` with ``pk=1`` set from a verified
    authentication ceremony. The caller's dict is not mutated."""
    proof = passkey_proof_from_verified_authentication(verified_result)
    updated = dict(signals)
    updated["pk"] = proof
    return updated
