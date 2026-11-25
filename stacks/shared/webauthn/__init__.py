"""BankShield HumanGate: real WebAuthn server-side verification (Python).

This package replaces the demo-only passkey flag (``pk=1``) in the shared
gate with a real WebAuthn registration ceremony and authentication
ceremony, using the ``webauthn`` library (duo-labs py_webauthn, PyPI
package ``webauthn``).

Layout:

- ``store.py`` -- credential record and in-memory credential store.
- ``service.py`` -- ``WebAuthnService``: the four ceremonies.
- ``gate_wiring.py`` -- turns a verified authentication into the gate's
  passkey proof (``pk=1``) for a subsequent ``decide()`` call.

The gate itself (``stacks/shared/gate_reference.py``) is untouched: no
decision logic, weight, decision order, or test vector changes. WebAuthn
is the real path that produces the proof the gate consumes.

Import note: this directory is named ``webauthn``, the same name as the
PyPI library it wraps, so importing this package can shadow the library
on ``sys.path``. ``service.py`` handles that: it loads the real library
by briefly swapping this package out of ``sys.modules`` and removing this
package's parent directory from ``sys.path``. Callers just do
``from webauthn.service import WebAuthnService`` with
``stacks/shared`` on ``sys.path``.

The library needs to be installed (``webauthn`` 3.x). It is not a
dependency of the gate itself: the gate has zero dependencies.
"""
