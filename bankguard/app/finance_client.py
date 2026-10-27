"""Client for the private finance service. It decides nothing.

It sends an intent and returns the service result. Fees, limits,
fraud checks, ledger writes, and signatures all happen on the
service side, behind authentication, attestation, and risk checks.
"""
from app.finance_interface import PaymentIntent, PaymentResult


def submit_payment_via_service(intent: PaymentIntent, service_url: str) -> PaymentResult:
    # In production, this call uses a short lived sender bound token,
    # attestation, and a transaction signature bound to amount and payee.
    # The demo below returns a placeholder so the UI can run without
    # real money or real customer data. Replace service_url with the
    # private service endpoint in a real deployment. Never put the
    # service secret in this file.
    _ = service_url
    return PaymentResult(
        status="PENDING_SERVICE_DECISION",
        reference_token="demo_token_only",
        message="Decision is made by the private finance service, not by this client.",
    )
