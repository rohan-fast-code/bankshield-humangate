"""Public interface only. This file contains no finance logic.

An agent may read this file. It will learn the shape of a payment
intent and nothing about fees, limits, fraud rules, or approval.
Real logic lives in the private finance service, which is not
imported here and is not present in this repo.
"""
from dataclasses import dataclass


@dataclass
class PaymentIntent:
    source_account_token: str
    destination_account_token: str
    amount_minor_units: int
    currency: str


@dataclass
class PaymentResult:
    status: str
    reference_token: str
    message: str


class FinanceService:
    """Contract only. No implementation lives in this repo."""

    def submit_payment(self, intent: PaymentIntent) -> PaymentResult:
        raise NotImplementedError(
            "Finance logic is not in this repo. Call the private finance service API."
        )
