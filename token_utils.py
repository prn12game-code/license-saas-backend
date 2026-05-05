"""
token_utils.py — LicenseHub Internal Token System

Tokens are credits users buy to use features (invoices, API calls, etc).
Admin creates packages. Users buy packages. System debits tokens on use.

Flow:
  1. Admin creates a TokenPackage via /api/admin/token-packages
  2. User views available packages via /api/token-packages
  3. Admin grants tokens to a user via /api/admin/grant-tokens (after payment confirmed)
  4. System automatically debits tokens when user performs token-gated actions
  5. Full audit trail in TokenTransaction table
"""

from sqlalchemy.orm import Session
from models import User, TokenPackage, TokenTransaction
from fastapi import HTTPException


def get_balance(user: User) -> int:
    """Return the user's current token balance."""
    return user.token_balance or 0


def grant_tokens(db: Session, user: User, amount: int, reason: str) -> int:
    """
    Credit tokens to a user's balance. Used by admin after payment.
    Returns the new balance.
    """
    if amount <= 0:
        raise ValueError("Grant amount must be positive")

    user.token_balance = (user.token_balance or 0) + amount

    tx = TokenTransaction(
        user_id=user.id,
        delta=amount,
        reason=reason,
        balance_after=user.token_balance,
    )
    db.add(tx)
    db.commit()
    db.refresh(user)
    return user.token_balance


def spend_tokens(db: Session, user: User, amount: int, reason: str) -> int:
    """
    Debit tokens from a user's balance. Raises HTTP 402 if insufficient.
    Returns the new balance.
    """
    if amount <= 0:
        raise ValueError("Spend amount must be positive")

    current = user.token_balance or 0
    if current < amount:
        raise HTTPException(
            status_code=402,
            detail=f"Insufficient tokens. You have {current}, need {amount}. "
                   f"Purchase more tokens to continue."
        )

    user.token_balance = current - amount

    tx = TokenTransaction(
        user_id=user.id,
        delta=-amount,
        reason=reason,
        balance_after=user.token_balance,
    )
    db.add(tx)
    db.commit()
    db.refresh(user)
    return user.token_balance


def get_history(db: Session, user_id: int, limit: int = 50) -> list:
    """Return the last N token transactions for a user."""
    return (
        db.query(TokenTransaction)
        .filter(TokenTransaction.user_id == user_id)
        .order_by(TokenTransaction.created_at.desc())
        .limit(limit)
        .all()
    )


def get_active_packages(db: Session) -> list:
    """Return all active token packages available for purchase."""
    return (
        db.query(TokenPackage)
        .filter(TokenPackage.is_active == True)
        .order_by(TokenPackage.price)
        .all()
    )
