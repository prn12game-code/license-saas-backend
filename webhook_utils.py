"""
Webhook delivery system for LicenseHub.

When an invoice is marked paid, this module fires a POST request
to the user's configured webhook URL with a signed JSON payload.

Payload format:
{
  "event": "invoice.paid",
  "timestamp": "2025-01-15T10:30:00Z",
  "data": {
    "invoice_id": 42,
    "customer_name": "Acme Corp",
    "customer_email": "billing@acme.com",
    "total": 299.0,
    "currency": "USD"
  }
}

Security:
  Every request includes an X-LicenseHub-Signature header.
  Value: sha256=HMAC(webhook_secret, raw_body)
  Receivers can verify this to confirm the request came from LicenseHub.
"""

import hmac
import hashlib
import json
import threading
from datetime import datetime, timezone
import urllib.request
import urllib.error


def _build_payload(event: str, invoice) -> dict:
    return {
        "event": event,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {
            "invoice_id": invoice.id,
            "customer_name": invoice.customer_name,
            "customer_email": invoice.customer_email,
            "total": invoice.total,
            "currency": getattr(invoice, "currency", "USD"),
            "status": invoice.status,
        }
    }


def _sign(secret: str, body: bytes) -> str:
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


def _deliver(url: str, payload: dict, secret: str | None):
    """Send the webhook. Runs in a background thread so it never blocks the API."""
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "LicenseHub-Webhook/2.0",
    }
    if secret:
        headers["X-LicenseHub-Signature"] = _sign(secret, body)

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            print(f"[webhook] {url} → {status}")
    except urllib.error.HTTPError as e:
        print(f"[webhook] HTTP error {e.code} for {url}")
    except Exception as e:
        print(f"[webhook] Failed to reach {url}: {e}")


def fire(event: str, invoice, webhook_url: str, webhook_secret: str | None = None):
    """
    Fire a webhook in a background thread.
    Call this from your route handler after marking invoice as paid.

    Args:
        event:          e.g. "invoice.paid"
        invoice:        SQLAlchemy Invoice object
        webhook_url:    user's configured URL
        webhook_secret: optional HMAC secret for signature
    """
    if not webhook_url or not webhook_url.startswith(("http://", "https://")):
        return

    payload = _build_payload(event, invoice)
    thread = threading.Thread(
        target=_deliver,
        args=(webhook_url, payload, webhook_secret),
        daemon=True,
    )
    thread.start()
