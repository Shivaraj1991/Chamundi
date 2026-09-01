"""
Cookie-based shopping cart.

VULNERABILITY #11 - Insecure Deserialization (OWASP A08:2021 - Software and
Data Integrity Failures).

The cart contents are pickled, base64-encoded, and stored directly in a
client-side cookie with NO signature/HMAC. Django's own session framework
would sign this data automatically, but this cart deliberately bypasses that
protection to demonstrate the bug: since the client fully controls the
`cart_data` cookie, an attacker can craft a malicious pickle payload (e.g. a
class with a `__reduce__` method that runs a command) and get arbitrary code
execution the moment the server calls pickle.loads() on it.

Fix: never unpickle untrusted input. Use Django's signed session storage (or
JSON) for cart data instead.
"""

import base64
import pickle

COOKIE_NAME = "cart_data"


def get_cart(request):
    raw = request.COOKIES.get(COOKIE_NAME)
    if not raw:
        return {}
    try:
        return pickle.loads(base64.b64decode(raw))  # noqa: S301 - intentional vuln
    except Exception:
        return {}


def save_cart(response, cart):
    raw = base64.b64encode(pickle.dumps(cart)).decode()
    response.set_cookie(COOKIE_NAME, raw)
    return response
