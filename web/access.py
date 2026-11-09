"""
Second lock behind Cloudflare Access.

When the web app is published through a Cloudflare tunnel, Cloudflare Access
asks for a login before any request reaches it, then attaches a signed token
(the Cf-Access-Jwt-Assertion header) to every request it lets through. This
module checks that token, so the app refuses to serve anything Cloudflare did
not vouch for, even if the Access policy is ever removed or misconfigured.

It is switched on by two environment variables, set only on the server:

    NMPRO_ACCESS_TEAM   the Zero Trust team name (<team>.cloudflareaccess.com)
    NMPRO_ACCESS_AUD    the Access application's Audience (AUD) tag

With neither set, the check is off, which is how the app runs locally on PT.
With only one set, the app refuses to start rather than run half-protected.
"""

import os

import threading

TEAM = os.environ.get("NMPRO_ACCESS_TEAM", "").strip()
AUD = os.environ.get("NMPRO_ACCESS_AUD", "").strip()

if bool(TEAM) != bool(AUD):
    raise SystemExit("NMPRO_ACCESS_TEAM and NMPRO_ACCESS_AUD must be set together "
                     "(or neither, for local use). Refusing to start.")

ENABLED = bool(TEAM and AUD)
ISSUER = f"https://{TEAM}.cloudflareaccess.com" if ENABLED else ""
CERTS_URL = f"{ISSUER}/cdn-cgi/access/certs" if ENABLED else ""

# Paths answered without a token. Only the bare health check, which reveals
# nothing; the watchdog on BBB polls it locally.
OPEN_PATHS = {"/healthz"}

_jwks = None
_jwks_lock = threading.Lock()


def _client():
    """Cloudflare's signing keys, fetched once and cached (PyJWT refreshes them)."""
    global _jwks
    with _jwks_lock:
        if _jwks is None:
            from jwt import PyJWKClient
            _jwks = PyJWKClient(CERTS_URL, cache_keys=True, lifespan=3600)
        return _jwks


def identity(token):
    """
    Return the verified claims for a Cloudflare Access token, or raise.

    Checks the signature against Cloudflare's published keys, the expiry, the
    issuer (our team) and the audience (this application only).
    """
    import jwt
    key = _client().get_signing_key_from_jwt(token).key
    return jwt.decode(token, key, algorithms=["RS256"],
                      audience=AUD, issuer=ISSUER)


def token_from(request):
    """The Access token from the header Cloudflare adds, or its cookie."""
    return (request.headers.get("Cf-Access-Jwt-Assertion")
            or request.cookies.get("CF_Authorization") or "")
