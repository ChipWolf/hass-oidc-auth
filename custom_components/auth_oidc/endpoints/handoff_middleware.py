"""Middleware that triggers proxy-login for unauthenticated Envoy requests.

When Envoy Gateway forwards a request with ``forwardAccessToken: true``,
every request reaching HA carries an ``Authorization: Bearer <keycloak_token>``
header.  After the token-handoff flow completes, the user has HA credentials
and active refresh tokens stored server-side.

The middleware uses lightweight JWT introspection (no signature verification,
Envoy already validated the token) to determine whether the bearer token was
issued by Keycloak.  It then checks HA's in-memory auth store for existing
credentials and active refresh tokens for the user's ``sub`` claim.

Decision matrix:
  +-----------------+--------------------+-------------------------------+
  | Bearer issuer   | HA session exists   | Action                        |
  +-----------------+--------------------+-------------------------------+
  | Keycloak        | no                 | 302 -> /auth/oidc/proxy-login |
  | Keycloak        | yes                | pass through                  |
  | Not Keycloak    | any                | pass through                  |
  | No bearer       | any                | pass through                  |
  +-----------------+--------------------+-------------------------------+
"""

import base64
import json
import logging
import time

from aiohttp import web

from ..tools.oidc_client import OIDCClient

_LOGGER = logging.getLogger(__name__)

# Paths that must never be intercepted by the middleware.
_PASSTHROUGH_PREFIXES = (
    "/auth/oidc/",       # All plugin endpoints (proxy-login, handoff-complete, proxy-logout)
    "/auth/login_flow",  # HA login flow API (used by handoff-complete JS)
    "/auth/token",       # HA token exchange endpoint
    "/auth/authorize",   # HA authorize page
    "/auth/providers",   # HA auth providers list
    "/api/",             # HA REST API + WebSocket (frontend sends its own bearer)
    "/static/",          # Static assets
    "/frontend_latest/", # HA frontend bundles
    "/frontend_es5/",    # HA frontend bundles (legacy)
    "/hacsfiles/",       # HACS static files
    "/local/",           # HA local static files
    "/service_worker.js",
    "/manifest.json",
)

# Provider type and id used by this plugin.
_PROVIDER_TYPE = "auth_oidc"
_PROVIDER_ID = "default"


def _decode_jwt_payload(token: str) -> dict | None:
    """Decode the payload of a JWT without signature verification.

    Returns the parsed claims dict, or None if the token is malformed.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload_bytes)
    except Exception:  # noqa: BLE001
        return None


def _has_active_session(hass, sub: str) -> bool:
    """Check if a Keycloak sub has HA credentials AND active refresh tokens.

    Performs an in-memory scan of HA's auth store.  For the typical HA user
    count (single digits) this is effectively instant.
    """
    # pylint: disable=protected-access
    try:
        users = hass.auth._store._users
    except AttributeError:
        _LOGGER.debug("handoff_middleware: unable to access auth store")
        return False

    now = time.time()

    for user in users.values():
        if user.system_generated or not user.is_active:
            continue

        # Look for OIDC credentials matching this sub.
        has_oidc_cred = False
        for cred in user.credentials:
            if (
                cred.auth_provider_type == _PROVIDER_TYPE
                and cred.auth_provider_id == _PROVIDER_ID
                and cred.data.get("sub") == sub
            ):
                has_oidc_cred = True
                break

        if not has_oidc_cred:
            continue

        # Check for at least one active (non-expired) normal refresh token.
        for rt in user.refresh_tokens.values():
            if rt.token_type != "normal":
                continue
            if rt.expire_at is not None and rt.expire_at <= now:
                continue
            return True

        # Credentials exist but no active tokens.
        return False

    return False


def create_handoff_middleware(oidc_client: OIDCClient) -> web.middleware:
    """Return an aiohttp middleware that redirects un-handed-off Keycloak requests.

    Args:
        oidc_client: The OIDC client instance, used to resolve the expected
            Keycloak issuer from the discovery document.
    """
    hass = oidc_client.hass

    @web.middleware
    async def handoff_middleware(
        request: web.Request,
        handler,
    ) -> web.StreamResponse:
        path = request.path

        # 1. Never intercept plugin, API, or static paths.
        for prefix in _PASSTHROUGH_PREFIXES:
            if path.startswith(prefix) or path == prefix.rstrip("/"):
                return await handler(request)

        # 2. If there is no bearer token at all, pass through.
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return await handler(request)

        token = auth_header[len("Bearer "):]

        # 3. Decode the JWT payload to check the issuer.
        claims = _decode_jwt_payload(token)
        if claims is None:
            return await handler(request)

        # 4. Compare issuer against the Keycloak issuer from OIDC discovery.
        expected_issuer = None
        try:
            discovery = oidc_client.discovery_document
            if discovery:
                expected_issuer = discovery.get("issuer")
        except Exception:  # noqa: BLE001
            pass

        if not expected_issuer:
            _LOGGER.debug(
                "handoff_middleware: discovery not loaded yet, passing through"
            )
            return await handler(request)

        token_issuer = claims.get("iss")
        if token_issuer != expected_issuer:
            return await handler(request)

        # 5. Token IS from Keycloak. Check HA auth state for this user.
        sub = claims.get("sub")
        if not sub:
            return await handler(request)

        if _has_active_session(hass, sub):
            return await handler(request)

        # 6. Keycloak token present, no active HA session: trigger handoff.
        _LOGGER.debug(
            "handoff_middleware: Keycloak token for sub=%s on %s with no "
            "active HA session, redirecting to proxy-login",
            sub,
            path,
        )
        raise web.HTTPFound(location="/auth/oidc/proxy-login")

    return handoff_middleware
