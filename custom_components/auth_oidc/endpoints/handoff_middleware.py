"""Middleware that triggers proxy-login for Envoy-authenticated requests.

When Envoy Gateway forwards a request with ``forwardAccessToken: true``,
every request reaching HA carries an ``Authorization: Bearer <keycloak_token>``
header.

The middleware uses lightweight JWT introspection (no signature verification,
Envoy already validated the token) to determine whether the bearer token was
issued by Keycloak.  For browser navigation requests (``Accept: text/html``)
bearing a valid Keycloak token, the middleware **always** redirects to
``/auth/oidc/proxy-login`` which performs token exchange and populates the
browser's ``localStorage`` with HA tokens via the handoff-complete page.

Server-side session state is intentionally NOT checked.  HA's frontend
requires ``hassTokens`` in ``localStorage`` to function; when a user opens a
new browser context the server-side credentials still exist but the browser
has nothing.  Skipping the handoff in that case would let HA's frontend fall
through to the manual login page, defeating SSO.  The handoff flow is
idempotent: ``async_get_or_create_credentials`` reuses existing credentials,
and a fresh refresh token per browser session is cheap.  The rate limiter on
``proxy-login`` (30 req/min per source IP) provides sufficient protection.

Decision matrix:
  +-----------------+-------------------------------+
  | Bearer issuer   | Action                        |
  +-----------------+-------------------------------+
  | Keycloak        | 302 -> /auth/oidc/proxy-login |
  | Not Keycloak    | pass through                  |
  | No bearer       | pass through                  |
  +-----------------+-------------------------------+
"""

import base64
import json
import logging
import urllib.parse

from aiohttp import web

from ..tools.oidc_client import OIDCClient

_LOGGER = logging.getLogger(__name__)

# Paths that must never be intercepted by the middleware.
_PASSTHROUGH_PREFIXES = (
    "/auth/oidc/",  # All plugin endpoints (proxy-login, handoff-complete, proxy-logout)
    "/auth/login_flow",  # HA login flow API (used by handoff-complete JS)
    "/auth/token",  # HA token exchange endpoint
    "/auth/providers",  # HA auth providers list
    "/api/",  # HA REST API + WebSocket (frontend sends its own bearer)
    "/static/",  # Static assets
    "/frontend_latest/",  # HA frontend bundles
    "/frontend_es5/",  # HA frontend bundles (legacy)
    "/hacsfiles/",  # HACS static files
    "/local/",  # HA local static files
    "/service_worker.js",
    "/manifest.json",
)


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


def create_handoff_middleware(oidc_client: OIDCClient) -> web.middleware:
    """Return an aiohttp middleware that redirects Keycloak-bearer requests.

    Every browser navigation request carrying a valid Keycloak access token
    is redirected to the proxy-login endpoint, which performs token exchange
    and ensures the browser gets ``hassTokens`` in ``localStorage``.

    Args:
        oidc_client: The OIDC client instance, used to resolve the expected
            Keycloak issuer from the discovery document.
    """

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

        # 2. Only intercept browser navigation requests (Accept: text/html).
        #    Sub-resource requests (images, scripts, favicons, service workers,
        #    XHR/fetch without text/html) must pass through to avoid creating
        #    parallel redirect chains that break the handoff-complete JS flow.
        accept = request.headers.get("Accept", "")
        if "text/html" not in accept:
            return await handler(request)

        # 3. If there is no bearer token at all, pass through.
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return await handler(request)

        token = auth_header[len("Bearer ") :]

        # 4. Decode the JWT payload to check the issuer.
        claims = _decode_jwt_payload(token)
        if claims is None:
            return await handler(request)

        # 5. Compare issuer against the Keycloak issuer from OIDC discovery.
        expected_issuer = None
        try:
            discovery = oidc_client.discovery_document
            if discovery:
                expected_issuer = discovery.get("issuer")
        except Exception:  # noqa: BLE001
            pass

        if not expected_issuer:
            _LOGGER.debug("Discovery document not loaded, passing through")
            return await handler(request)

        token_issuer = claims.get("iss")
        if token_issuer != expected_issuer:
            return await handler(request)

        # 6. Token IS from Keycloak. Check sub claim exists.
        sub = claims.get("sub")
        if not sub:
            _LOGGER.debug("Keycloak token has no sub claim")
            return await handler(request)

        # 7. If the request carries ?oidc_handoff=1, the browser just
        #    completed the handoff flow and has hassTokens.  Pass through
        #    so HA's frontend can load normally.
        if request.query.get("oidc_handoff") == "1":
            return await handler(request)

        # 8. Always redirect to proxy-login for Keycloak-bearer browser
        #    navigation.  The handoff flow is idempotent and ensures the
        #    browser gets hassTokens in localStorage.
        proxy_login_location = "/auth/oidc/proxy-login"
        redirect_uri = request.query.get("redirect_uri", "")
        if (
            path == "/auth/authorize"
            and redirect_uri.startswith(
                ("homeassistant://", "homeassistant-dev://", "homeassistant-beta://")
            )
        ):
            return_to = path
            if request.query_string:
                return_to += f"?{request.query_string}"
            proxy_login_location += "?return_to=" + urllib.parse.quote_plus(return_to)

        _LOGGER.info(
            "Redirecting %s to proxy-login (sub=%s…)",
            path,
            sub[:8],
        )
        raise web.HTTPFound(location=proxy_login_location)

    return handoff_middleware
