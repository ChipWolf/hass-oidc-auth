"""Trusted token handoff endpoint for proxy-based login."""

from collections import defaultdict
import ipaddress
import logging
import time
import urllib.parse

from aiohttp import web
from homeassistant.components.http import HomeAssistantView

from ..config.const import (
    DEFAULT_SUBJECT_TOKEN_FALLBACK_HEADER,
    TOKEN_EXCHANGE_AUDIENCE,
    TOKEN_EXCHANGE_ENABLED,
    TOKEN_EXCHANGE_JWT_ASSERTION_HEADER,
    TOKEN_EXCHANGE_RATE_LIMIT_PER_MINUTE,
    TOKEN_EXCHANGE_REQUESTER_CLIENT_ID,
    TOKEN_EXCHANGE_REQUESTER_CLIENT_SECRET,
    TOKEN_EXCHANGE_REQUIRED_PROXY_HEADERS,
    TOKEN_EXCHANGE_SUBJECT_TOKEN_HEADER,
    TOKEN_EXCHANGE_SUBJECT_TOKEN_PREFIX,
)
from ..provider import OpenIDAuthProvider
from ..tools.oidc_client import OIDCClient

PATH = "/auth/oidc/proxy-login"
_LOGGER = logging.getLogger(__name__)


class OIDCProxyLoginView(HomeAssistantView):
    """OIDC token handoff endpoint behind trusted proxy."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:proxy_login"

    def __init__(
        self,
        oidc_client: OIDCClient,
        oidc_provider: OpenIDAuthProvider,
        token_exchange_config: dict,
    ) -> None:
        self.oidc_client = oidc_client
        self.oidc_provider = oidc_provider
        self.token_exchange_config = token_exchange_config
        self._attempts: dict[str, list[int]] = defaultdict(list)

    def _is_trusted_proxy_request(self, request: web.Request) -> bool:
        """Validate that request came through trusted Home Assistant proxy path.

        Uses the raw TCP peer address from the transport layer rather than
        ``request.remote``, because HA's ``ForwardedMiddleware`` overwrites
        ``request.remote`` with the real client IP when
        ``use_x_forwarded_for`` is enabled.  The proxy trust check must
        inspect the *direct connection* source, not the forwarded one.
        """
        hass_http = self.oidc_provider.hass.http
        trusted_proxies = getattr(hass_http, "trusted_proxies", [])
        if not trusted_proxies:
            _LOGGER.debug("proxy-login rejected: trusted_proxies missing")
            return False

        # Prefer the raw transport peer address so we see the direct
        # connection source even after HA middleware rewrites request.remote.
        peer_ip_str: str | None = None
        transport = getattr(request, "transport", None) or (
            getattr(request, "_payload_writer", None)
            and getattr(request._payload_writer, "transport", None)
        )
        if transport is not None:
            peername = transport.get_extra_info("peername")
            if peername:
                peer_ip_str = peername[0]

        # Fall back to request.remote when transport info is unavailable
        # (e.g. during unit tests).
        if not peer_ip_str:
            peer_ip_str = request.remote

        if not peer_ip_str:
            _LOGGER.debug("proxy-login rejected: unable to determine source IP")
            return False

        try:
            source_ip = ipaddress.ip_address(peer_ip_str)
        except ValueError:
            _LOGGER.debug("proxy-login rejected: invalid source ip %s", peer_ip_str)
            return False

        if not self._source_matches_trusted_proxy(source_ip, trusted_proxies):
            _LOGGER.debug(
                "proxy-login rejected: source %s not in trusted proxies %s",
                source_ip,
                trusted_proxies,
            )
            return False

        required = self.token_exchange_config.get(
            TOKEN_EXCHANGE_REQUIRED_PROXY_HEADERS, True
        )
        if required:
            if isinstance(required, list):
                required_headers = tuple(required)
            else:
                # Default: only require X-Forwarded-For. Many proxies
                # (Envoy, Traefik) do not set X-Forwarded-Host unless
                # explicitly configured, so we don't require it.
                required_headers = ("X-Forwarded-For",)
            if any(not request.headers.get(header) for header in required_headers):
                _LOGGER.debug(
                    "proxy-login rejected: missing required proxy headers "
                    "(need %s)",
                    required_headers,
                )
                return False

        return True

    def _source_matches_trusted_proxy(
        self, source_ip: ipaddress.IPv4Address | ipaddress.IPv6Address, trusted_proxies
    ) -> bool:
        """Match source IP against HA trusted proxy config values."""
        for proxy in trusted_proxies:
            if isinstance(proxy, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                if source_ip == proxy:
                    return True
                continue

            if isinstance(proxy, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                if source_ip in proxy:
                    return True
                continue

            if isinstance(proxy, str):
                try:
                    parsed_proxy = ipaddress.ip_network(proxy, strict=False)
                except ValueError:
                    continue
                if source_ip in parsed_proxy:
                    return True

        return False

    def _rate_limited(self, request: web.Request) -> bool:
        """Simple in-memory per-source limiter."""
        limit = self.token_exchange_config.get(TOKEN_EXCHANGE_RATE_LIMIT_PER_MINUTE, 30)
        identifier = request.headers.get("X-Forwarded-For", request.remote or "unknown")
        now = int(time.time())
        cutoff = now - 60
        self._attempts[identifier] = [ts for ts in self._attempts[identifier] if ts > cutoff]
        if len(self._attempts[identifier]) >= limit:
            return True
        self._attempts[identifier].append(now)
        return False

    def _extract_subject_token(self, request: web.Request) -> str | None:
        """Extract token from configured and fallback proxy headers."""
        header_name = self.token_exchange_config.get(
            TOKEN_EXCHANGE_SUBJECT_TOKEN_HEADER, "Authorization"
        )
        prefix = self.token_exchange_config.get(TOKEN_EXCHANGE_SUBJECT_TOKEN_PREFIX, "Bearer ")
        configured_header_value = request.headers.get(header_name)
        if configured_header_value:
            if prefix and configured_header_value.startswith(prefix):
                return configured_header_value[len(prefix) :]
            if not prefix:
                return configured_header_value

        forwarded_token = request.headers.get(DEFAULT_SUBJECT_TOKEN_FALLBACK_HEADER)
        if forwarded_token:
            return forwarded_token

        assertion_header = self.token_exchange_config.get(
            TOKEN_EXCHANGE_JWT_ASSERTION_HEADER, "X-Forwarded-Jwt-Assertion"
        )
        assertion = request.headers.get(assertion_header)
        if assertion:
            return assertion

        return None

    async def _handle(self, request: web.Request) -> web.StreamResponse:
        """Handle token handoff request."""
        if not self.token_exchange_config.get(TOKEN_EXCHANGE_ENABLED, False):
            return web.Response(text="Token handoff is disabled.", status=403)

        if not self._is_trusted_proxy_request(request):
            return web.Response(text="Untrusted source.", status=403)

        if self._rate_limited(request):
            return web.Response(text="Too many requests.", status=429)

        subject_token = self._extract_subject_token(request)
        if not subject_token:
            return web.Response(text="Missing subject token.", status=401)

        requester_client_id = self.token_exchange_config.get(
            TOKEN_EXCHANGE_REQUESTER_CLIENT_ID
        )
        requester_client_secret = self.token_exchange_config.get(
            TOKEN_EXCHANGE_REQUESTER_CLIENT_SECRET
        )
        audience = self.token_exchange_config.get(TOKEN_EXCHANGE_AUDIENCE, self.oidc_client.client_id)

        user_details = await self.oidc_client.async_exchange_subject_token(
            requester_client_id=requester_client_id,
            requester_client_secret=requester_client_secret,
            subject_token=subject_token,
            audience=audience,
        )
        if user_details is None:
            return web.Response(text="Token exchange failed.", status=401)

        if user_details.get("role") == "invalid":
            return web.Response(text="User is not permitted.", status=403)

        code = await self.oidc_provider.async_save_user_info(user_details)
        handoff_url = "/auth/oidc/handoff-complete?code=" + urllib.parse.quote_plus(code)
        raise web.HTTPFound(location=handoff_url)

    async def get(self, request: web.Request) -> web.StreamResponse:
        """Handle GET requests."""
        return await self._handle(request)

    async def post(self, request: web.Request) -> web.StreamResponse:
        """Handle POST requests."""
        return await self._handle(request)
