"""Optional local logout endpoint for token handoff mode."""

from aiohttp import web
from homeassistant.components.http import HomeAssistantView

from ..config.const import LOGOUT_REDIRECT_URL

PATH = "/auth/oidc/proxy-logout"


class OIDCProxyLogoutView(HomeAssistantView):
    """OIDC token handoff logout endpoint."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:proxy_logout"

    def __init__(self, config: dict) -> None:
        self.config = config

    async def get(self, _request: web.Request) -> web.StreamResponse:
        """Clear handoff cookie and redirect."""
        redirect_target = self.config.get(LOGOUT_REDIRECT_URL, "/")
        raise web.HTTPFound(
            location=redirect_target,
            headers={
                "set-cookie": "auth_oidc_code=; Path=/auth/login_flow; "
                + "SameSite=Strict; HttpOnly; Max-Age=0",
            },
        )
