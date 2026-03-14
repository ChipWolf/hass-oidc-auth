"""Auto-complete page for token handoff login."""

from aiohttp import web
from homeassistant.components.http import HomeAssistantView

from ..tools.helpers import get_view

PATH = "/auth/oidc/handoff-complete"


class OIDCHandoffCompleteView(HomeAssistantView):
    """Render the token handoff auto-complete page."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:handoff_complete"

    async def get(self, request: web.Request) -> web.Response:
        """Show the auto-complete handoff page."""
        code = request.query.get("code")
        if not code:
            view_html = await get_view(
                "error",
                {"error": "Missing handoff code, please retry sign-in."},
            )
            return web.Response(text=view_html, content_type="text/html", status=400)

        view_html = await get_view("handoff_complete", {"code": code})
        return web.Response(text=view_html, content_type="text/html")
