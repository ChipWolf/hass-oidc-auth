"""Tests for the registered webpages"""

import os
import ipaddress
from auth_oidc.config.const import (
    MODE,
    MODE_TOKEN_HANDOFF,
    TOKEN_EXCHANGE,
    TOKEN_EXCHANGE_ENABLED,
    TOKEN_EXCHANGE_REQUESTER_CLIENT_ID,
    TOKEN_EXCHANGE_REQUESTER_CLIENT_SECRET,
    TOKEN_EXCHANGE_AUDIENCE,
    DISCOVERY_URL,
    CLIENT_ID,
    FEATURES,
    FEATURES_DISABLE_FRONTEND_INJECTION,
)
import pytest

from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component
from homeassistant.components.http import StaticPathConfig, DOMAIN as HTTP_DOMAIN

from custom_components.auth_oidc import DOMAIN
from .mocks.oidc_server import MockOIDCServer, mock_oidc_responses


async def setup(hass: HomeAssistant, enable_frontend_changes: bool = None):
    mock_config = {
        DOMAIN: {
            CLIENT_ID: "dummy",
            DISCOVERY_URL: "https://example.com/.well-known/openid-configuration",
            FEATURES: {
                FEATURES_DISABLE_FRONTEND_INJECTION: not enable_frontend_changes
            },
        }
    }

    if enable_frontend_changes is None:
        del mock_config[DOMAIN][FEATURES][FEATURES_DISABLE_FRONTEND_INJECTION]

    result = await async_setup_component(hass, DOMAIN, mock_config)
    assert result


async def setup_token_handoff(hass: HomeAssistant):
    """Set up token handoff mode."""
    await async_setup_component(
        hass,
        HTTP_DOMAIN,
        {
            HTTP_DOMAIN: {
                "use_x_forwarded_for": True,
                "trusted_proxies": ["127.0.0.1"],
            }
        },
    )

    mock_config = {
        DOMAIN: {
            CLIENT_ID: "homeassistant",
            DISCOVERY_URL: MockOIDCServer.get_discovery_url(),
            MODE: MODE_TOKEN_HANDOFF,
            TOKEN_EXCHANGE: {
                TOKEN_EXCHANGE_ENABLED: True,
                TOKEN_EXCHANGE_REQUESTER_CLIENT_ID: "ha-token-exchange",
                TOKEN_EXCHANGE_REQUESTER_CLIENT_SECRET: "secret",
                TOKEN_EXCHANGE_AUDIENCE: "homeassistant",
                "required_proxy_headers": False,
                "subject_token_header": "X-Forwarded-Access-Token",
                "subject_token_prefix": "",
            },
        }
    }
    result = await async_setup_component(hass, DOMAIN, mock_config)
    assert result
    hass.http.use_x_forwarded_for = True
    hass.http.trusted_proxies = [ipaddress.ip_network("127.0.0.0/8")]


@pytest.mark.asyncio
async def test_welcome_page_registration(hass: HomeAssistant, hass_client):
    """Test that welcome page is present if frontend changes are disabled."""

    await setup(hass, enable_frontend_changes=False)

    client = await hass_client()
    resp = await client.get("/auth/oidc/welcome", allow_redirects=False)
    assert resp.status == 200


@pytest.mark.asyncio
async def test_welcome_page_registration_with_changes(hass: HomeAssistant, hass_client):
    """Test that welcome page is redirect if frontend changes are enabled."""

    await setup(hass, enable_frontend_changes=True)

    client = await hass_client()
    resp = await client.get("/auth/oidc/welcome", allow_redirects=False)
    assert resp.status == 307


@pytest.mark.asyncio
async def test_redirect_page_registration(hass: HomeAssistant, hass_client):
    """Test that redirect page shows OIDC misconfiguration error if OIDC server is not reachable."""

    await setup(hass)

    client = await hass_client()
    resp = await client.get("/auth/oidc/redirect", allow_redirects=False)
    assert resp.status == 200
    text = await resp.text()
    assert "Integration is misconfigured" in text

    resp2 = await client.post("/auth/oidc/redirect", allow_redirects=False)
    assert resp2.status == 200


@pytest.mark.asyncio
async def test_callback_registration(hass: HomeAssistant, hass_client):
    """Test that callback page is reachable."""

    await setup(hass)

    client = await hass_client()
    resp = await client.get("/auth/oidc/callback", allow_redirects=False)
    assert resp.status == 200


@pytest.mark.asyncio
async def test_finish_registration(hass: HomeAssistant, hass_client):
    """Test that finish page is reachable."""

    await setup(hass)

    client = await hass_client()
    resp = await client.get("/auth/oidc/finish", allow_redirects=False)
    assert resp.status == 200
    text = await resp.text()

    # Should miss the code parameter if called without it
    assert "Missing code" in text

    resp2 = await client.get("/auth/oidc/finish?code=123456", allow_redirects=False)
    assert resp2.status == 200
    text2 = await resp2.text()
    assert "Missing code" not in text2
    assert "123456" in text2


@pytest.mark.asyncio
async def test_finish_post(hass: HomeAssistant, hass_client):
    """Test that finish page works with POST."""

    await setup(hass)
    client = await hass_client()
    resp = await client.post("/auth/oidc/finish", data={}, allow_redirects=False)
    assert resp.status == 500

    resp2 = await client.post(
        "/auth/oidc/finish", data={"code": "456888"}, allow_redirects=False
    )
    assert resp2.status == 302
    assert resp2.headers["Location"] == "/?storeToken=true"
    assert resp2.cookies["auth_oidc_code"].value == "456888"


# Test the frontend injection
@pytest.mark.asyncio
async def test_frontend_injection(hass: HomeAssistant, hass_client):
    """Test that frontend injection works."""

    # Because there is no frontend in the test setup,
    # we'll have to fake /auth/authorize for the changes to register
    await async_setup_component(hass, HTTP_DOMAIN, {})

    mock_html_path = os.path.join(os.path.dirname(__file__), "mocks", "auth_page.html")
    await hass.http.async_register_static_paths(
        [
            StaticPathConfig(
                "/auth/authorize",
                mock_html_path,
                cache_headers=False,
            )
        ]
    )

    await setup(hass, enable_frontend_changes=True)

    client = await hass_client()
    resp = await client.get("/auth/authorize", allow_redirects=False)
    assert resp.status == 200
    text = await resp.text()

    assert "<script src='/auth/oidc/static/injection.js" in text
    assert 'window.sso_name = "OpenID Connect (SSO)";' in text


@pytest.mark.asyncio
async def test_proxy_login_success(hass: HomeAssistant, hass_client):
    """Test token handoff endpoint login success."""
    await setup_token_handoff(hass)

    with mock_oidc_responses():
        client = await hass_client()
        resp = await client.get(
            "/auth/oidc/proxy-login",
            headers={
                    "X-Forwarded-Access-Token": "envoy-token",
            },
            allow_redirects=False,
        )
    assert resp.status == 302
    assert resp.headers["Location"].startswith("/auth/oidc/handoff-complete?code=")
    assert "auth_oidc_code" not in resp.cookies


@pytest.mark.asyncio
async def test_handoff_complete_page_requires_code(hass: HomeAssistant, hass_client):
    """Test handoff complete endpoint rejects missing code."""
    await setup_token_handoff(hass)

    client = await hass_client()
    resp = await client.get("/auth/oidc/handoff-complete", allow_redirects=False)
    assert resp.status == 400
    text = await resp.text()
    assert "Missing handoff code" in text


@pytest.mark.asyncio
async def test_handoff_complete_page_bootstrap(hass: HomeAssistant, hass_client):
    """Test handoff complete endpoint renders login flow bootstrap script."""
    await setup_token_handoff(hass)

    client = await hass_client()
    resp = await client.get(
        "/auth/oidc/handoff-complete?code=test-code",
        allow_redirects=False,
    )
    assert resp.status == 200
    text = await resp.text()
    assert "/auth/login_flow" in text
    assert "hassTokens" in text
    assert "test-code" in text


@pytest.mark.asyncio
async def test_proxy_login_rejects_untrusted_source(hass: HomeAssistant, hass_client):
    """Test token handoff endpoint rejects direct/untrusted calls."""
    await setup_token_handoff(hass)
    hass.http.trusted_proxies = [ipaddress.ip_network("10.10.0.0/16")]

    with mock_oidc_responses():
        client = await hass_client()
        resp = await client.get(
            "/auth/oidc/proxy-login",
            headers={
                    "X-Forwarded-Access-Token": "envoy-token",
            },
            allow_redirects=False,
        )
    assert resp.status == 403


@pytest.mark.asyncio
async def test_proxy_login_missing_token(hass: HomeAssistant, hass_client):
    """Test token handoff endpoint requires a forwarded subject token."""
    await setup_token_handoff(hass)

    client = await hass_client()
    resp = await client.get(
        "/auth/oidc/proxy-login",
        allow_redirects=False,
    )
    assert resp.status == 401


@pytest.mark.asyncio
async def test_proxy_login_rejects_invalid_exchange_token(
    hass: HomeAssistant, hass_client
):
    """Test token handoff endpoint rejects invalid exchanged token claims."""
    await setup_token_handoff(hass)

    with mock_oidc_responses("exchange_bad_audience"):
        client = await hass_client()
        resp = await client.get(
            "/auth/oidc/proxy-login",
            headers={
                    "X-Forwarded-Access-Token": "envoy-token",
            },
            allow_redirects=False,
        )
    assert resp.status == 401
