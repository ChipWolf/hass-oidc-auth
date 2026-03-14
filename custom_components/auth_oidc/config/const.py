"""Config constants."""

from typing import Any, Dict

## ===
## General integration constants
## ===

DEFAULT_TITLE = "OpenID Connect (SSO)"
DOMAIN = "auth_oidc"
REPO_ROOT_URL = (
    "https://github.com/christiaangoossens/hass-oidc-auth/tree/v0.7.0-alpha-rc3"
)

## ===
## Config keys
## ===

CLIENT_ID = "client_id"
CLIENT_SECRET = "client_secret"
DISCOVERY_URL = "discovery_url"
DISPLAY_NAME = "display_name"
ID_TOKEN_SIGNING_ALGORITHM = "id_token_signing_alg"
GROUPS_SCOPE = "groups_scope"
ADDITIONAL_SCOPES = "additional_scopes"
FEATURES = "features"
FEATURES_AUTOMATIC_USER_LINKING = "automatic_user_linking"
FEATURES_AUTOMATIC_PERSON_CREATION = "automatic_person_creation"
FEATURES_DISABLE_PKCE = "disable_rfc7636"
FEATURES_INCLUDE_GROUPS_SCOPE = "include_groups_scope"
FEATURES_DISABLE_FRONTEND_INJECTION = "disable_frontend_changes"
FEATURES_FORCE_HTTPS = "force_https"
CLAIMS = "claims"
CLAIMS_DISPLAY_NAME = "display_name"
CLAIMS_USERNAME = "username"
CLAIMS_GROUPS = "groups"
ROLES = "roles"
ROLE_ADMINS = "admin"
ROLE_USERS = "user"
NETWORK = "network"
NETWORK_TLS_VERIFY = "tls_verify"
NETWORK_TLS_CA_PATH = "tls_ca_path"
MODE = "mode"
MODE_BROWSER_OIDC = "browser_oidc"
MODE_TOKEN_HANDOFF = "token_handoff"
TOKEN_EXCHANGE = "token_exchange"
TOKEN_EXCHANGE_ENABLED = "enabled"
TOKEN_EXCHANGE_REQUESTER_CLIENT_ID = "requester_client_id"
TOKEN_EXCHANGE_REQUESTER_CLIENT_SECRET = "requester_client_secret"
TOKEN_EXCHANGE_SUBJECT_TOKEN_HEADER = "subject_token_header"
TOKEN_EXCHANGE_SUBJECT_TOKEN_PREFIX = "subject_token_prefix"
TOKEN_EXCHANGE_JWT_ASSERTION_HEADER = "jwt_assertion_header"
TOKEN_EXCHANGE_AUDIENCE = "audience"
TOKEN_EXCHANGE_RATE_LIMIT_PER_MINUTE = "rate_limit_per_minute"
TOKEN_EXCHANGE_REQUIRED_PROXY_HEADERS = "required_proxy_headers"
LOGOUT_REDIRECT_URL = "logout_redirect_url"

## ===
## Default configurations for providers
## ===

REQUIRED_SCOPES = "openid profile"
DEFAULT_ID_TOKEN_SIGNING_ALGORITHM = "RS256"
DEFAULT_MODE = MODE_BROWSER_OIDC
DEFAULT_SUBJECT_TOKEN_HEADER = "Authorization"
DEFAULT_SUBJECT_TOKEN_PREFIX = "Bearer "
DEFAULT_JWT_ASSERTION_HEADER = "X-Forwarded-Jwt-Assertion"
DEFAULT_SUBJECT_TOKEN_FALLBACK_HEADER = "X-Forwarded-Access-Token"

DEFAULT_GROUPS_SCOPE = "groups"
DEFAULT_ADMIN_GROUP = "admins"

OIDC_PROVIDERS: Dict[str, Dict[str, Any]] = {
    "authentik": {
        "name": "Authentik",
        "discovery_url": "",
        "default_admin_group": DEFAULT_ADMIN_GROUP,
        "supports_groups": True,
        "claims": {
            "display_name": "name",
            "username": "preferred_username",
            "groups": "groups",
        },
    },
    "authelia": {
        "name": "Authelia",
        "discovery_url": "",
        "default_admin_group": DEFAULT_ADMIN_GROUP,
        "supports_groups": True,
        "claims": {
            "display_name": "name",
            "username": "preferred_username",
            "groups": "groups",
        },
    },
    "pocketid": {
        "name": "Pocket ID",
        "discovery_url": "",
        "default_admin_group": DEFAULT_ADMIN_GROUP,
        "supports_groups": True,
        "claims": {
            "display_name": "name",
            "username": "preferred_username",
            "groups": "groups",
        },
    },
    "generic": {
        "name": "OpenID Connect (SSO)",
        "discovery_url": "",
        "supports_groups": False,
        "claims": {"display_name": "name", "username": "preferred_username"},
    },
}
