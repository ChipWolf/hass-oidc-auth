"""Config schema"""

import voluptuous as vol
from .const import (
    CLIENT_ID,
    CLIENT_SECRET,
    DISCOVERY_URL,
    DISPLAY_NAME,
    ID_TOKEN_SIGNING_ALGORITHM,
    GROUPS_SCOPE,
    ADDITIONAL_SCOPES,
    FEATURES,
    FEATURES_AUTOMATIC_USER_LINKING,
    FEATURES_AUTOMATIC_PERSON_CREATION,
    FEATURES_DISABLE_PKCE,
    FEATURES_INCLUDE_GROUPS_SCOPE,
    FEATURES_DISABLE_FRONTEND_INJECTION,
    FEATURES_FORCE_HTTPS,
    CLAIMS,
    CLAIMS_DISPLAY_NAME,
    CLAIMS_USERNAME,
    CLAIMS_GROUPS,
    ROLES,
    ROLE_ADMINS,
    ROLE_USERS,
    NETWORK,
    NETWORK_TLS_VERIFY,
    NETWORK_TLS_CA_PATH,
    MODE,
    MODE_BROWSER_OIDC,
    MODE_TOKEN_HANDOFF,
    TOKEN_EXCHANGE,
    TOKEN_EXCHANGE_ENABLED,
    TOKEN_EXCHANGE_REQUESTER_CLIENT_ID,
    TOKEN_EXCHANGE_REQUESTER_CLIENT_SECRET,
    TOKEN_EXCHANGE_SUBJECT_TOKEN_HEADER,
    TOKEN_EXCHANGE_SUBJECT_TOKEN_PREFIX,
    TOKEN_EXCHANGE_JWT_ASSERTION_HEADER,
    TOKEN_EXCHANGE_AUDIENCE,
    TOKEN_EXCHANGE_RATE_LIMIT_PER_MINUTE,
    TOKEN_EXCHANGE_REQUIRED_PROXY_HEADERS,
    LOGOUT_REDIRECT_URL,
    DOMAIN,
    DEFAULT_GROUPS_SCOPE,
    DEFAULT_MODE,
    DEFAULT_SUBJECT_TOKEN_HEADER,
    DEFAULT_SUBJECT_TOKEN_PREFIX,
    DEFAULT_JWT_ASSERTION_HEADER,
)

def _validate_mode_dependencies(config: dict) -> dict:
    """Validate cross-field dependencies for advanced auth modes."""
    oidc_config = config[DOMAIN]
    if oidc_config.get(MODE, DEFAULT_MODE) == MODE_TOKEN_HANDOFF:
        token_exchange = oidc_config.get(TOKEN_EXCHANGE, {})
        if token_exchange.get(TOKEN_EXCHANGE_ENABLED, False) is not True:
            raise vol.Invalid(
                "token_exchange.enabled must be true when mode=token_handoff"
            )

        if not token_exchange.get(TOKEN_EXCHANGE_REQUESTER_CLIENT_ID):
            raise vol.Invalid(
                "token_exchange.requester_client_id is required when mode=token_handoff"
            )

        if not token_exchange.get(TOKEN_EXCHANGE_REQUESTER_CLIENT_SECRET):
            raise vol.Invalid(
                "token_exchange.requester_client_secret is required when mode=token_handoff"
            )

    return config


CONFIG_SCHEMA = vol.All(
    vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                # Required client ID as registered with the OIDC provider
                vol.Required(CLIENT_ID): vol.Coerce(str),
                # Optional Client Secret to enable confidential client mode
                vol.Optional(CLIENT_SECRET): vol.Coerce(str),
                # Which OIDC well-known URL should we use?
                vol.Required(DISCOVERY_URL): vol.Coerce(str),
                # Which name should be shown on the login screens?
                vol.Optional(DISPLAY_NAME): vol.Coerce(str),
                # Should we enforce a specific signing algorithm on the id tokens?
                # Defaults to RS256/RSA-pubkey
                vol.Optional(ID_TOKEN_SIGNING_ALGORITHM): vol.Coerce(str),
                # String value to allow changing the groups scope
                # Defaults to 'groups' which is used by Authelia and Authentik
                vol.Optional(GROUPS_SCOPE, default=DEFAULT_GROUPS_SCOPE): vol.Coerce(
                    str
                ),
                # Additional scopes to request from the OIDC provider
                # Optional, this field is unnecessary if you only use the openid and profile scopes.
                vol.Optional(ADDITIONAL_SCOPES, default=[]): vol.Coerce(list[str]),
                # Which features should be enabled/disabled?
                # Optional, defaults to sane/secure defaults
                vol.Optional(FEATURES): vol.Schema(
                    {
                        # Automatically links users to the HA user based on OIDC username claim
                        # See provider.py for explanation
                        vol.Optional(FEATURES_AUTOMATIC_USER_LINKING): vol.Coerce(bool),
                        # Automatically creates a person entry for your new OIDC user
                        # See provider.py for explanation
                        vol.Optional(FEATURES_AUTOMATIC_PERSON_CREATION): vol.Coerce(
                            bool
                        ),
                        # Feature flag to disable PKCE to support OIDC servers that do not
                        # allow additional parameters and don't support RFC 7636
                        vol.Optional(FEATURES_DISABLE_PKCE): vol.Coerce(bool),
                        # Boolean which activates and deactivates scope 'groups'
                        vol.Optional(
                            FEATURES_INCLUDE_GROUPS_SCOPE, default=True
                        ): vol.Coerce(bool),
                        # Disable frontend injection of OIDC login button
                        vol.Optional(
                            FEATURES_DISABLE_FRONTEND_INJECTION, default=False
                        ): vol.Coerce(bool),
                        # Force HTTPS on all generated URLs (like redirect_uri)
                        vol.Optional(FEATURES_FORCE_HTTPS, default=False): vol.Coerce(
                            bool
                        ),
                    }
                ),
                # Determine which specific claims will be used from the id_token
                # Optional, defaults to most common claims
                vol.Optional(CLAIMS): vol.Schema(
                    {
                        # Which claim should we use to obtain the display name from OIDC?
                        vol.Optional(CLAIMS_DISPLAY_NAME): vol.Coerce(str),
                        # Which claim should we use to obtain the username from OIDC?
                        vol.Optional(CLAIMS_USERNAME): vol.Coerce(str),
                        # Which claim should we use to obtain the group(s) from OIDC?
                        vol.Optional(CLAIMS_GROUPS): vol.Coerce(str),
                    }
                ),
                # Determine which specific group values will be mapped to which roles
                # Optional, defaults user = null, admin = 'admins'
                # If user role is set, users that do not have either will be rejected!
                vol.Optional(ROLES): vol.Schema(
                    {
                        # Which group name should we use to assign the user role?
                        vol.Optional(ROLE_USERS): vol.Coerce(str),
                        # What group name should we use to assign the admin role?
                        # Defaults to admins
                        vol.Optional(ROLE_ADMINS): vol.Coerce(str),
                    }
                ),
                # Network options
                vol.Optional(NETWORK): vol.Schema(
                    {
                        # Verify x509 certificates provided when starting TLS connections
                        vol.Optional(NETWORK_TLS_VERIFY, default=True): vol.Coerce(
                            bool
                        ),
                        # Load custom certificate chain for private CAs
                        vol.Optional(NETWORK_TLS_CA_PATH): vol.Coerce(str),
                    }
                ),
                # Select auth mode
                vol.Optional(MODE, default=DEFAULT_MODE): vol.In(
                    [MODE_BROWSER_OIDC, MODE_TOKEN_HANDOFF]
                ),
                # Token handoff / token exchange options
                vol.Optional(TOKEN_EXCHANGE): vol.Schema(
                    {
                        vol.Optional(TOKEN_EXCHANGE_ENABLED, default=False): vol.Coerce(
                            bool
                        ),
                        vol.Optional(TOKEN_EXCHANGE_REQUESTER_CLIENT_ID): vol.Coerce(
                            str
                        ),
                        vol.Optional(
                            TOKEN_EXCHANGE_REQUESTER_CLIENT_SECRET
                        ): vol.Coerce(str),
                        vol.Optional(
                            TOKEN_EXCHANGE_SUBJECT_TOKEN_HEADER,
                            default=DEFAULT_SUBJECT_TOKEN_HEADER,
                        ): vol.Coerce(str),
                        vol.Optional(
                            TOKEN_EXCHANGE_SUBJECT_TOKEN_PREFIX,
                            default=DEFAULT_SUBJECT_TOKEN_PREFIX,
                        ): vol.Coerce(str),
                        vol.Optional(
                            TOKEN_EXCHANGE_JWT_ASSERTION_HEADER,
                            default=DEFAULT_JWT_ASSERTION_HEADER,
                        ): vol.Coerce(str),
                        vol.Optional(TOKEN_EXCHANGE_AUDIENCE): vol.Coerce(str),
                        vol.Optional(
                            TOKEN_EXCHANGE_RATE_LIMIT_PER_MINUTE, default=30
                        ): vol.All(vol.Coerce(int), vol.Range(min=1, max=600)),
                        vol.Optional(
                            TOKEN_EXCHANGE_REQUIRED_PROXY_HEADERS, default=True
                        ): vol.Coerce(bool),
                    }
                ),
                # Optional upstream logout URL in token_handoff mode
                vol.Optional(LOGOUT_REDIRECT_URL): vol.Coerce(str),
            }
        )
    },
    # Any extra fields should not go into our config right now
    # You may set them for upgrading etc
    extra=vol.REMOVE_EXTRA,
    ),
    _validate_mode_dependencies,
)
