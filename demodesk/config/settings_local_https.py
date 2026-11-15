"""Settings for the loopback Django demo behind the local Caddy proxy."""

from .settings import *  # noqa: F403

ALLOWED_HOSTS = ["localhost"]
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = False
HELPDESK_USE_HTTPS_IN_EMAIL_LINK = True
