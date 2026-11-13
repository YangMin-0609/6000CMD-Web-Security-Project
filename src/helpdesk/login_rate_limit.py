"""
SEC-03: server-side rate limiting of failed login attempts.

Problem
-------
Before this change the application accepted an unlimited number of wrong
passwords, so an attacker could keep guessing (brute force / credential
stuffing). The project has several ways to log in, and all of them call
Django's ``authenticate()``:

* ``/login/``           helpdesk login page
* ``/admin/login/``     Django admin login page
* ``/api/auth/login/``  Django REST Framework browsable-API login
* ``/api/...``          HTTP Basic authentication on every API request

How the control works
---------------------
1. ``LoginRateLimitBackend`` is placed FIRST in ``AUTHENTICATION_BACKENDS``.
   It never logs anyone in. If the username/IP is locked it raises
   ``PermissionDenied``; Django then stops trying the remaining backends, so
   the password is not even checked. Because the check sits inside
   ``authenticate()``, all four entry points above are covered by one control.
2. The ``user_login_failed`` signal counts failures in Django's cache:
   * per (username + IP): default 5 failures in 15 minutes  -> locked 15 minutes
   * per IP (any username): default 20 failures in 15 minutes -> IP locked 15 minutes
     (catches "password spraying": one password tried against many accounts)
   Counting by username + IP, instead of username alone, stops an attacker
   from locking a real user out of their account from elsewhere.
3. A successful login resets the username + IP counter.
4. ``LoginRateLimitMiddleware`` turns a blocked attempt into HTTP 429
   ("Too Many Requests") with a ``Retry-After`` header and a friendly message.
   A blocked attempt gets the same response whether the password was right or
   wrong and whether the account exists or not, so it reveals nothing.
5. Every failure, lockout and blocked attempt is logged to the
   ``helpdesk.security`` logger. Passwords are never logged.

Settings (all optional)
-----------------------
HELPDESK_LOGIN_RATE_LIMIT_ENABLED      default True
HELPDESK_LOGIN_FAILURE_LIMIT           default 5    failures per username + IP
HELPDESK_LOGIN_IP_FAILURE_LIMIT        default 20   failures per IP
HELPDESK_LOGIN_FAILURE_WINDOW          default 900  seconds failures are counted for
HELPDESK_LOGIN_LOCKOUT_SECONDS         default 900  seconds a lock lasts
HELPDESK_LOGIN_RATE_LIMIT_CACHE        default "default"  cache alias
HELPDESK_LOGIN_TRUST_X_FORWARDED_FOR   default False  only enable behind a trusted
                                       reverse proxy (e.g. Caddy/Nginx)
"""

import hashlib
import logging
import math
import time

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.core.cache import caches
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse
from django.shortcuts import render

logger = logging.getLogger("helpdesk.security")

# Attribute set on the request when an attempt was blocked
LOCKED_ATTR = "_helpdesk_login_locked_seconds"


# ---------------------------------------------------------------------------
# Settings helpers (read on every call so tests can override them)
# ---------------------------------------------------------------------------


def _enabled():
    return getattr(settings, "HELPDESK_LOGIN_RATE_LIMIT_ENABLED", True)


def _user_ip_limit():
    return getattr(settings, "HELPDESK_LOGIN_FAILURE_LIMIT", 5)


def _ip_limit():
    return getattr(settings, "HELPDESK_LOGIN_IP_FAILURE_LIMIT", 20)


def _window():
    return getattr(settings, "HELPDESK_LOGIN_FAILURE_WINDOW", 900)


def _lockout_seconds():
    return getattr(settings, "HELPDESK_LOGIN_LOCKOUT_SECONDS", 900)


def _cache():
    return caches[getattr(settings, "HELPDESK_LOGIN_RATE_LIMIT_CACHE", "default")]


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------


def _django_request(request):
    """DRF wraps Django's HttpRequest; always return the underlying HttpRequest."""
    if request is None:
        return None
    return getattr(request, "_request", request)


def get_client_ip(request):
    """
    Return the client IP address.

    X-Forwarded-For is ignored by default because any client can send that
    header; trusting it would let an attacker pick a new "IP" for every guess.
    Behind a trusted reverse proxy, enable HELPDESK_LOGIN_TRUST_X_FORWARDED_FOR:
    the right-most entry is the one added by our own proxy.
    """
    request = _django_request(request)
    if getattr(settings, "HELPDESK_LOGIN_TRUST_X_FORWARDED_FOR", False):
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        parts = [part.strip() for part in forwarded.split(",") if part.strip()]
        if parts:
            return parts[-1]
    return request.META.get("REMOTE_ADDR") or "unknown"


def _normalise_username(username):
    return str(username or "").strip().lower()[:150]


def _username_from_credentials(credentials):
    field = get_user_model().USERNAME_FIELD
    return credentials.get(field, credentials.get("username"))


def _safe_for_log(value):
    """Remove control characters so a crafted username cannot forge log lines."""
    return "".join(ch if ch.isprintable() else "?" for ch in str(value))[:150]


# ---------------------------------------------------------------------------
# Cache keys (hashed so any username is a valid cache key)
# ---------------------------------------------------------------------------


def _hash(*parts):
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _keys(username, ip):
    user_ip = _hash(_normalise_username(username), ip)
    ip_only = _hash(ip)
    return {
        "user_ip_count": f"helpdesk:login:fail:user_ip:{user_ip}",
        "ip_count": f"helpdesk:login:fail:ip:{ip_only}",
        "user_ip_lock": f"helpdesk:login:lock:user_ip:{user_ip}",
        "ip_lock": f"helpdesk:login:lock:ip:{ip_only}",
    }


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def _increment(cache, key, timeout):
    """Atomically add one to a counter that expires `timeout` seconds after the first failure."""
    if cache.add(key, 1, timeout=timeout):
        return 1
    try:
        return cache.incr(key)
    except ValueError:  # the key expired between add() and incr()
        cache.set(key, 1, timeout=timeout)
        return 1


def _remaining(cache, lock_key):
    """Seconds left on a lock, or 0 if not locked."""
    unlock_at = cache.get(lock_key)
    if unlock_at is None:
        return 0
    remaining = unlock_at - time.time()
    if remaining <= 0:
        cache.delete(lock_key)
        return 0
    return math.ceil(remaining)


def lockout_remaining(username, ip):
    """Seconds until this username + IP may try again (0 = allowed)."""
    cache = _cache()
    keys = _keys(username, ip)
    return max(
        _remaining(cache, keys["user_ip_lock"]), _remaining(cache, keys["ip_lock"])
    )


def _lock(cache, lock_key, count_key, scope, username, ip, failures):
    seconds = _lockout_seconds()
    cache.set(lock_key, time.time() + seconds, timeout=seconds)
    # Start counting from zero again once the lock expires
    cache.delete(count_key)
    logger.warning(
        "LOGIN_LOCKOUT scope=%s username=%s ip=%s failures=%d lockout_seconds=%d",
        scope,
        _safe_for_log(username),
        ip,
        failures,
        seconds,
    )
    # 3.2.4: also store the event for the security dashboard
    from .security_audit import record

    record(
        "LOGIN_LOCKOUT",
        username=username or "",
        severity="CRITICAL",
        ip=ip,
        description=f"Locked for {seconds // 60} min after {failures} failures (scope: {scope})",
        log=False,
    )


def register_failure(username, ip):
    """Record one failed login and lock the username + IP (or the IP) when a limit is reached."""
    cache = _cache()
    keys = _keys(username, ip)
    window = _window()

    user_ip_failures = _increment(cache, keys["user_ip_count"], window)
    ip_failures = _increment(cache, keys["ip_count"], window)

    logger.info(
        "LOGIN_FAILED username=%s ip=%s failures=%d/%d ip_failures=%d/%d",
        _safe_for_log(username),
        ip,
        user_ip_failures,
        _user_ip_limit(),
        ip_failures,
        _ip_limit(),
    )

    if user_ip_failures >= _user_ip_limit():
        _lock(
            cache,
            keys["user_ip_lock"],
            keys["user_ip_count"],
            "username+ip",
            username,
            ip,
            user_ip_failures,
        )
    if ip_failures >= _ip_limit():
        _lock(cache, keys["ip_lock"], keys["ip_count"], "ip", username, ip, ip_failures)


def reset_failures(username, ip):
    """Clear the username + IP counter after a successful login (the IP counter is kept)."""
    _cache().delete(_keys(username, ip)["user_ip_count"])


# ---------------------------------------------------------------------------
# Authentication backend
# ---------------------------------------------------------------------------


class LoginRateLimitBackend(BaseBackend):
    """
    Must be listed FIRST in AUTHENTICATION_BACKENDS.

    It never authenticates anyone. When the username/IP is locked it raises
    PermissionDenied, which makes Django's authenticate() stop immediately,
    so the real password check (ModelBackend) never runs.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        if not _enabled() or request is None:
            return
        if username is None:
            username = kwargs.get(get_user_model().USERNAME_FIELD)

        ip = get_client_ip(request)
        remaining = lockout_remaining(username, ip)
        if remaining:
            setattr(_django_request(request), LOCKED_ATTR, remaining)
            logger.warning(
                "LOGIN_BLOCKED username=%s ip=%s retry_after=%d",
                _safe_for_log(username),
                ip,
                remaining,
            )
            # 3.2.4: also store the event for the security dashboard
            from .security_audit import record

            record(
                "LOGIN_BLOCKED",
                request=request,
                username=username or "",
                severity="WARNING",
                description=f"Attempt refused during lockout ({remaining}s remaining)",
                log=False,
            )
            raise PermissionDenied("Too many failed login attempts.")
        return

    def get_user(self, user_id):
        return None


# ---------------------------------------------------------------------------
# Signal handlers (connected in HelpdeskConfig.ready)
# ---------------------------------------------------------------------------


def on_login_failed(sender, credentials, request=None, **kwargs):
    if not _enabled() or request is None:
        return
    # A blocked attempt was already handled by the backend; do not count it again
    if getattr(_django_request(request), LOCKED_ATTR, None):
        return
    register_failure(_username_from_credentials(credentials), get_client_ip(request))


def on_login_success(sender, request, user, **kwargs):
    if not _enabled() or request is None:
        return
    ip = get_client_ip(request)
    reset_failures(user.get_username(), ip)
    logger.info(
        "LOGIN_SUCCESS username=%s ip=%s", _safe_for_log(user.get_username()), ip
    )


def connect_signals():
    user_login_failed.connect(
        on_login_failed, dispatch_uid="helpdesk_login_rate_limit_failed"
    )
    user_logged_in.connect(
        on_login_success, dispatch_uid="helpdesk_login_rate_limit_success"
    )


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class LoginRateLimitMiddleware:
    """Replace the response of a blocked login attempt with HTTP 429 Too Many Requests."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        remaining = getattr(request, LOCKED_ATTR, None)
        if remaining:
            return locked_response(request, remaining)
        return response


def locked_response(request, seconds):
    minutes = max(1, math.ceil(seconds / 60))
    message = (
        f"Too many failed login attempts. "
        f"Please wait {minutes} minute{'s' if minutes != 1 else ''} and try again."
    )
    # API clients (HTTP Basic or JSON) get JSON; browsers get an HTML page
    wants_json = request.META.get("HTTP_AUTHORIZATION", "").lower().startswith(
        "basic "
    ) or "application/json" in request.META.get("HTTP_ACCEPT", "")
    if wants_json:
        response = JsonResponse({"detail": message}, status=429)
    else:
        response = render(
            request,
            "helpdesk/registration/login_locked.html",
            {"message": message, "minutes": minutes},
            status=429,
        )
    response["Retry-After"] = str(seconds)
    return response
