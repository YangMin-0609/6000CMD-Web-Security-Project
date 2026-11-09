"""
3.2.4 Audit logging.

Records security-relevant events in the SecurityEvent table (for the
security dashboard) and in the ``helpdesk.security`` log:

    Event                 Source
    -------------------   ---------------------------------------------------
    LOGIN_SUCCESS         user_logged_in signal
    LOGIN_FAILED          user_login_failed signal
    LOGIN_LOCKOUT         helpdesk.login_rate_limit (SEC-03)
    LOGIN_BLOCKED         helpdesk.login_rate_limit (SEC-03)
    LOGOUT                user_logged_out signal
    PERMISSION_DENIED     any HTTP 403 response (SecurityAuditMiddleware)
    USER_CREATED          post_save on the user model
    USER_DELETED          post_delete on the user model
    PRIVILEGE_CHANGE      is_superuser / is_staff / is_active changed
    ROLE_CHANGE           groups or individual permissions changed
    ESCALATION_BLOCKED    helpdesk.security_admin refused a privilege change
    ADMIN_ACTION          successful POST in the Django admin
    SENSITIVE_ACCESS      a staff member opened a ticket record
    DASHBOARD_VIEWED      someone opened the security dashboard

Design rules
* Auditing must never break the application: every write is wrapped in a
  savepoint and any error is logged instead of raised.
* Passwords are never recorded. Usernames and details are cleaned of control
  characters so they cannot forge log lines.
* The user who performed an action (``actor``) is taken from the current
  request, which the middleware stores in a context variable so that model
  signals (which have no request) can still attribute changes.
"""

import contextvars
import logging

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.db import transaction
from django.db.models.signals import m2m_changed, post_delete, post_save, pre_save

logger = logging.getLogger("helpdesk.security")

_current_request = contextvars.ContextVar("helpdesk_audit_request", default=None)

PRIVILEGE_FIELDS = ("is_superuser", "is_staff", "is_active")


def _enabled():
    return getattr(settings, "HELPDESK_SECURITY_AUDIT_ENABLED", True)


def _clean(value, limit):
    """Remove control characters (log-injection protection) and truncate."""
    return "".join(ch if ch.isprintable() else "?" for ch in str(value or ""))[:limit]


def _authenticated_user(request):
    user = getattr(request, "user", None)
    if user is not None and getattr(user, "is_authenticated", False):
        return user
    return None


def mask_ip(ip):
    """Hide the host part of an IP address for users who do not need it."""
    if not ip:
        return ""
    if ":" in ip:  # IPv6
        return ":".join(ip.split(":")[:2]) + ":****"
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.*.*"
    return "****"


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------

def record(event_type, *, request=None, actor=None, username="", severity="INFO",
           description="", ip=None, log=True):
    """
    Store one security event. Never raises.

    request   the current request (defaults to the one seen by the middleware)
    actor     the user who performed the action (defaults to request.user)
    username  the account the event is about
    ip        the client IP (defaults to the request's IP)
    log       also write a line to the helpdesk.security log
    """
    if not _enabled():
        return None

    from .login_rate_limit import _django_request, get_client_ip
    from .security_models import SecurityEvent

    if request is None:
        request = _current_request.get()
    django_request = _django_request(request)

    if actor is None and django_request is not None:
        actor = _authenticated_user(django_request)

    path = ""
    if django_request is not None:
        path = django_request.path
        if ip is None:
            try:
                ip = get_client_ip(django_request)
            except Exception:  # pragma: no cover - defensive
                ip = ""
    ip = ip or ""

    username = _clean(username, 150)
    description = _clean(description, 500)

    if log:
        level = logging.WARNING if severity in ("WARNING", "CRITICAL") else logging.INFO
        logger.log(
            level, "AUDIT %s severity=%s username=%s actor=%s ip=%s %s",
            event_type, severity, username,
            _clean(actor.get_username(), 150) if actor else "-", ip or "-", description,
        )

    try:
        with transaction.atomic():
            return SecurityEvent.objects.create(
                event_type=event_type,
                severity=severity,
                username=username,
                actor=actor,
                ip_address=_clean(ip, 45),
                path=_clean(path, 255),
                description=description,
            )
    except Exception:
        logger.exception("AUDIT_WRITE_FAILED event=%s", event_type)
        return None


# ---------------------------------------------------------------------------
# Middleware: request context, HTTP 403s, admin actions, ticket access
# ---------------------------------------------------------------------------

class SecurityAuditMiddleware:
    """Must be placed after AuthenticationMiddleware."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token = _current_request.set(request)
        try:
            response = self.get_response(request)
            if _enabled():
                try:
                    self._inspect(request, response)
                except Exception:  # auditing must not break the response
                    logger.exception("AUDIT_MIDDLEWARE_FAILED path=%s", request.path)
            return response
        finally:
            _current_request.reset(token)

    def _inspect(self, request, response):
        user = _authenticated_user(request)
        match = getattr(request, "resolver_match", None)

        if response.status_code == 403:
            # A wrong HTTP Basic password is already recorded as LOGIN_FAILED
            basic_login = request.META.get("HTTP_AUTHORIZATION", "").lower().startswith("basic ")
            if user is None and basic_login:
                return
            record(
                "PERMISSION_DENIED",
                request=request,
                username=user.get_username() if user else "",
                severity="WARNING",
                description=f"{request.method} {request.path} was refused",
            )
            return

        if match is None:
            return

        # Successful changes made through the Django admin (a save redirects with 302)
        if (
            "admin" in match.namespaces
            and request.method == "POST"
            and response.status_code == 302
            and match.url_name not in ("login", "logout")
        ):
            object_id = match.kwargs.get("object_id", "")
            record(
                "ADMIN_ACTION",
                request=request,
                username=user.get_username() if user else "",
                description=f"{match.url_name}" + (f" object={object_id}" if object_id else ""),
            )
            return

        # A staff member opened a ticket containing personal data
        if (
            match.view_name == "helpdesk:view"
            and request.method == "GET"
            and response.status_code == 200
            and user is not None
            and user.is_staff
        ):
            record(
                "SENSITIVE_ACCESS",
                request=request,
                username=user.get_username(),
                description=f"Viewed ticket #{match.kwargs.get('ticket_id')}",
                log=False,
            )


# ---------------------------------------------------------------------------
# Signal receivers
# ---------------------------------------------------------------------------

def on_login_success(sender, request, user, **kwargs):
    record("LOGIN_SUCCESS", request=request, actor=user,
           username=user.get_username(), log=False)


def on_login_failed(sender, credentials, request=None, **kwargs):
    from .login_rate_limit import LOCKED_ATTR, _django_request, _username_from_credentials

    if request is None:
        return
    # A blocked attempt during a lockout is recorded as LOGIN_BLOCKED instead
    if getattr(_django_request(request), LOCKED_ATTR, None):
        return
    record("LOGIN_FAILED", request=request,
           username=_username_from_credentials(credentials) or "",
           severity="WARNING", log=False)


def on_logout(sender, request, user, **kwargs):
    if user is None:
        return
    record("LOGOUT", request=request, actor=user, username=user.get_username())


def on_user_pre_save(sender, instance, raw=False, update_fields=None, **kwargs):
    """Remember the old privilege flags so post_save can compare them."""
    if raw or not instance.pk or not _enabled():
        return
    if update_fields is not None and not set(update_fields) & set(PRIVILEGE_FIELDS):
        return  # e.g. the last_login update on every login
    instance._audit_old_flags = (
        sender.objects.filter(pk=instance.pk).values(*PRIVILEGE_FIELDS).first()
    )


def on_user_post_save(sender, instance, created, raw=False, **kwargs):
    if raw:
        return
    username = instance.get_username()
    if created:
        flags = ", ".join(f for f in PRIVILEGE_FIELDS[:2] if getattr(instance, f))
        record("USER_CREATED", username=username,
               severity="WARNING" if instance.is_superuser else "INFO",
               description=f"Account created{' with ' + flags if flags else ''}")
        return

    old = getattr(instance, "_audit_old_flags", None)
    if not old:
        return
    instance._audit_old_flags = None
    changes = [
        f"{field}: {old[field]} -> {getattr(instance, field)}"
        for field in PRIVILEGE_FIELDS
        if old[field] != getattr(instance, field)
    ]
    if not changes:
        return
    became_superuser = not old["is_superuser"] and instance.is_superuser
    record("PRIVILEGE_CHANGE", username=username,
           severity="CRITICAL" if became_superuser else "WARNING",
           description="; ".join(changes))


def on_user_deleted(sender, instance, **kwargs):
    record("USER_DELETED", username=instance.get_username(), severity="WARNING",
           description="Account deleted")


def on_role_change(sender, instance, action, reverse, model, pk_set, **kwargs):
    if action not in ("post_add", "post_remove", "post_clear"):
        return
    User = get_user_model()
    verb = {"post_add": "added", "post_remove": "removed", "post_clear": "cleared"}[action]
    relation = "groups" if sender is User.groups.through else "permissions"

    if not reverse:
        # user.groups.add(...) / user.user_permissions.remove(...)
        names = ", ".join(str(obj) for obj in model.objects.filter(pk__in=pk_set or []))
        record("ROLE_CHANGE", username=instance.get_username(), severity="WARNING",
               description=f"{relation} {verb}: {names or 'all'}")
    else:
        # group.user_set.add(...): one event per affected user
        for user in User.objects.filter(pk__in=pk_set or []):
            record("ROLE_CHANGE", username=user.get_username(), severity="WARNING",
                   description=f"{relation} {verb}: {instance}")


def connect_signals():
    User = get_user_model()
    user_logged_in.connect(on_login_success, dispatch_uid="helpdesk_audit_login")
    user_login_failed.connect(on_login_failed, dispatch_uid="helpdesk_audit_login_failed")
    user_logged_out.connect(on_logout, dispatch_uid="helpdesk_audit_logout")
    pre_save.connect(on_user_pre_save, sender=User, dispatch_uid="helpdesk_audit_user_pre")
    post_save.connect(on_user_post_save, sender=User, dispatch_uid="helpdesk_audit_user_post")
    post_delete.connect(on_user_deleted, sender=User, dispatch_uid="helpdesk_audit_user_del")
    if hasattr(User, "groups") and hasattr(User, "user_permissions"):
        m2m_changed.connect(on_role_change, sender=User.groups.through,
                            dispatch_uid="helpdesk_audit_groups")
        m2m_changed.connect(on_role_change, sender=User.user_permissions.through,
                            dispatch_uid="helpdesk_audit_perms")
