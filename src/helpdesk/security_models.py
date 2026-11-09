"""
3.2.4 Audit logging: database model for security events.

Security events are stored in their own table so the security dashboard
(3.2.5) can search, filter and summarise them. Rows are written by
helpdesk.security_audit and are read-only in the Django admin.
"""

from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class SecurityEvent(models.Model):
    class EventType(models.TextChoices):
        LOGIN_SUCCESS = "LOGIN_SUCCESS", _("Login success")
        LOGIN_FAILED = "LOGIN_FAILED", _("Login failure")
        LOGIN_LOCKOUT = "LOGIN_LOCKOUT", _("Account lockout")
        LOGIN_BLOCKED = "LOGIN_BLOCKED", _("Login blocked (locked out)")
        LOGOUT = "LOGOUT", _("Logout")
        PERMISSION_DENIED = "PERMISSION_DENIED", _("Permission denied")
        USER_CREATED = "USER_CREATED", _("User created")
        USER_DELETED = "USER_DELETED", _("User deleted")
        PRIVILEGE_CHANGE = "PRIVILEGE_CHANGE", _("Privilege change")
        ROLE_CHANGE = "ROLE_CHANGE", _("Group / permission change")
        ESCALATION_BLOCKED = "ESCALATION_BLOCKED", _("Privilege escalation blocked")
        ADMIN_ACTION = "ADMIN_ACTION", _("Administrator action")
        SENSITIVE_ACCESS = "SENSITIVE_ACCESS", _("Ticket record viewed")
        DASHBOARD_VIEWED = "DASHBOARD_VIEWED", _("Security dashboard viewed")

    class Severity(models.TextChoices):
        INFO = "INFO", _("Info")
        WARNING = "WARNING", _("Warning")
        CRITICAL = "CRITICAL", _("Critical")

    timestamp = models.DateTimeField(_("Time"), default=timezone.now, db_index=True)
    event_type = models.CharField(
        _("Event"), max_length=32, choices=EventType.choices, db_index=True
    )
    severity = models.CharField(
        _("Severity"), max_length=10, choices=Severity.choices, default=Severity.INFO
    )
    # The account the event is about (the attempted username, or the user
    # whose privileges were changed)
    username = models.CharField(_("Account"), max_length=150, blank=True, db_index=True)
    # The logged-in user who caused the event, if any
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        verbose_name=_("Performed by"),
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    ip_address = models.CharField(_("IP address"), max_length=45, blank=True)
    path = models.CharField(_("Path"), max_length=255, blank=True)
    description = models.CharField(_("Details"), max_length=500, blank=True)

    class Meta:
        ordering = ("-timestamp", "-id")
        verbose_name = _("Security event")
        verbose_name_plural = _("Security events")

    def __str__(self):
        return f"{self.timestamp:%Y-%m-%d %H:%M:%S} {self.event_type} {self.username}"
