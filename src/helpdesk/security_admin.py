"""
3.2.3 Secure administration.

Problem
-------
In the default Django admin, any staff member who has the "change user"
permission can edit every account, including their own, and tick
"Superuser status" or add themselves to any group. Django's own
documentation warns that giving a non-superuser the ability to edit users is
effectively the same as giving them superuser status.

Control
-------
``SecureUserAdmin`` replaces the default user admin:

* Only superusers can change superuser/staff status, groups or individual
  permissions; for everyone else these fields are read-only.
* Non-superusers cannot see, edit or delete superuser accounts, so they
  cannot take over an administrator account (e.g. by resetting its password).
* ``save_model`` re-checks the privilege fields on the server (defence in
  depth). Any attempted change is reverted, the administrator is warned and
  the attempt is recorded as an ESCALATION_BLOCKED security event. (The
  change is reverted rather than raising an error, because the admin saves
  inside a database transaction: raising would also roll back the audit
  record of the attempt.)

``SecurityEventAdmin`` shows the audit log read-only: events cannot be added,
edited or deleted through the admin, so the trail cannot be tampered with
from the web interface.
"""

from django.conf import settings
from django.contrib import admin, messages
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin
from .security_audit import record
from .security_models import SecurityEvent

PROTECTED_FIELDS = ("is_superuser", "is_staff", "groups", "user_permissions")


class SecureUserAdmin(UserAdmin):
    def get_readonly_fields(self, request, obj=None):
        readonly = list(super().get_readonly_fields(request, obj))
        if not request.user.is_superuser:
            readonly += [f for f in PROTECTED_FIELDS if f not in readonly]
        return readonly

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        if not request.user.is_superuser:
            # Administrators are invisible to non-superusers
            queryset = queryset.filter(is_superuser=False)
        return queryset

    def has_change_permission(self, request, obj=None):
        if obj is not None and obj.is_superuser and not request.user.is_superuser:
            return False
        return super().has_change_permission(request, obj)

    def has_delete_permission(self, request, obj=None):
        if obj is not None and obj.is_superuser and not request.user.is_superuser:
            return False
        return super().has_delete_permission(request, obj)

    def save_model(self, request, obj, form, change):
        if not self._actor_is_superuser(request):
            self._revert_privilege_change(request, obj, change)
        super().save_model(request, obj, form, change)

    @staticmethod
    def _actor_is_superuser(request):
        """
        Decide from the database, not from the in-memory request.user object.
        When staff edit their own account, the object being saved may be the
        same user, so trusting in-memory attributes could let a tampered
        object approve its own privilege change.
        """
        user = request.user  # usually a SimpleLazyObject wrapper, so use get_user_model()
        if not (user.is_authenticated and user.is_active):
            return False
        return get_user_model().objects.filter(pk=user.pk, is_superuser=True).exists()

    def _revert_privilege_change(self, request, obj, change):
        """Server-side re-check, independent of what the form displayed."""
        User = get_user_model()
        if change:
            old = User.objects.filter(pk=obj.pk).values("is_superuser", "is_staff").first()
        else:
            old = None
        old = old or {"is_superuser": False, "is_staff": False}

        attempted = [f for f in ("is_superuser", "is_staff") if getattr(obj, f) != old[f]]
        if not attempted:
            return
        for field in attempted:
            setattr(obj, field, old[field])
        record(
            "ESCALATION_BLOCKED",
            request=request,
            username=obj.get_username(),
            severity="CRITICAL",
            description=f"Non-superuser tried to change: {', '.join(attempted)} (reverted)",
        )
        self.message_user(
            request,
            "Only superusers can change administrative privileges. "
            "The privilege change was ignored and has been logged.",
            level=messages.ERROR,
        )


class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "event_type", "severity", "username", "actor",
                    "ip_address", "description")
    list_filter = ("event_type", "severity")
    search_fields = ("username", "ip_address", "description")
    date_hierarchy = "timestamp"

    def has_module_permission(self, request):
        return request.user.is_active and request.user.is_superuser

    def has_view_permission(self, request, obj=None):
        return request.user.is_active and request.user.is_superuser

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


def register(site=admin.site):
    """Swap in the secure user admin and register the read-only audit log."""
    if not site.is_registered(SecurityEvent):
        site.register(SecurityEvent, SecurityEventAdmin)

    if not getattr(settings, "HELPDESK_SECURE_USER_ADMIN", True):
        return
    User = get_user_model()
    current = site._registry.get(User)
    # Only replace the stock UserAdmin; leave custom user admins alone
    if current is not None and type(current) is UserAdmin:
        site.unregister(User)
        site.register(User, SecureUserAdmin)
