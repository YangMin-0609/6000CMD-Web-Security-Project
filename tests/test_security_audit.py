"""
3.2.3 - 3.2.5: audit logging, secure user admin and security dashboard tests.

Run only these tests:
    uv run python quicktest.py tests.test_security_audit -v 2
"""

from datetime import timedelta
from io import StringIO
from unittest import mock

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.messages.storage.cookie import CookieStorage
from django.core.cache import cache
from django.core.management import call_command
from django.db import DatabaseError
from django.test import RequestFactory, TestCase, modify_settings, override_settings
from django.urls import reverse
from django.utils import timezone

from helpdesk.models import Queue, Ticket
from helpdesk.security_admin import SecureUserAdmin
from helpdesk.security_audit import mask_ip
from helpdesk.security_models import SecurityEvent

User = get_user_model()
PASSWORD = "Correct-Horse-Battery-42"
AUDIT_MIDDLEWARE = "helpdesk.security_audit.SecurityAuditMiddleware"


def events(event_type, **filters):
    return SecurityEvent.objects.filter(event_type=event_type, **filters)


@modify_settings(MIDDLEWARE={"append": AUDIT_MIDDLEWARE})
class AuditLoggingTests(TestCase):
    """3.2.4: security-relevant events are recorded."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("alice", "alice@example.com", PASSWORD)
        cls.admin = User.objects.create_superuser("root", "root@example.com", PASSWORD)

    def setUp(self):
        cache.clear()

    def login(self, username, password):
        return self.client.post(
            reverse("helpdesk:login"), {"username": username, "password": password}
        )

    def test_login_failure_and_success_are_recorded(self):
        self.login("alice", "wrong")
        failed = events("LOGIN_FAILED").get()
        self.assertEqual(failed.username, "alice")
        self.assertEqual(failed.severity, "WARNING")
        self.assertEqual(failed.ip_address, "127.0.0.1")

        self.login("alice", PASSWORD)
        success = events("LOGIN_SUCCESS").get()
        self.assertEqual(success.actor, self.user)

    def test_password_is_never_stored(self):
        self.login("alice", "Secret-Guess-123")
        stored = " ".join(SecurityEvent.objects.values_list("description", flat=True))
        self.assertNotIn("Secret-Guess-123", stored)

    def test_logout_is_recorded(self):
        self.client.login(username="alice", password=PASSWORD)
        self.client.post(reverse("helpdesk:logout"))
        self.assertEqual(events("LOGOUT").get().username, "alice")

    def test_last_login_update_is_not_a_privilege_change(self):
        self.login("alice", PASSWORD)
        self.assertFalse(events("PRIVILEGE_CHANGE").exists())

    def test_privilege_change_is_recorded_as_critical(self):
        self.user.is_superuser = True
        self.user.save()
        change = events("PRIVILEGE_CHANGE").get()
        self.assertEqual(change.severity, "CRITICAL")
        self.assertIn("is_superuser: False -> True", change.description)

    def test_group_change_is_recorded(self):
        group = Group.objects.create(name="Queue Managers")
        self.user.groups.add(group)
        change = events("ROLE_CHANGE").get()
        self.assertEqual(change.username, "alice")
        self.assertIn("Queue Managers", change.description)

    def test_user_creation_and_deletion_are_recorded(self):
        bob = User.objects.create_user("bob", "bob@example.com", PASSWORD)
        self.assertTrue(events("USER_CREATED", username="bob").exists())
        bob.delete()
        self.assertTrue(events("USER_DELETED", username="bob").exists())

    def test_admin_action_is_recorded_with_actor(self):
        self.client.force_login(self.admin)
        response = self.client.post(
            reverse("admin:auth_group_add"), {"name": "Auditors"}
        )
        self.assertEqual(response.status_code, 302)
        action = events("ADMIN_ACTION").get()
        self.assertEqual(action.actor, self.admin)
        self.assertIn("auth_group_add", action.description)

    def test_permission_denied_is_recorded(self):
        self.client.force_login(self.user)  # not staff
        response = self.client.get(reverse("helpdesk:security_dashboard"))
        self.assertEqual(response.status_code, 403)
        denied = events("PERMISSION_DENIED").get()
        self.assertEqual(denied.username, "alice")
        self.assertIn("/security/", denied.path)

    def test_staff_ticket_access_is_recorded(self):
        queue = Queue.objects.create(title="Support", slug="support")
        ticket = Ticket.objects.create(queue=queue, title="Printer", description="x")
        self.client.force_login(self.admin)
        response = self.client.get(reverse("helpdesk:view", args=[ticket.id]))
        self.assertEqual(response.status_code, 200)
        access = events("SENSITIVE_ACCESS").get()
        self.assertEqual(access.description, f"Viewed ticket #{ticket.id}")

    def test_control_characters_are_removed(self):
        self.login("evil\nAUDIT LOGIN_SUCCESS", "wrong")
        self.assertEqual(
            events("LOGIN_FAILED").get().username, "evil?AUDIT LOGIN_SUCCESS"
        )

    def test_audit_failure_does_not_break_login(self):
        with (
            mock.patch.object(
                SecurityEvent.objects, "create", side_effect=DatabaseError("disk full")
            ),
            self.assertLogs("helpdesk.security", level="ERROR") as logs,
        ):
            response = self.login("alice", PASSWORD)
        self.assertEqual(response.status_code, 302)  # user still logged in
        self.assertIn("AUDIT_WRITE_FAILED", "\n".join(logs.output))

    @override_settings(
        AUTHENTICATION_BACKENDS=[
            "helpdesk.login_rate_limit.LoginRateLimitBackend",
            "django.contrib.auth.backends.ModelBackend",
        ],
        HELPDESK_LOGIN_FAILURE_LIMIT=5,
    )
    @modify_settings(
        MIDDLEWARE={"append": "helpdesk.login_rate_limit.LoginRateLimitMiddleware"}
    )
    def test_sec03_lockout_and_blocked_attempts_are_recorded(self):
        for _ in range(5):
            self.login("alice", "wrong")
        self.assertEqual(self.login("alice", PASSWORD).status_code, 429)

        self.assertEqual(
            events("LOGIN_FAILED").count(), 5
        )  # blocked attempt not counted
        lockout = events("LOGIN_LOCKOUT").get()
        self.assertEqual(lockout.severity, "CRITICAL")
        self.assertEqual(lockout.ip_address, "127.0.0.1")
        self.assertEqual(events("LOGIN_BLOCKED").count(), 1)

    def test_old_events_are_purged_after_retention_period(self):
        old = SecurityEvent.objects.create(event_type="LOGOUT", username="old")
        SecurityEvent.objects.filter(pk=old.pk).update(
            timestamp=timezone.now() - timedelta(days=100)
        )
        recent = SecurityEvent.objects.create(event_type="LOGOUT", username="recent")
        call_command("purge_security_events", "--days", "90", stdout=StringIO())
        self.assertFalse(SecurityEvent.objects.filter(pk=old.pk).exists())
        self.assertTrue(SecurityEvent.objects.filter(pk=recent.pk).exists())


@modify_settings(MIDDLEWARE={"append": AUDIT_MIDDLEWARE})
class SecureUserAdminTests(TestCase):
    """3.2.3: staff who may edit users cannot grant themselves privileges."""

    @classmethod
    def setUpTestData(cls):
        cls.root = User.objects.create_superuser("root", "root@example.com", PASSWORD)
        cls.manager = User.objects.create_user(
            "manager", "manager@example.com", PASSWORD, is_staff=True
        )
        cls.manager.user_permissions.add(
            *Permission.objects.filter(
                content_type__app_label="auth",
                codename__in=["view_user", "change_user"],
            )
        )

    def setUp(self):
        self.model_admin = admin.site._registry[User]
        self.factory = RequestFactory()

    def request_as(self, user):
        request = self.factory.post("/admin/")
        request.user = user
        request._messages = CookieStorage(request)
        return request

    def test_secure_admin_is_installed(self):
        self.assertIsInstance(self.model_admin, SecureUserAdmin)

    def test_privilege_fields_are_read_only_for_non_superusers(self):
        readonly = self.model_admin.get_readonly_fields(
            self.request_as(self.manager), self.manager
        )
        for field in ("is_superuser", "is_staff", "groups", "user_permissions"):
            self.assertIn(field, readonly)
        readonly_root = self.model_admin.get_readonly_fields(
            self.request_as(self.root), self.manager
        )
        self.assertNotIn("is_superuser", readonly_root)

    def test_manager_page_has_no_superuser_checkbox(self):
        self.client.force_login(self.manager)
        response = self.client.get(
            reverse("admin:auth_user_change", args=[self.manager.pk])
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'name="is_superuser"')

    def test_superusers_are_hidden_from_non_superusers(self):
        queryset = self.model_admin.get_queryset(self.request_as(self.manager))
        self.assertNotIn(self.root, queryset)
        self.assertFalse(
            self.model_admin.has_change_permission(
                self.request_as(self.manager), self.root
            )
        )
        self.assertFalse(
            self.model_admin.has_delete_permission(
                self.request_as(self.manager), self.root
            )
        )

        self.client.force_login(self.manager)
        response = self.client.get(
            reverse("admin:auth_user_change", args=[self.root.pk])
        )
        self.assertNotEqual(response.status_code, 200)

    def test_server_side_check_reverts_escalation_and_logs_it(self):
        """Defence in depth: even if a request bypasses the form, save_model refuses."""
        self.manager.is_superuser = True  # simulated tampering
        self.model_admin.save_model(
            self.request_as(self.manager), self.manager, None, True
        )

        self.manager.refresh_from_db()
        self.assertFalse(self.manager.is_superuser)
        blocked = events("ESCALATION_BLOCKED").get()
        self.assertEqual(blocked.severity, "CRITICAL")
        self.assertIn("is_superuser", blocked.description)

    def test_superuser_can_still_grant_privileges(self):
        self.manager.is_superuser = True
        self.model_admin.save_model(
            self.request_as(self.root), self.manager, None, True
        )
        self.manager.refresh_from_db()
        self.assertTrue(self.manager.is_superuser)

    def test_superuser_can_add_and_edit_users_through_admin(self):
        """Real admin requests (request.user is a lazy wrapper) must work end to end."""
        self.client.force_login(self.root)
        response = self.client.post(
            reverse("admin:auth_user_add"),
            {
                "username": "normal_user",
                "password1": PASSWORD,
                "password2": PASSWORD,
                "usable_password": "true",
            },
        )
        self.assertEqual(
            response.status_code,
            302,
            getattr(response, "context", None) and response.context.get("errors"),
        )
        self.assertTrue(User.objects.filter(username="normal_user").exists())

    def test_manager_post_cannot_make_themselves_superuser(self):
        """End-to-end: tampered POST with is_superuser=on through the real admin form."""
        self.client.force_login(self.manager)
        url = reverse("admin:auth_user_change", args=[self.manager.pk])
        joined = timezone.localtime(self.manager.date_joined)
        self.client.post(
            url,
            {
                "username": "manager",
                "email": "manager@example.com",
                "is_active": "on",
                "is_staff": "on",
                "is_superuser": "on",  # attacker adds this field by hand
                "date_joined_0": joined.strftime("%Y-%m-%d"),
                "date_joined_1": joined.strftime("%H:%M:%S"),
            },
        )
        self.manager.refresh_from_db()
        self.assertFalse(self.manager.is_superuser)

    def test_audit_log_is_read_only_in_admin(self):
        self.client.force_login(self.root)
        self.assertEqual(
            self.client.get(
                reverse("admin:helpdesk_securityevent_changelist")
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.get(reverse("admin:helpdesk_securityevent_add")).status_code,
            403,
        )


@modify_settings(MIDDLEWARE={"append": AUDIT_MIDDLEWARE})
class SecurityDashboardTests(TestCase):
    """3.2.5: dashboard content depends on the viewer's role."""

    @classmethod
    def setUpTestData(cls):
        cls.root = User.objects.create_superuser("root", "root@example.com", PASSWORD)
        cls.staff = User.objects.create_user(
            "agent", "agent@example.com", PASSWORD, is_staff=True
        )
        cls.user = User.objects.create_user("alice", "alice@example.com", PASSWORD)
        SecurityEvent.objects.create(
            event_type="LOGIN_FAILED",
            username="agent",
            ip_address="10.1.2.3",
            severity="WARNING",
        )
        SecurityEvent.objects.create(
            event_type="LOGIN_LOCKOUT",
            username="victim",
            ip_address="198.51.100.7",
            severity="CRITICAL",
        )

    def setUp(self):
        self.url = reverse("helpdesk:security_dashboard")

    def test_anonymous_visitor_is_sent_to_login(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response["Location"])

    def test_ordinary_user_is_refused(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(self.url).status_code, 403)

    def test_staff_see_only_their_own_events_with_masked_ip(self):
        self.client.force_login(self.staff)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        usernames = {row["event"].username for row in response.context["rows"]}
        self.assertNotIn("victim", usernames)
        self.assertContains(response, "10.1.*.*")
        self.assertNotContains(response, "10.1.2.3")
        self.assertNotContains(response, "198.51.100.7")
        self.assertFalse(response.context["full_access"])

    def test_superuser_sees_everything(self):
        self.client.force_login(self.root)
        response = self.client.get(self.url)
        self.assertContains(response, "10.1.2.3")
        self.assertContains(response, "198.51.100.7")
        self.assertTrue(response.context["full_access"])

    def test_filter_by_event_type(self):
        self.client.force_login(self.root)
        response = self.client.get(self.url, {"event_type": "LOGIN_LOCKOUT"})
        types = {row["event"].event_type for row in response.context["rows"]}
        self.assertEqual(types, {"LOGIN_LOCKOUT"})

    def test_staff_cannot_search_by_ip(self):
        self.client.force_login(self.staff)
        response = self.client.get(self.url, {"q": "10.1.2"})
        self.assertEqual(len(response.context["rows"]), 0)

    def test_invalid_filter_values_are_ignored(self):
        self.client.force_login(self.root)
        response = self.client.get(
            self.url,
            {
                "event_type": "<script>",
                "severity": "nope",
                "date_from": "not-a-date",
                "date_to": "2026-13-40",
                "page": "abc",
            },
        )
        self.assertEqual(response.status_code, 200)

    def test_brute_force_alert_for_superuser(self):
        for _ in range(10):
            SecurityEvent.objects.create(
                event_type="LOGIN_FAILED", username="admin", ip_address="203.0.113.9"
            )
        self.client.force_login(self.root)
        response = self.client.get(self.url)
        self.assertContains(response, "Possible brute-force attack")
        self.assertContains(response, "203.0.113.9")

    def test_staff_get_personal_alert(self):
        self.client.force_login(self.staff)
        response = self.client.get(self.url)
        self.assertContains(
            response, "failed or blocked sign-in attempts on your account"
        )

    def test_event_text_is_html_escaped(self):
        SecurityEvent.objects.create(
            event_type="LOGIN_FAILED", username="<script>alert(1)</script>"
        )
        self.client.force_login(self.root)
        response = self.client.get(self.url)
        self.assertNotContains(response, "<script>alert(1)</script>")
        self.assertContains(response, "&lt;script&gt;alert(1)&lt;/script&gt;")

    def test_dashboard_visits_are_audited(self):
        self.client.force_login(self.root)
        self.client.get(self.url)
        self.assertTrue(events("DASHBOARD_VIEWED", username="root").exists())

    def test_mask_ip(self):
        self.assertEqual(mask_ip("192.168.10.25"), "192.168.*.*")
        self.assertEqual(mask_ip("2001:db8:1:2::5"), "2001:db8:****")
        self.assertEqual(mask_ip(""), "")
