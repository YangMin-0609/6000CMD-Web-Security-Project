"""
SEC-03: Login rate limiting tests.

Run only these tests:
    uv run python quicktest.py tests.test_login_rate_limit -v 2
"""

import base64
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, modify_settings, override_settings
from django.urls import reverse
from freezegun import freeze_time

PASSWORD = "Correct-Horse-Battery-42"
WRONG = "wrong-password"

User = get_user_model()


@override_settings(
    AUTHENTICATION_BACKENDS=[
        "helpdesk.login_rate_limit.LoginRateLimitBackend",
        "django.contrib.auth.backends.ModelBackend",
    ],
    HELPDESK_LOGIN_RATE_LIMIT_ENABLED=True,
    HELPDESK_LOGIN_FAILURE_LIMIT=5,
    HELPDESK_LOGIN_IP_FAILURE_LIMIT=20,
    HELPDESK_LOGIN_FAILURE_WINDOW=900,
    HELPDESK_LOGIN_LOCKOUT_SECONDS=900,
    HELPDESK_LOGIN_TRUST_X_FORWARDED_FOR=False,
)
@modify_settings(
    MIDDLEWARE={"append": "helpdesk.login_rate_limit.LoginRateLimitMiddleware"}
)
class LoginRateLimitTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.agent = User.objects.create_user(
            "support_agent", "agent@example.com", PASSWORD, is_staff=True
        )
        cls.admin = User.objects.create_superuser("admin", "admin@example.com", PASSWORD)

    def setUp(self):
        cache.clear()
        self.login_url = reverse("helpdesk:login")

    # ---------------------------------------------------------------- helpers
    def login(self, username="support_agent", password=PASSWORD, ip="127.0.0.1", **extra):
        return self.client.post(
            self.login_url,
            {"username": username, "password": password},
            REMOTE_ADDR=ip,
            **extra,
        )

    def fail(self, times, username="support_agent", ip="127.0.0.1", **extra):
        for _ in range(times):
            response = self.login(username, WRONG, ip, **extra)
            self.assertEqual(response.status_code, 200)  # normal "wrong password" page

    def assertLoggedIn(self, response):
        self.assertEqual(response.status_code, 302)
        self.assertIn("_auth_user_id", self.client.session)
        self.client.logout()

    def assertBlocked(self, response):
        self.assertEqual(response.status_code, 429)
        self.assertIn("Retry-After", response)
        self.assertNotIn("_auth_user_id", self.client.session)

    # ------------------------------------------------------- normal behaviour
    def test_correct_password_logs_in(self):
        self.assertLoggedIn(self.login())

    def test_fewer_failures_than_limit_do_not_block(self):
        self.fail(4)
        self.assertLoggedIn(self.login())

    def test_successful_login_resets_the_counter(self):
        self.fail(4)
        self.assertLoggedIn(self.login())
        self.fail(4)  # would be 8 failures without the reset
        self.assertLoggedIn(self.login())

    # ------------------------------------------------------------ the control
    def test_correct_password_blocked_after_five_failures(self):
        """The exact scenario from the SEC-03 finding."""
        self.fail(5)
        response = self.login()
        self.assertBlocked(response)
        self.assertContains(response, "Too many failed login attempts", status_code=429)

    def test_login_works_again_after_lockout_expires(self):
        with freeze_time("2026-11-08 10:00:00") as frozen:
            self.fail(5)
            self.assertBlocked(self.login())

            frozen.tick(timedelta(seconds=600))  # 10 minutes: still locked
            self.assertBlocked(self.login())

            frozen.tick(timedelta(seconds=301))  # 15 minutes + 1 second
            self.assertLoggedIn(self.login())

    def test_unknown_username_is_treated_the_same(self):
        """No user enumeration: a non-existent account is locked exactly like a real one."""
        self.fail(5, username="no_such_user")
        self.assertBlocked(self.login(username="no_such_user"))

    def test_username_case_does_not_bypass_the_limit(self):
        for name in ["support_agent", "SUPPORT_AGENT", "Support_Agent", "support_AGENT", "SuPpOrT_aGeNt"]:
            self.login(name, WRONG)
        self.assertBlocked(self.login())

    def test_lock_is_per_username_and_ip(self):
        """An attacker at one IP cannot lock the real user out from another IP (lockout DoS)."""
        self.fail(5, ip="10.0.0.66")
        self.assertBlocked(self.login(ip="10.0.0.66"))
        self.assertLoggedIn(self.login(ip="10.0.0.10"))  # real user elsewhere
        self.assertLoggedIn(self.login(username="admin", ip="10.0.0.66"))  # other account

    def test_password_spraying_from_one_ip_is_blocked(self):
        """Trying one password against many accounts trips the per-IP limit."""
        for i in range(20):
            self.login(f"user{i}", WRONG, ip="10.0.0.77")
        self.assertBlocked(self.login(ip="10.0.0.77"))

    def test_spoofed_x_forwarded_for_does_not_bypass(self):
        for i in range(5):
            self.login(password=WRONG, HTTP_X_FORWARDED_FOR=f"203.0.113.{i}")
        self.assertBlocked(self.login(HTTP_X_FORWARDED_FOR="203.0.113.200"))

    # ------------------------------------------------- other login entry points
    def test_admin_login_is_rate_limited(self):
        url = reverse("admin:login")
        for _ in range(5):
            self.client.post(url, {"username": "admin", "password": WRONG})
        response = self.client.post(url, {"username": "admin", "password": PASSWORD})
        self.assertBlocked(response)

    def test_api_basic_auth_is_rate_limited(self):
        url = reverse("helpdesk:ticket-list")

        def basic(password):
            token = base64.b64encode(f"admin:{password}".encode()).decode()
            return {"HTTP_AUTHORIZATION": f"Basic {token}"}

        self.assertEqual(self.client.get(url, **basic(PASSWORD)).status_code, 200)
        for _ in range(5):
            # DRF answers 403 instead of 401 because SessionAuthentication is its
            # first authentication class; either way the wrong password is rejected
            self.assertIn(self.client.get(url, **basic(WRONG)).status_code, (401, 403))
        response = self.client.get(url, **basic(PASSWORD))
        self.assertEqual(response.status_code, 429)
        self.assertIn("Retry-After", response)
        self.assertIn("Too many failed login attempts", response.json()["detail"])

    def test_web_login_and_api_share_the_same_counter(self):
        """Switching between entry points does not give the attacker extra guesses."""
        self.fail(3, username="admin")
        url = reverse("helpdesk:ticket-list")
        token = base64.b64encode(f"admin:{WRONG}".encode()).decode()
        for _ in range(2):
            self.client.get(url, HTTP_AUTHORIZATION=f"Basic {token}")
        self.assertBlocked(self.login(username="admin"))

    # ----------------------------------------------------------------- logging
    def test_security_events_are_logged_without_passwords(self):
        with self.assertLogs("helpdesk.security", level="INFO") as logs:
            self.fail(5)
            self.login()
        output = "\n".join(logs.output)
        self.assertIn("LOGIN_FAILED username=support_agent", output)
        self.assertIn("LOGIN_LOCKOUT", output)
        self.assertIn("LOGIN_BLOCKED", output)
        self.assertNotIn(WRONG, output)
        self.assertNotIn(PASSWORD, output)

    def test_newlines_in_username_cannot_forge_log_lines(self):
        with self.assertLogs("helpdesk.security", level="INFO") as logs:
            self.login("evil\nLOGIN_SUCCESS username=admin", WRONG)
        self.assertNotIn("\nLOGIN_SUCCESS", "\n".join(record.getMessage() for record in logs.records))

    # ---------------------------------------------------------- feature switch
    @override_settings(HELPDESK_LOGIN_RATE_LIMIT_ENABLED=False)
    def test_can_be_disabled(self):
        self.fail(10)
        self.assertLoggedIn(self.login())