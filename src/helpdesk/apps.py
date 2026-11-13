from django.apps import AppConfig


class HelpdeskConfig(AppConfig):
    name = "helpdesk"
    verbose_name = "Helpdesk"
    # for Django 3.2 support:
    # see:
    # https://docs.djangoproject.com/en/3.2/ref/applications/#django.apps.AppConfig.default_auto_field
    default_auto_field = "django.db.models.AutoField"

    def ready(self):
        from . import webhooks  # noqa: F401
        from .login_rate_limit import connect_signals

        # SEC-03: count failed / successful logins for rate limiting
        connect_signals()

        # 3.2.4: audit logging of security events
        from .security_audit import connect_signals as connect_audit_signals

        connect_audit_signals()
