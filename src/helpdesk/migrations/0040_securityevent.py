# 3.2.4 Audit logging: SecurityEvent table

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("helpdesk", "0039_alter_ticketchange_field"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="SecurityEvent",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "timestamp",
                    models.DateTimeField(
                        db_index=True,
                        default=django.utils.timezone.now,
                        verbose_name="Time",
                    ),
                ),
                (
                    "event_type",
                    models.CharField(
                        choices=[
                            ("LOGIN_SUCCESS", "Login success"),
                            ("LOGIN_FAILED", "Login failure"),
                            ("LOGIN_LOCKOUT", "Account lockout"),
                            ("LOGIN_BLOCKED", "Login blocked (locked out)"),
                            ("LOGOUT", "Logout"),
                            ("PERMISSION_DENIED", "Permission denied"),
                            ("USER_CREATED", "User created"),
                            ("USER_DELETED", "User deleted"),
                            ("PRIVILEGE_CHANGE", "Privilege change"),
                            ("ROLE_CHANGE", "Group / permission change"),
                            ("ESCALATION_BLOCKED", "Privilege escalation blocked"),
                            ("ADMIN_ACTION", "Administrator action"),
                            ("SENSITIVE_ACCESS", "Ticket record viewed"),
                            ("DASHBOARD_VIEWED", "Security dashboard viewed"),
                        ],
                        db_index=True,
                        max_length=32,
                        verbose_name="Event",
                    ),
                ),
                (
                    "severity",
                    models.CharField(
                        choices=[
                            ("INFO", "Info"),
                            ("WARNING", "Warning"),
                            ("CRITICAL", "Critical"),
                        ],
                        default="INFO",
                        max_length=10,
                        verbose_name="Severity",
                    ),
                ),
                (
                    "username",
                    models.CharField(
                        blank=True, db_index=True, max_length=150, verbose_name="Account"
                    ),
                ),
                (
                    "ip_address",
                    models.CharField(blank=True, max_length=45, verbose_name="IP address"),
                ),
                (
                    "path",
                    models.CharField(blank=True, max_length=255, verbose_name="Path"),
                ),
                (
                    "description",
                    models.CharField(blank=True, max_length=500, verbose_name="Details"),
                ),
                (
                    "actor",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to=settings.AUTH_USER_MODEL,
                        verbose_name="Performed by",
                    ),
                ),
            ],
            options={
                "verbose_name": "Security event",
                "verbose_name_plural": "Security events",
                "ordering": ("-timestamp", "-id"),
            },
        ),
    ]
