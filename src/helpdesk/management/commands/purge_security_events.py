"""
3.2.4 Audit-log retention.

Security events contain personal data (usernames and IP addresses). Under the
data-minimisation and retention principles of PDPA/GDPR they should not be
kept forever. This command deletes events older than the retention period.

    python manage.py purge_security_events            # uses the setting (default 90 days)
    python manage.py purge_security_events --days 30
    python manage.py purge_security_events --dry-run
"""

from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from helpdesk.security_models import SecurityEvent


class Command(BaseCommand):
    help = "Delete security events older than the retention period."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=getattr(settings, "HELPDESK_SECURITY_EVENT_RETENTION_DAYS", 90),
            help="Keep events from the last N days (default: setting or 90).",
        )
        parser.add_argument("--dry-run", action="store_true", help="Only count, do not delete.")

    def handle(self, *args, **options):
        days = options["days"]
        if days < 1:
            raise CommandError("--days must be at least 1")
        cutoff = timezone.now() - timedelta(days=days)
        old_events = SecurityEvent.objects.filter(timestamp__lt=cutoff)
        count = old_events.count()
        if options["dry_run"]:
            self.stdout.write(f"{count} security event(s) older than {days} days would be deleted.")
            return
        old_events.delete()
        self.stdout.write(self.style.SUCCESS(
            f"Deleted {count} security event(s) older than {days} days."
        ))
