"""
3.2.5 Logging and analytics dashboard.

Access is decided on the server (RBAC), and what each role sees depends on
what it needs:

    Role                  Access
    --------------------  ------------------------------------------------------
    Anonymous visitor     redirected to the login page
    Ordinary user         HTTP 403 (recorded as PERMISSION_DENIED)
    Staff member          only events about their own account; IP addresses
                          masked; personal alert about failed logins
    Superuser             all events, full IP addresses, system-wide alerts
                          and the top attacking IP addresses

Every visit is itself recorded (DASHBOARD_VIEWED), so access to the security
log is auditable.
"""

from datetime import datetime, time, timedelta

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.shortcuts import render
from django.utils import timezone
from django.utils.dateparse import parse_date

from helpdesk.security_audit import mask_ip, record
from helpdesk.security_models import SecurityEvent

PAGE_SIZE = 50

# Thresholds for the suspicious-activity indicators (last 24 hours)
FAILED_LOGINS_PER_IP_ALERT = 10
LOCKOUTS_PER_ACCOUNT_ALERT = 2

SUMMARY_GROUPS = {
    "failed_logins": ["LOGIN_FAILED", "LOGIN_BLOCKED"],
    "lockouts": ["LOGIN_LOCKOUT"],
    "permission_denials": ["PERMISSION_DENIED"],
    "privilege_changes": ["PRIVILEGE_CHANGE", "ROLE_CHANGE", "ESCALATION_BLOCKED"],
}


def _scope(user):
    """Events this user is allowed to see."""
    events = SecurityEvent.objects.select_related("actor")
    if user.is_superuser:
        return events
    return events.filter(Q(username__iexact=user.get_username()) | Q(actor=user))


def _start_of_day(value):
    start = datetime.combine(value, time.min)
    return timezone.make_aware(start) if settings.USE_TZ else start


def _today():
    return timezone.localdate() if settings.USE_TZ else timezone.now().date()


def _safe_date(value):
    """parse_date returns None for bad formats but raises for impossible dates."""
    try:
        return parse_date(value) if value else None
    except ValueError:
        return None


def _apply_filters(events, params, full_access):
    """Apply the search form. Invalid values are ignored rather than causing errors."""
    filters = {
        "event_type": params.get("event_type", ""),
        "severity": params.get("severity", ""),
        "q": params.get("q", "").strip()[:100],
        "date_from": params.get("date_from", ""),
        "date_to": params.get("date_to", ""),
    }
    if filters["event_type"] in SecurityEvent.EventType.values:
        events = events.filter(event_type=filters["event_type"])
    else:
        filters["event_type"] = ""

    if filters["severity"] in SecurityEvent.Severity.values:
        events = events.filter(severity=filters["severity"])
    else:
        filters["severity"] = ""

    if filters["q"]:
        search = Q(username__icontains=filters["q"]) | Q(description__icontains=filters["q"])
        if full_access:  # only superusers may search by IP address
            search |= Q(ip_address__icontains=filters["q"])
        events = events.filter(search)

    date_from = _safe_date(filters["date_from"])
    date_to = _safe_date(filters["date_to"])
    if date_from:
        events = events.filter(timestamp__gte=_start_of_day(date_from))
    else:
        filters["date_from"] = ""
    if date_to:
        events = events.filter(timestamp__lt=_start_of_day(date_to + timedelta(days=1)))
    else:
        filters["date_to"] = ""
    return events, filters


def _summary(events, since):
    recent = events.filter(timestamp__gte=since)
    counts = dict(recent.values_list("event_type").annotate(n=Count("id")))
    return {
        key: sum(counts.get(event_type, 0) for event_type in types)
        for key, types in SUMMARY_GROUPS.items()
    }


def _daily_activity(events, days=7):
    """Failed logins and permission denials per day, for the bar chart."""
    today = _today()
    first_day = today - timedelta(days=days - 1)
    rows = (
        events.filter(
            timestamp__gte=_start_of_day(first_day),
            event_type__in=["LOGIN_FAILED", "LOGIN_BLOCKED", "PERMISSION_DENIED"],
        )
        .annotate(day=TruncDate("timestamp"))
        .values("day", "event_type")
        .annotate(n=Count("id"))
    )
    per_day = {first_day + timedelta(days=i): {"failed": 0, "denied": 0} for i in range(days)}
    for row in rows:
        bucket = per_day.get(row["day"])
        if bucket is None:
            continue
        key = "denied" if row["event_type"] == "PERMISSION_DENIED" else "failed"
        bucket[key] += row["n"]
    peak = max([b["failed"] + b["denied"] for b in per_day.values()] + [1])
    return [
        {
            "day": day,
            "failed": b["failed"],
            "denied": b["denied"],
            "failed_pct": round(100 * b["failed"] / peak),
            "denied_pct": round(100 * b["denied"] / peak),
        }
        for day, b in per_day.items()
    ]


def _alerts(user, events, since):
    """Suspicious-activity indicators for the last 24 hours."""
    recent = events.filter(timestamp__gte=since)
    alerts = []
    if user.is_superuser:
        noisy_ips = (
            recent.filter(event_type__in=["LOGIN_FAILED", "LOGIN_BLOCKED"])
            .exclude(ip_address="")
            .values("ip_address")
            .annotate(n=Count("id"))
            .filter(n__gte=FAILED_LOGINS_PER_IP_ALERT)
            .order_by("-n")
        )
        for row in noisy_ips:
            alerts.append({
                "level": "danger",
                "text": f"Possible brute-force attack: {row['n']} failed logins "
                        f"from {row['ip_address']} in the last 24 hours.",
            })
        repeated = (
            recent.filter(event_type="LOGIN_LOCKOUT")
            .values("username")
            .annotate(n=Count("id"))
            .filter(n__gte=LOCKOUTS_PER_ACCOUNT_ALERT)
        )
        for row in repeated:
            alerts.append({
                "level": "warning",
                "text": f"Account '{row['username']}' was locked {row['n']} times "
                        f"in the last 24 hours.",
            })
        escalations = recent.filter(event_type="ESCALATION_BLOCKED").count()
        if escalations:
            alerts.append({
                "level": "danger",
                "text": f"{escalations} blocked privilege-escalation attempt(s) "
                        f"in the last 24 hours.",
            })
        new_superusers = recent.filter(event_type="PRIVILEGE_CHANGE", severity="CRITICAL").count()
        if new_superusers:
            alerts.append({
                "level": "warning",
                "text": f"{new_superusers} account(s) were given superuser status "
                        f"in the last 24 hours. Confirm these changes were authorised.",
            })
    else:
        failures = recent.filter(
            event_type__in=["LOGIN_FAILED", "LOGIN_BLOCKED", "LOGIN_LOCKOUT"]
        ).count()
        if failures:
            alerts.append({
                "level": "warning",
                "text": f"There were {failures} failed or blocked sign-in attempts on your "
                        f"account in the last 24 hours. If this was not you, change your "
                        f"password and tell an administrator.",
            })
    return alerts


@login_required
def security_dashboard(request):
    user = request.user
    if not user.is_staff:
        # Turned into HTTP 403 and recorded as PERMISSION_DENIED by the middleware
        raise PermissionDenied("The security dashboard is only available to staff.")

    full_access = user.is_superuser
    scoped = _scope(user)
    since = timezone.now() - timedelta(hours=24)

    events, filters = _apply_filters(scoped, request.GET, full_access)
    page = Paginator(events, PAGE_SIZE).get_page(request.GET.get("page"))

    rows = [
        {
            "event": event,
            "ip": event.ip_address if full_access else mask_ip(event.ip_address),
        }
        for event in page.object_list
    ]

    top_ips = []
    if full_access:
        top_ips = list(
            scoped.filter(timestamp__gte=since,
                          event_type__in=["LOGIN_FAILED", "LOGIN_BLOCKED"])
            .exclude(ip_address="")
            .values("ip_address")
            .annotate(n=Count("id"))
            .order_by("-n")[:5]
        )

    query = request.GET.copy()
    query.pop("page", None)

    context = {
        "full_access": full_access,
        "summary": _summary(scoped, since),
        "alerts": _alerts(user, scoped, since),
        "daily": _daily_activity(scoped),
        "top_ips": top_ips,
        "rows": rows,
        "page": page,
        "filters": filters,
        "query_string": query.urlencode(),
        "event_types": SecurityEvent.EventType.choices,
        "severities": SecurityEvent.Severity.choices,
    }
    response = render(request, "helpdesk/security_dashboard.html", context)

    record(
        "DASHBOARD_VIEWED",
        request=request,
        username=user.get_username(),
        description="Full view" if full_access else "Own-account view",
        log=False,
    )
    return response
