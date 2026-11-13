"""Private attachment viewing for the ticket submitter and administrator"""

from django.http import FileResponse, Http404, HttpResponse
from django.shortcuts import get_object_or_404
from django.utils.crypto import constant_time_compare
from django.views.decorators.http import require_safe

from helpdesk.decorators import protect_view
from helpdesk.models import FollowUpAttachment
from helpdesk.user import huser_from_request


@require_safe
@protect_view
def attachment_download(request, ticket_id, attachment_id):
    user = request.user

    # Nobody can view attachments without an active login.
    if not user.is_authenticated or not user.is_active:
        raise Http404

    # The attachment must belong to the requested ticket.
    attachment = get_object_or_404(
        FollowUpAttachment.objects.select_related("followup__ticket"),
        pk=attachment_id,
        followup__ticket_id=ticket_id,
    )

    ticket = attachment.followup.ticket

    can_view_as_staff = user.is_staff and huser_from_request(request).can_access_ticket(
        ticket
    )

    account_email = (user.email or "").strip().casefold()
    submitter_email = (ticket.submitter_email or "").strip().casefold()
    key = request.GET.get("key", "")

    is_owner = bool(
        account_email
        and account_email == submitter_email
        and key
        and ticket.secret_key
        and constant_time_compare(key, ticket.secret_key)
    )

    # Owners may view public follow-up attachments.
    # Staff can view private follow-ups in tickets they may access.
    permitted = can_view_as_staff or (is_owner and attachment.followup.public)

    if not permitted:
        raise Http404

    # Allow browser viewing only for these content types.
    inline_types = {
        "application/pdf",
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "text/plain",
    }

    mime_type = (attachment.mime_type or "").split(";", 1)[0].strip().lower()

    if mime_type not in inline_types:
        return HttpResponse(
            "This file type is not supported for browser viewing.",
            status=415,
            content_type="text/plain",
        )

    try:
        stream = attachment.file.open("rb")
    except FileNotFoundError:
        raise Http404 from None

    response = FileResponse(
        stream,
        as_attachment=False,
        filename=attachment.filename,
        content_type=mime_type,
    )

    response["Cache-Control"] = "private, no-store"
    response["X-Content-Type-Options"] = "nosniff"
    response["Referrer-Policy"] = "no-referrer"

    return response
