from urllib.parse import urlencode

from django.test import TestCase
from django.test.client import Client
from django.urls import reverse

from helpdesk.models import Queue, Ticket


class PublicActionsTestCase(TestCase):
    """
    Tests for public actions:
    - View a ticket
    - Add a followup
    - Close resolved case
    """

    def setUp(self):
        """
        Create a queue & ticket we can use for later tests.
        """
        self.queue = Queue.objects.create(
            title="Queue 1",
            slug="q",
            allow_public_submission=True,
            new_ticket_cc="new.public@example.com",
            updated_ticket_cc="update.public@example.com",
        )
        self.ticket = Ticket.objects.create(
            title="Test Ticket",
            queue=self.queue,
            submitter_email="test.submitter@example.com",
            description="This is a test ticket.",
        )

        self.client = Client()

    def test_public_view_ticket(self):
        # Without key, we get 403
        response = self.client.get(
            "{}?ticket={}&email={}".format(
                reverse("helpdesk:public_view"),
                self.ticket.ticket_for_url,
                "test.submitter@example.com",
            )
        )
        self.assertEqual(response.status_code, 403)
        self.assertTemplateNotUsed(response, "helpdesk/public_view_form.html")
        # With a key it works
        response = self.client.get(
            "{}?ticket={}&email={}&key={}".format(
                reverse("helpdesk:public_view"),
                self.ticket.ticket_for_url,
                "test.submitter@example.com",
                self.ticket.secret_key,
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "helpdesk/public_view_ticket.html")

    def test_public_close(self):
        self.ticket.status = Ticket.RESOLVED_STATUS
        self.ticket.resolution = "Resolved by test script"
        self.ticket.save()
        url = reverse("helpdesk:public_view")
        credentials = {
            "ticket": self.ticket.ticket_for_url,
            "email": self.ticket.submitter_email,
            "key": self.ticket.secret_key,
        }
        url = f"{url}?{urlencode(credentials)}"
        client = Client(enforce_csrf_checks=True)

        response = client.get(url)
        self.assertContains(response, "Accept and Close")
        csrf = client.cookies["csrftoken"].value
        self.assertEqual(client.post(url, {"action": "close"}).status_code, 403)
        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.status, Ticket.RESOLVED_STATUS)
        self.assertFalse(self.ticket.followup_set.exists())

        response = client.post(url, {"action": "close"}, HTTP_X_CSRFTOKEN=csrf)
        self.assertRedirects(response, url, fetch_redirect_response=False)
        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.status, Ticket.CLOSED_STATUS)
        self.assertEqual(self.ticket.followup_set.count(), 1)
        self.assertContains(client.get(response["Location"]), self.ticket.title)
