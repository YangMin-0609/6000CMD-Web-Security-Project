"""Non-public filesystem storage for ticket attachments"""

import os
from pathlib import Path

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.files.storage import FileSystemStorage
from django.utils.deconstruct import deconstructible


@deconstructible
class PrivateAttachmentStorage(FileSystemStorage):
    def __init__(self):
        super().__init__(file_permissions_mode=0o600, directory_permissions_mode=0o700)

    @property
    def location(self):
        base = Path(getattr(settings, "BASE_DIR", Path.cwd()))
        private = Path(
            getattr(
                settings,
                "HELPDESK_PRIVATE_ATTACHMENT_ROOT",
                base / "private_helpdesk_attachments",
            )
        ).resolve()
        media_root = getattr(settings, "MEDIA_ROOT", "")
        if media_root and private.is_relative_to(Path(media_root).resolve()):
            raise ImproperlyConfigured(
                "HELPDESK_PRIVATE_ATTACHMENT_ROOT must be outside MEDIA_ROOT."
            )
        return os.fspath(private)

    def url(self, name):
        raise ValueError("Private attachments require the authorised download route.")


def private_attachment_storage():
    return PrivateAttachmentStorage()
