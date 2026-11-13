# validators.py
#
# validators for file uploads, etc.

from django.utils.translation import gettext as _

from helpdesk import settings as helpdesk_settings

# TODO: can we use the builtin Django validator instead?
# see:
# https://docs.djangoproject.com/en/4.0/ref/validators/#fileextensionvalidator


def validate_file_extension(value):
    import os

    from django.core.exceptions import ValidationError

    ext = os.path.splitext(value.name)[1]  # [0] returns path+filename
    if not helpdesk_settings.HELPDESK_VALIDATE_ATTACHMENT_TYPES:
        return

    # TODO: one more check in case it is a file with no extension; we
    # should always allow that?
    if ext.lower() not in helpdesk_settings.HELPDESK_VALID_EXTENSIONS and not (
        ext.lower() == "" or ext.lower() == "."
    ):
        raise ValidationError(_("Unsupported file extension: ") + ext.lower())

    if ext.lower() in (".png", ".jpg", ".jpeg"):
        from PIL import Image, UnidentifiedImageError

        expected_format = "PNG" if ext.lower() == ".png" else "JPEG"
        file_object = value.file
        original_position = file_object.tell()
        try:
            file_object.seek(0)
            with Image.open(file_object) as image:
                actual_format = image.format
                image.verify()
            if actual_format != expected_format:
                raise ValidationError(
                    _("Image content does not match file extension: ") + ext.lower()
                )
        except (
            UnidentifiedImageError,
            OSError,
            SyntaxError,
            ValueError,
            Image.DecompressionBombError,
        ):
            raise ValidationError(_("Invalid image file: ") + ext.lower()) from None
        finally:
            file_object.seek(original_position)
