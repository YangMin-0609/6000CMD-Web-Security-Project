from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.db import migrations


def move_existing_ticket_attachments(apps, schema_editor):
    if not settings.MEDIA_ROOT:
        return

    attachments = apps.get_model("helpdesk", "FollowUpAttachment")
    private = attachments._meta.get_field("file").storage
    public = FileSystemStorage(location=settings.MEDIA_ROOT)
    names = (
        attachments.objects.using(schema_editor.connection.alias)
        .exclude(file="")
        .values_list("file", flat=True)
        .distinct()
    )
    for name in names.iterator():
        if not public.exists(name):
            continue
        if not private.exists(name):
            with public.open(name, "rb") as source:
                saved_name = private.save(name, source)
            if saved_name != name:
                private.delete(saved_name)
                raise RuntimeError("Could not preserve the existing attachment path.")
        else:
            with public.open(name, "rb") as source, private.open(name, "rb") as target:
                for chunk in source.chunks():
                    if chunk != target.read(len(chunk)):
                        raise RuntimeError("Conflicting public and private attachment contents.")
                if target.read(1):
                    raise RuntimeError("Conflicting public and private attachment contents.")
        public.delete(name)


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("helpdesk", "0040_private_ticket_attachments"),
        ("helpdesk", "0040_securityevent"),
    ]

    operations = [
        migrations.RunPython(move_existing_ticket_attachments, migrations.RunPython.noop),
    ]
