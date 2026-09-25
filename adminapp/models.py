"""Models owned by the admin side of the project."""

from django.db import models
from django.utils.translation import gettext_lazy as _


class ContactMessage(models.Model):
    """A message sent through the public contact form."""

    name = models.CharField(_("name"), max_length=120)
    email = models.EmailField(_("email"))
    subject = models.CharField(_("subject"), max_length=160)
    message = models.TextField(_("message"))
    created_at = models.DateTimeField(_("received"), auto_now_add=True)
    is_handled = models.BooleanField(_("handled"), default=False)

    class Meta:
        verbose_name = _("contact message")
        verbose_name_plural = _("contact messages")
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.subject} - {self.name}"
