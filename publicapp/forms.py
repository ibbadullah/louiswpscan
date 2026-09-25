from django import forms
from django.utils.translation import gettext_lazy as _


class ScanForm(forms.Form):
    #The single input on the home page. One URL to scan.

    url = forms.CharField(
        label=_("Website address"),
        max_length=500,
        widget=forms.TextInput(attrs={
            "class": "form-control form-control-lg",
            "placeholder": _("example.com"),
            "autocomplete": "off",
            "spellcheck": "false",
            "aria-label": _("Website address to scan"),
        }),
    )

    def clean_url(self):
        value = (self.cleaned_data["url"] or "").strip()
        if " " in value or "." not in value:
            raise forms.ValidationError(_("Please enter a valid website address."))
        return value


class ContactForm(forms.Form):
    # Contact form. Stored as a message for the admin to read.

    name = forms.CharField(
        label=_("Your name"), max_length=120,
        widget=forms.TextInput(attrs={"class": "form-control"}),
    )
    email = forms.EmailField(
        label=_("Your email"),
        widget=forms.EmailInput(attrs={"class": "form-control"}),
    )
    subject = forms.CharField(
        label=_("Subject"), max_length=160,
        widget=forms.TextInput(attrs={"class": "form-control"}),
    )
    message = forms.CharField(
        label=_("Message"),
        widget=forms.Textarea(attrs={"class": "form-control", "rows": 6}),
    )
    # Simple honeypot for bots. If this field gets value then it means it is a bot. Real users never see or fill this field.
    website = forms.CharField(required=False, widget=forms.HiddenInput())

    def clean_website(self):
        if self.cleaned_data.get("website"):
            raise forms.ValidationError("spam detected")
        return ""
