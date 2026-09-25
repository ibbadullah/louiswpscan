# Values made available to every template.

from django.conf import settings
from django.urls import translate_url
from django.utils import timezone


def site_globals(request):
    # lets a visitor switch from /fr/about/ back to /about/ (English).
    path = request.path
    return {
        "SITE_NAME": "Louis WP Scan",
        "SITE_DOMAIN": "louiswpscan.org",
        "SITE_URL": "https://louiswpscan.org",
        "CURRENT_YEAR": timezone.now().year,
        "GOOGLE_ANALYTICS_ID": getattr(settings, "GOOGLE_ANALYTICS_ID", ""),
        "URL_EN": translate_url(path, "en"),
        "URL_FR": translate_url(path, "fr"),
    }