"""URL routes for the public app."""

from django.urls import path

from . import views

app_name = "public"

urlpatterns = [
    path("", views.home, name="home"),
    path("scan/", views.scan_api, name="scan_api"),
    path("result/<int:pk>/", views.scan_result, name="scan_result"),
    path("about/", views.about, name="about"),
    path("founding-story/", views.founding_story, name="founding_story"),
    path("contact/", views.contact, name="contact"),
    path("contact/thank-you/", views.contact_done, name="contact_done"),
    path("privacy-policy/", views.privacy, name="privacy"),
    path("terms-and-conditions/", views.terms, name="terms"),
]
