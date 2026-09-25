# Logics for the public side of Louis WP Scan.

import json
import time

from django.conf import settings
from django.core import signing
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.translation import gettext as _
from django.views.decorators.http import require_POST

from adminapp.models import ContactMessage
from .forms import ContactForm, ScanForm
from .models import ScanRecord
from .scanner import scan_site

# ----------------------
# A visitor can run 3 scans. After they must wait 24 hours before
# the allowance resets and they can run 3 more. The count lives in a signed
# (tamper proof) cookie, so we store nothing about the visitor on our side.
# -----------------------
SCAN_COOKIE = "lwps_quota"
SCAN_COOKIE_SALT = "lwps-scan-quota"
SCAN_LIMIT = 3
SCAN_WINDOW = 24 * 60 * 60  # 24 hours in seconds


def _read_quota(request, now):
    #Returning (start, count) for the current 24 hour window.
    try:
        raw = request.get_signed_cookie(SCAN_COOKIE, salt=SCAN_COOKIE_SALT)
        data = json.loads(raw)
        start = int(data.get("start", now))
        count = int(data.get("count", 0))
    except (KeyError, signing.BadSignature, ValueError, TypeError):
        return now, 0
    # If the window has fully passed, start a fresh one.
    if now - start >= SCAN_WINDOW:
        return now, 0
    return start, count


def _set_quota(response, start, count, secure):
    response.set_signed_cookie(
        SCAN_COOKIE,
        json.dumps({"start": start, "count": count}),
        salt=SCAN_COOKIE_SALT,
        max_age=SCAN_WINDOW,
        httponly=True,
        samesite="Lax",
        secure=secure,
    )


def home(request):
    #Landing page with the single scan input.
    return render(request, "public/home.html", {"form": ScanForm()})


@require_POST
def scan_api(request):
    """
    Run a scan and return JSON. The home page calls this with fetch() so it can
    play the scanning animation, then redirect to the result page.
    """
    # 1. Enforce the free usage limit before doing any work.
    now = int(time.time())
    start, count = _read_quota(request, now)
    if count >= SCAN_LIMIT:
        retry_secs = max(0, SCAN_WINDOW - (now - start))
        hours = max(1, round(retry_secs / 3600))
        return JsonResponse({
            "ok": False,
            "limit": True,
            "error": _("You have used your 3 free scans. Please come back in about "
                       "%(hours)s hours to scan more. This limit keeps our non profit "
                       "service available to everyone.") % {"hours": hours},
        }, status=429)

    # 2. Validate the address.
    try:
        payload = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        payload = {}
    form = ScanForm({"url": payload.get("url", "")})
    if not form.is_valid():
        return JsonResponse(
            {"ok": False, "error": _("Please enter a valid website address.")},
            status=400,
        )

    # 3. Run the scan.
    try:
        result = scan_site(form.cleaned_data["url"])
    except ValueError:
        return JsonResponse(
            {"ok": False, "error": _("That address could not be read.")},
            status=400,
        )

    record = ScanRecord.from_result(result)

    # 4. Count this scan and refresh the cookie.
    response = JsonResponse({
        "ok": True,
        "redirect": reverse("public:scan_result", args=[record.pk]),
    })
    _set_quota(response, start, count + 1, secure=not settings.DEBUG)
    return response


def scan_result(request, pk):
    ''' #Show the stored result of a scan.

    We re-run the live scan to display the full guidance, because we keep only a
    compact summary in the database.
    '''
    record = get_object_or_404(ScanRecord, pk=pk)
    result = scan_site(record.url)
    grouped = _group_by_category(result["checks"])
    return render(request, "public/scan_result.html", {
        "record": record,
        "result": result,
        "grouped": grouped,
    })


def _group_by_category(checks):
    grouped = {}
    for c in checks:
        grouped.setdefault(c["category"], []).append(c)
    # Issues first inside each category.
    order = {"issue": 0, "warning": 1, "ok": 2, "info": 3}
    for items in grouped.values():
        items.sort(key=lambda c: order.get(c["status"], 9))
    return grouped


def about(request):
    return render(request, "public/about.html")


def founding_story(request):
    return render(request, "public/founding_story.html")


def contact(request):
    if request.method == "POST":
        form = ContactForm(request.POST)
        if form.is_valid():
            ContactMessage.objects.create(
                name=form.cleaned_data["name"],
                email=form.cleaned_data["email"],
                subject=form.cleaned_data["subject"],
                message=form.cleaned_data["message"],
            )
            return redirect("public:contact_done")
    else:
        form = ContactForm()
    return render(request, "public/contact.html", {"form": form})


def contact_done(request):
    return render(request, "public/contact_done.html")


def privacy(request):
    return render(request, "public/privacy.html", {
        "ga_id": getattr(settings, "GOOGLE_ANALYTICS_ID", ""),
    })


def terms(request):
    return render(request, "public/terms.html")
