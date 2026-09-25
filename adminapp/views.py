"""Admin dashboard views. Protected by staff login."""

from django.contrib.admin.views.decorators import staff_member_required
from django.db.models import Avg, Count
from django.shortcuts import render
from django.utils import timezone

from publicapp.models import ScanRecord
from .models import ContactMessage


@staff_member_required
def dashboard(request):
    """A small overview for the team behind Louis WP Scan."""
    now = timezone.now()
    last_30 = now - timezone.timedelta(days=30)

    scans = ScanRecord.objects.all()
    recent = scans.filter(scan_date__gte=last_30)

    context = {
        "total_scans": scans.count(),
        "scans_30d": recent.count(),
        "avg_score": round(scans.aggregate(a=Avg("score"))["a"] or 0, 1),
        "wp_sites": scans.filter(is_wordpress=True).count(),
        "grade_breakdown": list(
            scans.values("grade").annotate(n=Count("id")).order_by("grade")
        ),
        "latest_scans": scans[:15],
        "unhandled_messages": ContactMessage.objects.filter(is_handled=False).count(),
        "latest_messages": ContactMessage.objects.all()[:10],
    }
    return render(request, "adminapp/dashboard.html", context)
