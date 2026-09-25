from django.contrib import admin

from .models import ScanRecord


@admin.register(ScanRecord)
class ScanRecordAdmin(admin.ModelAdmin):
    list_display = ("domain", "grade", "score", "high_count", "medium_count",
                    "low_count", "is_wordpress", "scan_date")
    list_filter = ("grade", "is_wordpress", "reachable", "scan_date")
    search_fields = ("domain", "url")
    date_hierarchy = "scan_date"
    readonly_fields = [f.name for f in ScanRecord._meta.fields]

    def has_add_permission(self, request):
        return False
