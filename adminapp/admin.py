from django.contrib import admin
from .models import ContactMessage
from django.contrib import admin

admin.site.site_header = "Louis WP Scan Administration"   # top of every admin page + login page
admin.site.site_title = "Louis WP Scan"                   # browser tab title
admin.site.index_title = "Dashboard"                      # heading on the admin home page

@admin.register(ContactMessage)
class ContactMessageAdmin(admin.ModelAdmin):
    list_display = ("subject", "name", "email", "is_handled", "created_at")
    list_filter = ("is_handled", "created_at")
    search_fields = ("name", "email", "subject", "message")
    list_editable = ("is_handled",)
    date_hierarchy = "created_at"
    readonly_fields = ("name", "email", "subject", "message", "created_at")
