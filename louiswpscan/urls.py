# Root URL configuration
from django.conf.urls.i18n import i18n_patterns
from django.contrib import admin
from django.urls import include, path
from django.contrib.sitemaps.views import sitemap
from .sitemaps import StaticSitemap, sitemaps
from django.shortcuts import HttpResponse
from django.views.generic import TemplateView



def robots_txt(request):
    scheme = request.scheme
    domain = request.get_host()
    base_url = f"{scheme}://{domain}"

    lines = [
        "User-agent: *",
        "",
        "Allow: /",
        "",
        "Disallow: /scp/",
        "Disallow: /scan/",
        "Disallow: /result/",
        "",
        f"Sitemap: {base_url}/sitemaps.xml",
    ]
    return HttpResponse("\n".join(lines), content_type="text/plain")


# Language switching endpoint (set_language) lives outside the i18n prefix.
urlpatterns = [
    path("i18n/", include("django.conf.urls.i18n")),
    path("llms.txt", TemplateView.as_view(
        template_name="llm.txt", content_type="text/plain")),
]

# Everything user facing is wrapped so URLs look like /en/... and /fr/...
urlpatterns += i18n_patterns(
    path("sitemaps.xml",sitemap,{"sitemaps":sitemaps}),
    path("scp/", admin.site.urls),
    path("team/", include("adminapp.urls")),
    path("", include("publicapp.urls")),
    path("robots.txt",robots_txt),
    prefix_default_language=False,  # English language stays at / without a prefix
)
