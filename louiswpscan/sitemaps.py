# sitemaps for the static pages
from django.contrib.sitemaps import Sitemap
from django.urls import reverse


class StaticSitemap(Sitemap):
    priority = 0.6
    changefreq = 'weekly'

    def items(self):
        return ['public:home', 'public:about', 'public:founding_story' ,'public:terms','public:privacy', 'public:contact']

    def location(self, item):
        return reverse(item)
    

sitemaps = {
    'static': StaticSitemap,
}