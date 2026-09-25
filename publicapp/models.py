"""Database models for the public side of Louis WP Scan.

We deliberately store very little. We keep the scanned URL, the date, and a
compact summary of the result (counts and the list of finding ids with their
severity). We do NOT store full page contents, headers or any personal data of
the site owner. This keeps us lean and friendly to EU data protection rules.
"""

from urllib.parse import urlparse

from django.db import models
from django.utils.translation import gettext_lazy as _


class ScanRecord(models.Model):
    """A single completed scan. Stores only summary data, never raw content."""

    GRADE_CHOICES = [
        ("A", "A"), ("B", "B"), ("C", "C"), ("D", "D"), ("F", "F"), ("N/A", "N/A"),
    ]

    url = models.URLField(_("scanned URL"), max_length=500)
    domain = models.CharField(_("domain"), max_length=255, db_index=True)
    scan_date = models.DateTimeField(_("scan date"), auto_now_add=True, db_index=True)

    is_wordpress = models.BooleanField(_("is WordPress"), default=False)
    reachable = models.BooleanField(_("reachable"), default=True)

    score = models.PositiveSmallIntegerField(_("security score"), default=0)
    grade = models.CharField(_("grade"), max_length=3, choices=GRADE_CHOICES, default="N/A")

    high_count = models.PositiveSmallIntegerField(_("high issues"), default=0)
    medium_count = models.PositiveSmallIntegerField(_("medium issues"), default=0)
    low_count = models.PositiveSmallIntegerField(_("low issues"), default=0)

    # Compact list of {"id", "severity", "status"} so we can show trends and
    # build a result page link without storing the full report text.
    summary = models.JSONField(_("summary"), default=list, blank=True)

    class Meta:
        verbose_name = _("scan record")
        verbose_name_plural = _("scan records")
        ordering = ["-scan_date"]

    def __str__(self):
        return f"{self.domain} ({self.grade}) {self.scan_date:%Y-%m-%d}"

    @property
    def total_issues(self):
        return self.high_count + self.medium_count + self.low_count

    @classmethod
    def from_result(cls, result: dict) -> "ScanRecord":
        """Build and persist a record from a scanner result dictionary."""
        counts = result.get("counts", {})
        compact = [
            {"id": c["id"], "severity": c["severity"], "status": c["status"]}
            for c in result.get("checks", [])
        ]
        return cls.objects.create(
            url=result["url"],
            domain=urlparse(result["url"]).netloc,
            is_wordpress=result.get("is_wordpress", False),
            reachable=result.get("reachable", True),
            score=result.get("score", 0),
            grade=result.get("grade", "N/A"),
            high_count=counts.get("high", 0),
            medium_count=counts.get("medium", 0),
            low_count=counts.get("low", 0),
            summary=compact,
        )
