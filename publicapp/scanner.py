'''
Louis WP Scan - WordPress security scanner engine.

This module performs a lightweight, non-intrusive security scan of a public
WordPress site. It only sends ordinary HTTP GET requests to public URLs that a
normal browser would request. It never attempts to log in, never sends a
payload, and never runs a brute force or denial of service test against the
target.

No paid third party API is used. Everything is done with the `requests` library.
'''

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin

import requests
from django.utils.translation import gettext as _

USER_AGENT = (
    "LouisWPScan/1.0 (+https://louiswpscan.org; "
    "non-profit WordPress security scanner)"
)
REQUEST_TIMEOUT = 8  # seconds, kept low so a slow target cannot block a worker
MAX_BYTES = 200_000  # we never read more than this from any single response

# Severity weights used to compute the final security score (0-100).
SEVERITY_WEIGHT = {"high": 22, "medium": 11, "low": 5, "info": 0}


@dataclass
class CheckResult:
    """One single security finding produced by a check."""

    check_id: str
    title: str
    category: str
    status: str  # "issue", "warning", "ok" or "info"
    severity: str  # "high", "medium", "low" or "info"
    finding: str
    fix: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.check_id,
            "title": self.title,
            "category": self.category,
            "status": self.status,
            "severity": self.severity,
            "finding": self.finding,
            "fix": self.fix,
        }


# ------------------------------------------------------
# Low level helpers
# ----------------------------------------------------

def normalize_url(raw_url: str) -> str:
    """Clean up user input and return a usable absolute base URL."""
    raw_url = (raw_url or "").strip()
    if not raw_url:
        raise ValueError("empty url")
    if not re.match(r"^https?://", raw_url, re.IGNORECASE):
        raw_url = "https://" + raw_url
    parsed = urlparse(raw_url)
    if not parsed.netloc:
        raise ValueError("invalid url")
    # Drop any path, query or fragment. We always work from the site root.
    return f"{parsed.scheme}://{parsed.netloc}"


def _new_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
    session.max_redirects = 5
    return session


def _get(session: requests.Session, url: str, allow_redirects: bool = True):
    """Perform a guarded GET. Returns the response or None on any failure."""
    try:
        resp = session.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=allow_redirects,
            stream=True,
            verify=True,
        )
        # Read at most MAX_BYTES so a huge file cannot exhaust memory.
        content = resp.raw.read(MAX_BYTES, decode_content=True) or b""
        resp._content = content
        return resp
    except requests.RequestException:
        return None


def _text(resp) -> str:
    if resp is None:
        return ""
    try:
        return resp.content.decode(resp.encoding or "utf-8", errors="ignore")
    except (LookupError, AttributeError):
        return resp.content.decode("utf-8", errors="ignore")


# ----------------------
# The scan
# ------------------

def scan_site(raw_url: str) -> dict:
    """
    Run the full scan and return a serializable result dictionary.

    The returned dict is the single source of truth used by the view, the
    template and the stored database record.
    """
    base_url = normalize_url(raw_url)
    session = _new_session()

    home = _get(session, base_url + "/")
    reachable = home is not None
    checks: list[CheckResult] = []

    if not reachable:
        return {
            "url": base_url,
            "reachable": False,
            "is_wordpress": False,
            "score": 0,
            "grade": "N/A",
            "counts": {"high": 0, "medium": 0, "low": 0},
            "checks": [],
        }

    home_html = _text(home)
    home_headers = {k.lower(): v for k, v in home.headers.items()}
    final_url = home.url  # after redirects, tells us if http went to https

    is_wp = _detect_wordpress(session, base_url, home_html, home_headers)

    # Always useful, even on non WordPress sites.
    checks.append(_check_https(base_url, final_url, home_headers))
    checks.append(_check_security_headers(home_headers))
    checks.append(_check_ddos_waf(home_headers))

    if is_wp:
        checks.append(_check_version_disclosure(session, base_url, home_html))
        checks.append(_check_xmlrpc(session, base_url))
        checks.append(_check_wp_admin(session, base_url))
        checks.append(_check_login_exposure(session, base_url))
        checks.append(_check_default_username(session, base_url))
        checks.append(_check_user_enumeration(session, base_url))
        checks.append(_check_directory_listing(session, base_url))
        checks.append(_check_debug_log(session, base_url))
        checks.append(_check_default_files(session, base_url))

    counts = {"high": 0, "medium": 0, "low": 0}
    for c in checks:
        if c.status in ("issue", "warning") and c.severity in counts:
            counts[c.severity] += 1

    score = _compute_score(checks)

    return {
        "url": base_url,
        "reachable": True,
        "is_wordpress": is_wp,
        "score": score,
        "grade": _grade(score),
        "counts": counts,
        "checks": [c.to_dict() for c in checks],
    }


def _compute_score(checks: list[CheckResult]) -> int:
    score = 100
    for c in checks:
        if c.status in ("issue", "warning"):
            score -= SEVERITY_WEIGHT.get(c.severity, 0)
    return max(0, min(100, score))


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


# ----------------------------------------------------------
# Individual checks. Each returns one CheckResult.
# -------------------------------------------------------------

def _detect_wordpress(session, base_url: str, home_html: str, home_headers: dict) -> bool:
    """Detect WordPress using many weak signals so themed or hardened sites
    are still recognised. Returns True as soon as one solid signal is found."""
    html = (home_html or "").lower()
    html_signals = (
        "/wp-content/", "/wp-includes/", "wp-json", "wp-embed.min.js",
        "wp-emoji", 'content="wordpress', "/wp-content/themes/",
        "/wp-content/plugins/", "wp-block-", "s.w.org", "/wp-json/",
    )
    if any(sig in html for sig in html_signals):
        return True

    # The REST API link is often advertised in a response header even when the
    # HTML is heavily customised or cached.
    link_header = (home_headers.get("link", "") + " " + home_headers.get("x-pingback", "")).lower()
    if "api.w.org" in link_header or "wp-json" in link_header or "xmlrpc.php" in link_header:
        return True

    # The REST API root.
    api = _get(session, urljoin(base_url + "/", "wp-json/"))
    if api is not None and api.status_code in (200, 401, 403):
        body = _text(api).lower()
        if "wp/v2" in body or '"namespace"' in body or "api.w.org" in body or "rest_" in body:
            return True

    # The login page is a very strong WordPress signal.
    login = _get(session, urljoin(base_url + "/", "wp-login.php"))
    if login is not None and login.status_code in (200, 302, 403):
        lb = _text(login).lower()
        if ("user_login" in lb or "wp-submit" in lb or "wordpress" in lb
                or "loginform" in lb or "/wp-content/" in lb):
            return True

    # The readme file confirms a WordPress install on many default setups.
    readme = _get(session, urljoin(base_url + "/", "readme.html"))
    if readme is not None and readme.status_code == 200 and "wordpress" in _text(readme).lower():
        return True

    return False


def _check_https(base_url: str, final_url: str, headers: dict) -> CheckResult:
    cat = _("Transport security")
    uses_https = final_url.lower().startswith("https://")
    hsts = "strict-transport-security" in headers
    if uses_https and hsts:
        return CheckResult(
            "https", _("HTTPS encryption"), cat, "ok", "info",
            _("The site is served over HTTPS and enforces it with HSTS."),
        )
    if uses_https and not hsts:
        return CheckResult(
            "https", _("HTTPS encryption"), cat, "warning", "low",
            _("The site uses HTTPS but does not send a Strict-Transport-Security header, "
              "so a first visit can still be downgraded to plain HTTP."),
            [
                _("Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
                _("On shared hosting you can add this in your .htaccess file inside an "
                  "<IfModule mod_headers.c> block."),
                _("Make sure every page redirects from http:// to https:// permanently (301)."),
            ],
        )
    return CheckResult(
        "https", _("HTTPS encryption"), cat, "issue", "high",
        _("The site does not enforce HTTPS. Visitor data and login passwords can be read on the network."),
        [
            _("Install a free SSL certificate. Most shared hosts offer Let's Encrypt with one click in cPanel."),
            _("Force HTTPS by adding a redirect rule in your .htaccess file."),
            _("In WordPress set both the WordPress Address and Site Address to the https:// version."),
        ],
    )


def _check_security_headers(headers: dict) -> CheckResult:
    cat = _("Browser hardening")
    wanted = {
        "x-frame-options": _("clickjacking protection"),
        "x-content-type-options": _("MIME sniffing protection"),
        "content-security-policy": _("content security policy"),
        "referrer-policy": _("referrer policy"),
    }
    missing = [label for key, label in wanted.items() if key not in headers]
    if not missing:
        return CheckResult(
            "headers", _("Security response headers"), cat, "ok", "info",
            _("All of the recommended browser security headers are present."),
        )
    severity = "medium" if len(missing) >= 3 else "low"
    return CheckResult(
        "headers", _("Security response headers"), cat, "warning", severity,
        _("The following protective headers are missing: %(list)s.") % {"list": ", ".join(missing)},
        [
            _("Add the missing headers in your .htaccess file using mod_headers."),
            _("Recommended values: X-Frame-Options: SAMEORIGIN, X-Content-Type-Options: nosniff, "
              "Referrer-Policy: strict-origin-when-cross-origin."),
            _("A security plugin such as a headers manager can also set these without editing files."),
        ],
    )


def _check_ddos_waf(headers: dict) -> CheckResult:
    cat = _("DDoS and firewall")
    server = (headers.get("server", "") + " " + headers.get("x-powered-by", "")).lower()
    behind_waf = (
        "cf-ray" in headers
        or "x-sucuri-id" in headers
        or "cloudflare" in server
        or "sucuri" in server
        or "stackpath" in server
    )
    if behind_waf:
        return CheckResult(
            "ddos", _("DDoS protection and web firewall"), cat, "ok", "info",
            _("The site appears to sit behind a content delivery network or web application "
              "firewall, which absorbs traffic floods and filters bad requests."),
        )
    return CheckResult(
        "ddos", _("DDoS protection and web firewall"), cat, "warning", "medium",
        _("No content delivery network or web application firewall was detected. On shared "
          "hosting a traffic flood can take the site offline and there is no filtering layer "
          "in front of WordPress."),
        [
            _("Put the site behind a free plan of a content delivery network such as Cloudflare. "
              "It is free and works on shared hosting by only changing your DNS."),
            _("Enable the firewall and bot fight features once the DNS is proxied."),
            _("Turn on rate limiting for the login and XML-RPC endpoints."),
        ],
    )


def _check_version_disclosure(session, base_url: str, home_html: str) -> CheckResult:
    cat = _("Information disclosure")
    version = None
    m = re.search(r'name="generator" content="WordPress ([0-9.]+)"', home_html)
    if m:
        version = m.group(1)
    readme = _get(session, urljoin(base_url + "/", "readme.html"))
    readme_exposed = readme is not None and readme.status_code == 200 and "WordPress" in _text(readme)
    if version or readme_exposed:
        shown = version or _("an unknown version")
        return CheckResult(
            "version", _("WordPress version disclosure"), cat, "warning", "low",
            _("The site reveals its WordPress version (%(v)s). Attackers use the version "
              "number to look up matching exploits.") % {"v": shown},
            [
                _("Remove the version meta tag. Many security plugins do this automatically."),
                _("Delete or block public access to readme.html and license.txt."),
                _("Most important of all: keep WordPress, themes and plugins fully up to date."),
            ],
        )
    return CheckResult(
        "version", _("WordPress version disclosure"), cat, "ok", "info",
        _("The WordPress version is not openly advertised."),
    )


def _check_xmlrpc(session, base_url: str) -> CheckResult:
    cat = _("Brute force and DDoS")
    resp = _get(session, urljoin(base_url + "/", "xmlrpc.php"))
    body = _text(resp)
    enabled = resp is not None and (
        resp.status_code in (200, 405) and "XML-RPC server accepts POST requests only" in body
    )
    if enabled:
        return CheckResult(
            "xmlrpc", _("XML-RPC interface enabled"), cat, "issue", "high",
            _("xmlrpc.php is active. This single file lets an attacker try hundreds of "
              "passwords in one request (system.multicall) and can be abused to attack "
              "other websites (pingback flooding)."),
            [
                _("If you do not use the Jetpack or the mobile app, disable XML-RPC completely "
                  "with a security plugin or by blocking the file in .htaccess."),
                _("To block it, deny access to xmlrpc.php in your .htaccess file."),
                _("If you need it, at least disable pingbacks and add login rate limiting."),
            ],
        )
    return CheckResult(
        "xmlrpc", _("XML-RPC interface"), cat, "ok", "info",
        _("The XML-RPC interface is disabled or blocked."),
    )


def _check_login_exposure(session, base_url: str) -> CheckResult:
    cat = _("Brute force protection")
    resp = _get(session, urljoin(base_url + "/", "wp-login.php"))
    body = _text(resp)
    exposed = resp is not None and resp.status_code == 200 and (
        "user_login" in body or "loginform" in body
    )
    if exposed:
        return CheckResult(
            "login", _("Login page openly reachable"), cat, "warning", "medium",
            _("The default login page wp-login.php is reachable by anyone with no extra "
              "protection in front of it. This is the main door attackers knock on to guess "
              "passwords."),
            [
                _("Install a login security plugin that limits failed attempts and locks out "
                  "repeat offenders."),
                _("Enable two factor authentication for every administrator account."),
                _("Protect the login page with a server password (HTTP basic auth) through "
                  "cPanel directory privacy, or change the login URL."),
                _("Never use the username admin and always use a long unique password."),
            ],
        )
    return CheckResult(
        "login", _("Login page protection"), cat, "ok", "info",
        _("The default login page is not openly reachable or is protected."),
    )


def _check_wp_admin(session, base_url: str) -> CheckResult:
    cat = _("Default URLs")
    # We do not follow redirects so we can see the tell tale redirect to wp-login.
    resp = _get(session, urljoin(base_url + "/", "wp-admin/"), allow_redirects=False)
    if resp is None:
        return CheckResult(
            "wpadmin", _("Default admin URL"), cat, "ok", "info",
            _("The default admin area did not respond."),
        )
    location = resp.headers.get("Location", "")
    reachable = resp.status_code == 200 or (
        resp.status_code in (301, 302, 303) and "wp-login.php" in location
    )
    if reachable:
        return CheckResult(
            "wpadmin", _("Default admin URL reachable"), cat, "warning", "medium",
            _("The default WordPress admin address /wp-admin/ is reachable. Attackers know this "
              "address by heart and point their password guessing tools straight at it."),
            [
                _("Protect the wp-admin folder with an extra server password using cPanel directory privacy."),
                _("If you always connect from the same place, allow only your own IP address to reach "
                  "/wp-admin/ in your .htaccess file."),
                _("Use a security plugin to change the login and admin address to something only you know."),
                _("Always pair this with two factor authentication and a login attempt limiter."),
            ],
        )
    return CheckResult(
        "wpadmin", _("Default admin URL"), cat, "ok", "info",
        _("The default admin address is not openly reachable."),
    )


def _check_default_username(session, base_url: str) -> CheckResult:
    cat = _("Brute force protection")
    common = {
        "admin", "administrator", "root", "test", "user", "wordpress",
        "webmaster", "support", "demo", "editor", "manager",
    }
    found = set()

    # Read usernames from the public REST API when it is open.
    api = _get(session, urljoin(base_url + "/", "wp-json/wp/v2/users"))
    if api is not None and api.status_code == 200:
        try:
            data = json.loads(_text(api))
            if isinstance(data, list):
                for u in data:
                    for key in ("slug", "name"):
                        value = str(u.get(key, "")).strip().lower()
                        if value in common:
                            found.add(value)
        except (ValueError, TypeError, AttributeError):
            pass

    # Read the username revealed by the author archive redirect.
    author = _get(session, base_url + "/?author=1", allow_redirects=True)
    if author is not None and "/author/" in author.url:
        name = author.url.rstrip("/").split("/author/")[-1].split("/")[0].lower()
        if name in common:
            found.add(name)

    if found:
        return CheckResult(
            "defaultuser", _("Default or common admin username"), cat, "issue", "high",
            _("The site uses a well known username (%(list)s). Half of a brute force attack is "
              "already solved when the username is easy to guess.") % {"list": ", ".join(sorted(found))},
            [
                _("Create a brand new administrator account with a unique username that is not a real word."),
                _("Log in with the new account, then delete the old default account and reassign its "
                  "content to the new one."),
                _("Never use admin, administrator or your domain name as a login name."),
                _("Add two factor authentication and a plugin that limits failed login attempts."),
            ],
        )
    return CheckResult(
        "defaultuser", _("Default username check"), cat, "ok", "info",
        _("No common default usernames were visible from public data."),
    )


def _check_user_enumeration(session, base_url: str) -> CheckResult:
    cat = _("Information disclosure")
    api = _get(session, urljoin(base_url + "/", "wp-json/wp/v2/users"))
    api_leak = api is not None and api.status_code == 200 and '"slug"' in _text(api)
    author = _get(session, base_url + "/?author=1", allow_redirects=True)
    author_leak = author is not None and "/author/" in author.url
    if api_leak or author_leak:
        return CheckResult(
            "userenum", _("Username enumeration possible"), cat, "warning", "medium",
            _("The list of author usernames can be read through the REST API or the author "
              "page redirect. Knowing real usernames makes password guessing much easier."),
            [
                _("Block the wp-json/wp/v2/users endpoint for visitors who are not logged in. "
                  "Many security plugins offer a single switch for this."),
                _("Stop the ?author= redirect so it no longer reveals the login name."),
                _("Use display names that are different from the login names."),
            ],
        )
    return CheckResult(
        "userenum", _("Username enumeration"), cat, "ok", "info",
        _("Author usernames are not exposed through the common channels."),
    )


def _check_directory_listing(session, base_url: str) -> CheckResult:
    cat = _("Information disclosure")
    resp = _get(session, urljoin(base_url + "/", "wp-content/uploads/"))
    listing = resp is not None and resp.status_code == 200 and "Index of" in _text(resp)
    if listing:
        return CheckResult(
            "dirlisting", _("Directory listing enabled"), cat, "warning", "low",
            _("The uploads folder shows a public file index. Visitors can browse every "
              "uploaded file, including files you did not link anywhere."),
            [
                _("Disable directory browsing by adding Options -Indexes to your .htaccess file."),
                _("Place an empty index.html file inside folders that should not be browsed."),
            ],
        )
    return CheckResult(
        "dirlisting", _("Directory listing"), cat, "ok", "info",
        _("Directory browsing is turned off."),
    )


def _check_debug_log(session, base_url: str) -> CheckResult:
    cat = _("Information disclosure")
    resp = _get(session, urljoin(base_url + "/", "wp-content/debug.log"))
    exposed = resp is not None and resp.status_code == 200 and len(resp.content) > 0 and (
        "PHP" in _text(resp) or "[" in _text(resp)
    )
    if exposed:
        return CheckResult(
            "debuglog", _("Public debug log file"), cat, "issue", "high",
            _("A public debug.log file was found. These files often leak server paths, "
              "database errors and sometimes secrets."),
            [
                _("Turn off WP_DEBUG_LOG on the live site by editing wp-config.php."),
                _("Delete the existing wp-content/debug.log file."),
                _("Block access to any .log file in your .htaccess."),
            ],
        )
    return CheckResult(
        "debuglog", _("Debug log exposure"), cat, "ok", "info",
        _("No public debug log file was found."),
    )


def _check_default_files(session, base_url: str) -> CheckResult:
    cat = _("Default files")
    found = []
    for path, label in (("license.txt", "license.txt"), ("wp-config-sample.php", "wp-config-sample.php")):
        resp = _get(session, urljoin(base_url + "/", path))
        if resp is not None and resp.status_code == 200 and len(resp.content) > 0:
            found.append(label)
    if found:
        return CheckResult(
            "defaultfiles", _("Default WordPress files present"), cat, "warning", "low",
            _("Default install files are still reachable: %(list)s. They are harmless on their "
              "own but they confirm the site runs WordPress and can hint at the version.")
            % {"list": ", ".join(found)},
            [
                _("Delete files you do not need, such as license.txt and readme.html."),
                _("Block public access to wp-config-sample.php and other sample files."),
            ],
        )
    return CheckResult(
        "defaultfiles", _("Default WordPress files"), cat, "ok", "info",
        _("No unnecessary default files were exposed."),
    )
