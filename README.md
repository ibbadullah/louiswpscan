# Louis WP Scan

A free, non-profit WordPress security scanner. It checks a public WordPress site for twelve common misconfigurations and returns a plain-language fix guide, not just a list of findings.

Live at **[louiswpscan.org](https://louiswpscan.org)**.

---

## Why this exists

I built the first version of this after my own WordPress site was compromised.

Wanting to know how common the problem was, I wrote a script that checked live WordPress sites for weak configuration and reported what I found to the site owners. Most of them could not act on it. They were shop owners, bloggers and small charities, not security practitioners, and a list of vulnerabilities meant nothing to them.

So the tool stopped producing reports and started producing instructions. Every finding carries steps written for someone with a cPanel login and no security background. That is why fix advice mentions `.htaccess` and cPanel directory privacy rather than SSH.

It is free, it has no account, and it will stay that way.

---

## What it checks

Twelve checks. Each returns a status (`ok`, `warning`, `issue` or `info`), a severity, a plain-language finding and, where relevant, concrete fix steps.

| Check | Category | Severity when found |
|---|---|---|
| HTTPS not enforced | Transport security | high |
| HTTPS without HSTS | Transport security | low |
| Missing security headers | Browser hardening | medium if 3+ missing, else low |
| No CDN or web application firewall | DDoS and firewall | medium |
| WordPress version disclosed | Information disclosure | low |
| `xmlrpc.php` enabled | Brute force and DDoS | high |
| `wp-login.php` openly reachable | Brute force protection | medium |
| `/wp-admin/` reachable | Default URLs | medium |
| Default or common admin username | Brute force protection | high |
| Username enumeration possible | Information disclosure | medium |
| Directory listing on uploads | Information disclosure | low |
| Public `debug.log` | Information disclosure | high |
| Default install files present | Default files | low |

Some specifics, since the details matter more than the labels:

- **Security headers** checked are `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy` and `Referrer-Policy`.
- **Firewall detection** looks for a `cf-ray` or `x-sucuri-id` header, or Cloudflare, Sucuri or StackPath in the `Server` or `X-Powered-By` header.
- **Version disclosure** reads the `generator` meta tag and checks whether `readme.html` is publicly readable.
- **Username enumeration** checks the `wp-json/wp/v2/users` endpoint and whether `/?author=1` redirects to a readable author slug.
- **Default username** checks those same two sources against a list of eleven common names including `admin`, `administrator`, `root` and `wordpress`.
- **Directory listing** checks `wp-content/uploads/` for an `Index of` page.
- **Debug log** checks `wp-content/debug.log`.
- **Default files** checks `license.txt` and `wp-config-sample.php`.

### WordPress detection

Before scanning, the tool confirms the site is WordPress using several weak signals rather than one: markers in the HTML such as `/wp-content/`, `wp-json` and `wp-block-`; the `Link` and `X-Pingback` response headers; the REST API root at `wp-json/`; the login page; and `readme.html`. One solid signal is enough. This is deliberate, so heavily customised or cached sites are still recognised.

### Scoring

A site starts at 100 and loses points per finding: high 22, medium 11, low 5, info 0. The result maps to a grade.

| Score | Grade |
|---|---|
| 90 and above | A |
| 75 to 89 | B |
| 60 to 74 | C |
| 40 to 59 | D |
| below 40 | F |

The score is a summary of these twelve checks, not a security guarantee. An A means nothing here was found, not that the site is safe.

---

## What it does not do

The scanner sends ordinary HTTP GET requests to public URLs that any browser would request. It does not:

- attempt to log in, guess passwords, or brute force anything
- send payloads, injections or exploit attempts
- perform load, stress or denial of service testing
- read more than 200 KB from any single response
- use any paid third-party API

Requests identify themselves:

```
User-Agent: LouisWPScan/1.0 (+https://louiswpscan.org; non-profit WordPress security scanner)
```

Timeouts are capped at 8 seconds and redirects at 5, so a slow or hostile target cannot tie up a worker.

**Only scan sites you own or have permission to test.**

---

## What it stores

A completed scan records the URL, the domain, the date, whether the site is WordPress, whether it was reachable, the score and grade, issue counts by severity, and a compact list of finding IDs with their severity and status.

It does not store page contents, response headers, or any personal data about the site owner. This is stated in the model docstring and enforced by the model fields themselves.

---

## Tech stack

- **Django 5.2.7**
- `requests` for all scanning; no external scanning service
- `django-environ` for configuration
- `whitenoise` for static files
- `django-jazzmin` for the admin interface
- `mysqlclient` available for MySQL; the repository ships configured for SQLite
- Internationalised via `gettext`, with a French translation included

Two apps. `publicapp` holds the scanner engine, the public pages and the scan records. `adminapp` holds the dashboard.

The engine is a single module at `publicapp/scanner.py`, about 580 lines. Its only Django dependency is the translation helper, so it can be read, tested or reused largely on its own.

---

## Running it locally

```bash
git clone https://github.com/ibbadullah/louiswpscan.git
cd louiswpscan

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env
# edit .env and set SECRET_KEY

python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Open http://127.0.0.1:8000.

To generate a secret key:

```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

### Configuration

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Django secret key. Required. |
| `DEBUG` | `True` locally, `False` in production. |
| `ALLOWED_HOSTS` | Comma-separated hostnames. |
| `CSRF_TRUSTED_ORIGINS` | Comma-separated origins. |
| `GOOGLE_ANALYTICS_ID` | Optional. |

Never commit a real `.env` file.

---

## Using the scanner on its own

```python
from publicapp.scanner import scan_site

result = scan_site("example.com")

print(result["score"], result["grade"])

for check in result["checks"]:
    if check["status"] in ("issue", "warning"):
        print(f"[{check['severity']}] {check['title']}")
        print(check["finding"])
        for step in check["fix"]:
            print("  -", step)
```

`scan_site` returns a dictionary with `url`, `reachable`, `is_wordpress`, `score`, `grade`, `counts` and `checks`. That dictionary is the single source of truth used by the view, the template and the stored record.

---

## Contributing

Adding a check means writing one function that returns a `CheckResult` and registering it in `scan_site`. The rules:

- Only ordinary GET requests to public URLs.
- Every finding needs fix steps someone without security training can follow.
- Fix steps should assume cPanel or the WordPress dashboard, not SSH.
- All user-facing strings go through `gettext` so they can be translated.

Issues and pull requests are welcome.

---

## Reporting a vulnerability

If you find a security problem in this project, please open an issue without exploit details and I will follow up privately.

---

## Licence

MIT. See [LICENSE](LICENSE).

---

## Author

**Ibbad Ullah** — [github.com/ibbadullah](https://github.com/ibbadullah)
