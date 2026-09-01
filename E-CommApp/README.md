# VulnShop - Intentionally Vulnerable Django E-Commerce Site

**This application is deliberately insecure.** It exists as a local training/CTF
target for practicing vulnerability discovery and exploitation (web app +
API), in the spirit of DVWA / OWASP Juice Shop, but for Django.

> ⚠️ **Do not deploy this anywhere reachable from the internet or an
> untrusted network.** Run it only on `localhost` / an isolated VM. Do not
> reuse any code, pattern, or setting from this project in a real
> application — every file contains at least one deliberate bug.

## Setup

```powershell
cd vulnerable-ecommerce-django
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python manage.py makemigrations shop
python manage.py migrate
python manage.py seed_demo_data
python manage.py runserver
```

Then open http://127.0.0.1:8000/.

- Default seeded admin account: `admin` / `admin123` (VULN #27).
- Register a normal account at `/register/` to explore the customer-facing bugs.

## Vulnerability catalog (38 total)

Each item below is tagged with its OWASP Top 10 (2021) or OWASP API
Security Top 10 (2023) category, the file/function where it lives, and a
one-line reproduction hint. Search the codebase for `VULNERABILITY #<n>` to
jump straight to the code.

### Web application

| # | Vulnerability | OWASP | Location | Try it |
|---|---|---|---|---|
| 1 | SQL Injection - product search | A03 Injection | `shop/views.py:search` | `/search/?q=' UNION SELECT id,username,password,1 FROM auth_user --` |
| 2 | SQL Injection - login bypass | A03 Injection | `shop/views.py:login_view` | username `admin' --`, any password |
| 3 | Reflected XSS | A03 Injection | `shop/templates/shop/search_results.html` | `/search/?q=<script>alert(document.cookie)</script>` |
| 4 | Stored XSS - product reviews | A03 Injection | `shop/templates/shop/product_detail.html` | post a review containing `<script>` |
| 5 | Insecure crypto storage - MD5 passwords, no salt | A02 Cryptographic Failures | `shop/views.py:register/login_view` | inspect `auth_user.password` in DB |
| 6 | Predictable API key (sequential) | A02 Cryptographic Failures | `shop/views.py:register` | register two accounts, compare `api_key` |
| 7 | IDOR - read/edit any user profile | A01 Broken Access Control | `shop/views.py:profile_view` | `/profile/2/`, `/profile/3/`, ... |
| 8 | IDOR - read any order | A01 Broken Access Control | `shop/views.py:order_detail` | `/orders/1/`, `/orders/2/`, ... |
| 9 | CSRF on checkout | A01 Broken Access Control | `shop/views.py:checkout` (`@csrf_exempt`) | auto-submitting HTML form from another origin |
| 10 | Client-controlled price/total | A04 Insecure Design | `shop/views.py:checkout` | tamper `total` hidden field before submit |
| 11 | Insecure deserialization - pickled cart cookie | A08 Software/Data Integrity Failures | `shop/cart.py` | craft a malicious pickle in the `cart_data` cookie |
| 12 | Unrestricted file upload | A04 Insecure Design | `shop/views.py:upload_avatar` | upload `.html`/`.svg`/any extension |
| 13 | Path traversal via upload filename | A01 Broken Access Control | `shop/views.py:upload_avatar` | filename `../../../vulnshop/settings.py` |
| 14 | Path traversal / arbitrary file read | A01 Broken Access Control | `shop/views.py:download_file` | `/files/download/?file=../../vulnshop/settings.py` |
| 15 | OS command injection | A03 Injection | `shop/views.py:track_shipment` | host `127.0.0.1 & whoami` |
| 16 | Server-Side Template Injection | A03 Injection | `shop/views.py:email_preview` | `{% for c in user.get_all_permissions %}{{ c }}{% endfor %}` |
| 17 | RCE via `eval()` | A03 Injection | `shop/views.py:apply_coupon` | formula `__import__('os').popen('whoami').read()` |
| 18 | XXE (XML External Entity) | A05 Security Misconfiguration | `shop/views.py:import_products_xml` | DOCTYPE with a `SYSTEM "file://..."` entity |
| 19 | SSRF | A10 SSRF | `shop/views.py:import_image_url` | `image_url=http://169.254.169.254/latest/meta-data/` |
| 20 | Broken password reset - weak/predictable token, no expiry | A07 Auth Failures | `shop/views.py:password_reset_request/confirm` | brute-force the 6-digit token |
| 21 | Host header injection in reset link | A05 Security Misconfiguration | `shop/views.py:password_reset_request` | send a forged `Host` header |
| 22 | Open redirect | A01 Broken Access Control | `shop/views.py:login_view` | `?next=https://evil.example/phish` |
| 23 | Security misconfiguration - `DEBUG=True`, hardcoded weak `SECRET_KEY`, `ALLOWED_HOSTS=['*']` | A05 Security Misconfiguration | `vulnshop/settings.py` | trigger any 500 error to see the debug page |
| 24 | Missing security headers - no clickjacking protection | A05 Security Misconfiguration | `vulnshop/settings.py` (X-Frame-Options middleware removed) | frame any page in an `<iframe>` |
| 25 | Insecure cookies - `HttpOnly`/`Secure` disabled | A05 Security Misconfiguration | `vulnshop/settings.py` | read `document.cookie` from injected JS |
| 26 | CORS misconfiguration - reflects Origin + `Allow-Credentials: true` | A05 Security Misconfiguration | `vulnshop/middleware.py` | cross-origin `fetch(..., {credentials:'include'})` |
| 27 | Hardcoded default admin credentials | A07 Auth Failures | `shop/management/commands/seed_demo_data.py` | `admin` / `admin123` |
| 28 | Sensitive data stored in plaintext (credit card number) | A02 Cryptographic Failures | `shop/models.py:UserProfile.credit_card_number` | view any profile page |

### API (`/api/...`)

| # | Vulnerability | OWASP API Top 10 | Location | Try it |
|---|---|---|---|---|
| 29 | BOLA - read any user | API1 Broken Object Level Authorization | `api/views.py:api_get_user` | `GET /api/users/2/` |
| 30 | BOLA - read any order | API1 Broken Object Level Authorization | `api/views.py:api_get_order` | `GET /api/orders/1/` |
| 31 | Mass assignment / privilege escalation | API3 Broken Object Property Level Authorization | `api/views.py:api_update_user` | `PATCH /api/users/2/update/ {"is_staff": true, "is_superuser": true}` |
| 32 | Broken function-level authorization - unauthenticated product creation | API5 Broken Function Level Authorization | `api/views.py:api_create_product` | `POST /api/products/` with no auth at all |
| 33 | Broken function-level authorization - client-controlled admin flag | API5 Broken Function Level Authorization | `api/views.py:api_admin_stats` | `GET /api/admin/stats/?is_admin=true` |
| 34 | Excessive data exposure | API3 Broken Object Property Level Authorization | `api/views.py:_user_dict` | any endpoint returning a user object leaks `password_hash`, `credit_card_number` |
| 35 | SQL Injection | Injection (API8 Security Misconfiguration family) | `api/views.py:api_search_products` | `GET /api/products/search/?q=' OR '1'='1` |
| 36 | Unrestricted resource consumption - unbounded `limit` param | API4 Unrestricted Resource Consumption | `api/views.py:api_search_products` | `?limit=999999999` or `?limit=1);DROP TABLE...` |
| 37 | Broken authentication - no rate limiting on login | API2 Broken Authentication | `api/views.py:api_login` | scripted brute force against `/api/login/` |
| 38 | Sensitive data exposure via debug endpoint | API8 Security Misconfiguration | `api/views.py:api_debug_info` | `GET /api/debug/` leaks `SECRET_KEY` |

## Suggested exercises

1. Chain #2 (SQLi login bypass) or #31 (mass assignment) to obtain admin access.
2. Chain #14 (path traversal) to read `vulnshop/settings.py` and recover `SECRET_KEY`.
3. Use #11 (pickle cart) to get local code execution, then use that shell to read the DB directly.
4. Use #19 (SSRF) to reach an internal-only service or a mock metadata endpoint you stand up alongside this app.
5. Fix each bug and write a regression test proving the fix (e.g. parameterized queries, `set_password()`, ownership checks, an allow-list for uploads, a proper serializer for the API).

## Ethical use

Use this project only against your own local instance for learning,
teaching, or authorized security testing/training. Do not point automated
scanners or exploit traffic at anyone else's infrastructure using code
copied from here.
