"""
Django settings for the VulnShop training application.

*** THIS PROJECT IS INTENTIONALLY INSECURE. ***
It exists to teach and test web/API vulnerability discovery and exploitation
in a safe, disposable, local sandbox. Do NOT deploy this anywhere reachable
by untrusted networks, and do NOT reuse any code, settings, or patterns from
this project in a real application. See README.md for the full vulnerability
catalog.
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# VULNERABILITY #23 - Security Misconfiguration (OWASP A05:2021)
# Hardcoded, weak, publicly-visible SECRET_KEY committed to source control.
# In a real app this key signs sessions/CSRF tokens; leaking it allows
# session/cookie forgery.
# ---------------------------------------------------------------------------
SECRET_KEY = "django-insecure-vulnshop-demo-secret-key-2026-do-not-use-in-prod"

# VULNERABILITY #23 (cont.) - DEBUG left on, leaking stack traces, source
# snippets, settings values, and installed package versions to any visitor
# who triggers a 500 error.
DEBUG = True

# VULNERABILITY #23 (cont.) - Wildcard ALLOWED_HOSTS accepts any Host header,
# enabling Host header injection (see password-reset flow) and cache
# poisoning style attacks.
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "shop",
    "api",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    # VULNERABILITY #24 - django.middleware.clickjacking.XFrameOptionsMiddleware
    # has been deliberately OMITTED, so every page can be framed by another
    # site (clickjacking).
    "vulnshop.middleware.InsecureCorsMiddleware",
]

ROOT_URLCONF = "vulnshop.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "shop.context_processors.cart_context",
            ],
        },
    },
]

WSGI_APPLICATION = "vulnshop.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

AUTH_PASSWORD_VALIDATORS = []  # VULNERABILITY #? - no password strength rules (weak passwords accepted)

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "home"

# ---------------------------------------------------------------------------
# VULNERABILITY #25 - Insecure session/cookie configuration.
# HttpOnly disabled means JavaScript (e.g. injected via one of the XSS bugs
# in this app) can read the session/CSRF cookies directly; Secure=False
# means cookies are sent over plain HTTP too.
# ---------------------------------------------------------------------------
SESSION_COOKIE_HTTPONLY = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SECURE = False

# VULNERABILITY - hardcoded "third-party" API secret, as if copy-pasted from
# a real integration and committed to source control. (Deliberately not
# formatted like a real provider's key prefix - this is a fake demo value,
# not a live credential - so it illustrates the bug without tripping
# secret-scanning tools looking for actual leaked keys.)
PAYMENT_GATEWAY_API_SECRET = "DEMO-HARDCODED-PAYMENT-SECRET-NOT-A-REAL-KEY-1234567890"
