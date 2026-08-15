"""
Minimal Django settings for running SessionArmor tests.
"""

SECRET_KEY = "test-secret-key-not-for-production"

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
]

SESSION_ENGINE = "django.contrib.sessions.backends.db"

# SessionArmor defaults
SESSION_ARMOR_ABSOLUTE_TIMEOUT = 28800
SESSION_ARMOR_IDLE_TIMEOUT = 1800
SESSION_ARMOR_BIND_IP = True
SESSION_ARMOR_BIND_USER_AGENT = True
SESSION_ARMOR_DETECT_CLAIM_DRIFT = True
SESSION_ARMOR_REQUIRE_BINDING = True
SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 0
SESSION_ARMOR_TRUSTED_PROXY_CIDRS = ()
SESSION_ARMOR_AUDIT_PEPPER = "test-audit-pepper-long-enough"

LOGIN_URL = "/login/"

ROOT_URLCONF = "tests.urls"
