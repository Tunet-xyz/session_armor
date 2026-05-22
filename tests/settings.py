"""
Minimal Django settings for running SessionArmor tests.
"""

SECRET_KEY = 'test-secret-key-not-for-production'

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.sessions',
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

MIDDLEWARE = [
    'django.contrib.sessions.middleware.SessionMiddleware',
]

SESSION_ENGINE = 'django.contrib.sessions.backends.db'

# SessionArmor defaults
SESSION_ABSOLUTE_TIMEOUT = 28800
SESSION_IDLE_TIMEOUT = 1800
SESSION_BIND_IP = True
SESSION_BIND_USER_AGENT = True
SESSION_DETECT_CLAIM_DRIFT = True
SESSION_ARMOR_TRUSTED_PROXY_DEPTH = 1

LOGIN_URL = '/login/'

ROOT_URLCONF = 'tests.urls'
