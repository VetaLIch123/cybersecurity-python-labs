"""Налаштування індивідуального варіанта 4."""

VARIANT_NUMBER = 4
DOMAIN_NAME = "Облік подій автентифікації"
RECORD_TITLE = "Інтервал автентифікації"
VALUE_UNIT = "events"
VALUE_LABEL = "кількість подій"
THRESHOLD = 20
VALUE_MIN = 0
VALUE_MAX = None
CATEGORIES = ("failed_login", "blocked_account", "mfa_failure")
STATUSES = ("new", "in_progress", "done")
