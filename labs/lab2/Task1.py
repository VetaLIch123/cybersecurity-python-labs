from __future__ import annotations
import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

PBKDF2_ITERATIONS = 310_000
PASSWORD_SALT_BYTES = 16
SESSION_TIMEOUT_SEC = 900
EMAIL_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,63}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


class User:
    def __init__(
        self,
        username: str,
        email: str,
        role: str = "user",
        active: bool = True,
        password: str | None = None,
    ) -> None:
        self.username = username
        self._email = ""
        self.email = email
        self.role = role
        self.active = active
        self.__password_hash: bytes | None = None
        self.__password_salt: bytes | None = None
        if password is not None:
            self.set_password(password)

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str) or not EMAIL_PATTERN.fullmatch(value):
            raise ValueError("Email має відповідати заданому формату.")
        self._email = value

    def set_password(self, password: str) -> None:
        if not isinstance(password, str) or not password:
            raise ValueError("Пароль має бути непорожнім рядком.")
        self.__password_salt = os.urandom(PASSWORD_SALT_BYTES)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )

    def check_password(self, password: str) -> bool:
        if self.__password_hash is None or self.__password_salt is None:
            return False
        if not isinstance(password, str):
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(self.__password_hash, candidate)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        return f"User(username={self.username!r}, email={self.email!r}, role={self.role!r}, active={self.active})"


class Admin(User):

    def __init__(
        self,
        username: str,
        email: str,
        permissions: set[str] | None = None,
        password: str | None = None,
        active: bool = True,
    ) -> None:
        super().__init__(username, email, role="admin", active=active, password=password)
        self.permissions = set() if permissions is None else set(permissions)

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        return f"{super().__str__()}, permissions={sorted(self.permissions)!r}"

class Session:

    def __init__(self, ip: str) -> None:
        self.ip = ip
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time

    def touch(self) -> None:
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("timeout_sec має бути додатним.")
        elapsed = datetime.now(timezone.utc) - self.last_activity
        return elapsed < timedelta(seconds=timeout_sec)


@dataclass
class AuditRecord:
    timestamp: datetime
    username: str
    action: str

class AuditLog:

    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def add_log(self, username: str, action: str) -> None:
        self.records.append(AuditRecord(datetime.now(timezone.utc), username, action))

    def show_all(self) -> None:
        if not self.records:
            print("Журнал аудиту порожній.")
            return
        for record in self.records:
            print(f"{record.timestamp.isoformat()} | {record.username} | {record.action}")


class UserAccount:

    _ALLOWED_ITEMS = {"user", "session", "audit_log"}

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        if not isinstance(user, User):
            raise TypeError("user має бути екземпляром User або його підкласу.")
        self.user = user
        self.session = session
        self.audit_log = AuditLog() if audit_log is None else audit_log

    def login(self, username: str, password: str, ip: str) -> bool:
        success = (
            username == self.user.username
            and self.user.active
            and self.user.check_password(password)
        )
        if not success:
            self.audit_log.add_log(self.user.username, "login_failure")
            return False
        self.session = Session(ip)
        self.session.touch()
        self.audit_log.add_log(self.user.username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        return self.session is not None and self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        if self.session is not None:
            self.session = None
            self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key: str) -> User | Session | AuditLog | None:
        if not isinstance(key, str) or key not in self._ALLOWED_ITEMS:
            raise KeyError(key)
        return getattr(self, key)

    def __setitem__(self, key: str, value: User | Session | AuditLog | None) -> None:
        expected_types = {"user": User, "session": Session, "audit_log": AuditLog}
        if not isinstance(key, str) or key not in expected_types:
            raise KeyError(key)
        if value is None and key == "session":
            self.session = None
        elif not isinstance(value, expected_types[key]):
            raise TypeError(f"Значення для {key!r} має бути типу {expected_types[key].__name__}.")
        else:
            setattr(self, key, value)
