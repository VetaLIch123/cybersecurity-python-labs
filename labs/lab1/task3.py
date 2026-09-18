import csv
from datetime import datetime
from functools import wraps
import hashlib
import json
import os
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER
MIN_LENGTH = 14
SALT = str(VARIANT_NUMBER).zfill(5)
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_FILE = os.path.join(DATA_DIR, "users.csv")
LOG_FILE = os.path.join(DATA_DIR, "log.json")

class ValidationError(Exception):
    pass

def generate_hash(password: str, salt: str = "00000") -> str:
    if not password:
        raise ValueError("Password cannot be empty")
    if not salt:
        raise ValueError("Salt cannot be empty")
    if len(password) < MIN_LENGTH:
        raise ValidationError(
            f"Password must contain at least {MIN_LENGTH} characters"
        )
    password_with_salt = password + salt
    hash_object = hashlib.sha512(password_with_salt.encode("utf-8"))
    return hash_object.hexdigest()
users_to_register = (
    ("admin", "AdminSecurePass123!"),
    ("ivan", "IvanSecurePass123!"),
    ("petro", "PetroStrongPass456@"),
    ("olena", "OlenaSecurePass789#"),
    ("andriy", "AndriyStrong123$"),
    ("maria", "MariaSecurePass456!"),
    ("oleh", "OlehStrongPassword1@"),
    ("anna", "AnnaSecurePassword2#"),
    ("max", "MaxStrongPass1234!"),
    ("guest", "GuestSecurePass99$"),
)

def create_user(username: str, password: str) -> tuple[str, str]:
    hash_value = generate_hash(password, SALT)
    return username, hash_value

def create_users(users_list: tuple[tuple[str, str], ...]) -> None:
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(USERS_FILE, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            for username, password in users_list:
                user = create_user(username, password)
                writer.writerow(user)
    except (
        OSError,
        FileNotFoundError,
        PermissionError,
        ValidationError,
        ValueError,
    ) as error:
        print(f"Error while creating users database: {error}")

def read_users() -> list[tuple[str, str]]:
    users_db = []
    try:
        with open(USERS_FILE, "r", newline="", encoding="utf-8") as file:
            reader = csv.reader(file)
            for row in reader:
                if len(row) == 2:
                    users_db.append((row[0], row[1]))
    except (OSError, FileNotFoundError, PermissionError, ValueError) as error:
        print(f"Error while reading users database: {error}")
    return users_db

def print_users_db(users_db: list[tuple[str, str]]) -> None:
    print("\nUsers database:")
    print("-" * 85)
    print(f"{'Username':<20}{'SHA-512 hash'}")
    print("-" * 85)
    for username, password_hash in users_db:
        print(f"{username:<20}{password_hash}")
    print("-" * 85)

def log_event(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        result = "failure"
        try:
            result_value = func(*args, **kwargs)
            if result_value is True:
                result = "success"
            return result_value
        except Exception:
            result = "failure"
            raise
        finally:
            try:
                os.makedirs(DATA_DIR, exist_ok=True)
                username = args[0] if len(args) > 0 else kwargs.get("username", "")
                event = {
                    "event": "login",
                    "user": username,
                    "result": result,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "args": list(args),
                    "kwargs": kwargs,
                }
                log_data = []
                if os.path.exists(LOG_FILE):
                    with open(LOG_FILE, "r", encoding="utf-8") as file:
                        try:
                            log_data = json.load(file)
                            if not isinstance(log_data, list):
                                log_data = []
                        except json.JSONDecodeError:
                            log_data = []
                log_data.append(event)
                with open(LOG_FILE, "w", encoding="utf-8") as file:
                    json.dump(log_data, file, indent=4, ensure_ascii=False)
            except (
                OSError,
                FileNotFoundError,
                PermissionError,
                ValueError,
            ) as error:
                print(f"Error while writing log: {error}")
    return wrapper

@log_event
def login(username: str, password: str) -> bool:
    try:
        if not username:
            raise ValueError("Username cannot be empty")
        if not password:
            raise ValueError("Password cannot be empty")
        users_db = read_users()
        for saved_username, saved_hash in users_db:
            if saved_username == username:
                entered_hash = generate_hash(password, SALT)
                return entered_hash == saved_hash
        return False
    except (
        OSError,
        FileNotFoundError,
        PermissionError,
        ValidationError,
        ValueError,
    ) as error:
        print(f"Login error: {error}")
        return False

def run_task3():
    """Виконує повний цикл Завдання 3 для імпорту в main.py."""
    print("Secure User Authentication System")
    print("=" * 50)
    print(f"Student: {STUDENT_NAME}")
    print(f"Group: {GROUP_NAME}")
    print(f"Variant: {VARIANT_NUMBER}")
    print("Hash algorithm: SHA-512")
    print(f"Minimum password length: {MIN_LENGTH}")
    print(f"Personal salt: {SALT}")
    print("=" * 50)
    create_users(users_to_register)
    users_db = read_users()
    print_users_db(users_db)
    print("\nAuthentication tests:")
    print("-" * 50)
    try:
        result = login("admin", "AdminSecurePass123!")
        print(f"admin -> {result}")
        result = login("ivan", "WrongPassword123!")
        print(f"ivan -> {result}")
        result = login("petro", "PetroStrongPass456@")
        print(f"petro -> {result}")
    except (
        OSError,
        FileNotFoundError,
        PermissionError,
        ValidationError,
        ValueError,
    ) as error:
        print(f"Authentication error: {error}")
if __name__ == "__main__":
    run_task3()