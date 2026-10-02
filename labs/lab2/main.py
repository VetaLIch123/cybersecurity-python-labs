"""Демонстрація Завдання 1 лабораторної роботи №2."""

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from labs.lab2.Task1 import SESSION_TIMEOUT_SEC, Admin, User, UserAccount


def run_task1_demo() -> None:
    user = User("vitalik", "vitalik@example.com", password="demo-password")
    account = UserAccount(user)

    print("Успішний вхід:", account.login("vitalik", "demo-password", "192.0.2.10"))
    print("Перевірка автентифікації:", account.is_authenticated())

    # Невдалий вхід фіксується, але не оновлює час останньої активності.
    print("Невдалий вхід:", account.login("vitalik", "wrong-password", "192.0.2.10"))

    try:
        user.email = "invalid-email"
    except ValueError as error:
        print("Email не прийнято:", error)
    user.email = "vitalik_new@example.com"
    print("Оновлений email:", user.email)

    admin = Admin("admin", "admin@example.com", password="admin-password")
    admin.grant_permission("manage_users")
    print("Адміністратор має manage_users:", admin.has_permission("manage_users"))
    print(admin)

    account.session.last_activity = datetime.now(timezone.utc) - timedelta(
        seconds=SESSION_TIMEOUT_SEC + 1
    )
    print("Автентифікація після таймауту:", account.is_authenticated())
    account.logout()

    print("\nЗаписи аудиту:")
    account.audit_log.show_all()


def main() -> None:
    parser = argparse.ArgumentParser(description="Інструменти лабораторної роботи №2")
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("demo", help="демонстрація Завдання 1")

    analyze_parser = commands.add_parser("analyze", help="аналіз auth.log (Завдання 2)")
    analyze_parser.add_argument(
        "--auth-log",
        type=Path,
        default=PROJECT_ROOT / "labs" / "lab2" / "data" / "data_v04" / "auth.log",
        help="шлях до журналу автентифікації",
    )
    analyze_parser.add_argument("--threshold", type=int, default=5)
    analyze_parser.add_argument("--window-min", type=int, default=5)
    analyze_parser.add_argument("--output-json", type=Path, help="шлях до JSON-звіту")

    args = parser.parse_args()
    if args.command is None:
        run_task1_demo()
        print("\n" + "=" * 60)
        print("Автоматичний запуск Завдання 2 з auth.log")
        from labs.lab2.Task2 import run_task2

        run_task2(
            auth_log=PROJECT_ROOT / "labs" / "lab2" / "data" / "data_v04" / "auth.log",
            threshold=5,
            window_min=5,
        )
    elif args.command == "demo":
        run_task1_demo()
    elif args.command == "analyze":
        try:
            from labs.lab2.Task2 import run_task2
        except ImportError:
            parser.error("Точка входу Task2.run_task2 ще не реалізована.")
        run_task2(
            auth_log=args.auth_log,
            threshold=args.threshold,
            window_min=args.window_min,
            output_json=args.output_json,
        )


if __name__ == "__main__":
    main()
