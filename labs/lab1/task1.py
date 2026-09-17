import os
import random
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def run_task1():
    passwords = ["Security@2023", "pass", "MyStr0ng#Key", "root", "Advanc3d@Pass",
                 "user", "Protec7!Pass", "1234", "Elite@Secur1ty", "admin123"]
    criteria = {"min_length": 7, "require_digits": True, "require_upper": True,
                "require_special": True}
    forbidden_passwords = {"pass", "root", "user", "1234", "admin123", "password"}
    random_indexes = [random.randint(0, len(passwords) - 1) for _ in range(3)]
    for index in random_indexes:
        passwords.append(passwords[index])
    def analyze_password(password: str) -> str:
        length_ok = len(password) >= criteria["min_length"]
        has_digit = any(char.isdigit() for char in password)
        has_upper = any(char.isupper() for char in password)
        has_special = any(not char.isalnum() for char in password)
        if password in forbidden_passwords or not length_ok:
            return "Заборонений"
        criteria_count = sum([has_digit, has_upper, has_special])
        if criteria_count == 0:
            return "Слабкий"
        if criteria_count < 3:
            return "Середній"
        if len(password) < criteria["min_length"] + 4:
            return "Сильний"
        if passwords.count(password) == 1:
            return "Дуже сильний"
        return "Сильний"
    print("\nАналіз надійності паролів")
    print("=" * 75)
    print(f"Студент: {STUDENT_NAME}")
    print(f"Група: {GROUP_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}")
    print("=" * 75)
    print(f"{'№':<4}{'Пароль':<25}{'Довжина':<10}{'Результат':<20}")
    print("-" * 75)
    for i, password in enumerate(passwords, 1):
        result = analyze_password(password)
        print(f"{i:<4}{password:<25}{len(password):<10}{result:<20}")
    print("=" * 75)
if __name__ == "__main__":
    run_task1()
