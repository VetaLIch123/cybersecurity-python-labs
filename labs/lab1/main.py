import os
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)
from labs.lab1.task1 import run_task1
from labs.lab1.task2 import run_task2
from labs.lab1.task3 import run_task3
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def main():
    print("=" * 60)
    print(f"Лабораторна робота №1: {STUDENT_NAME}")
    print(f"Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 60)
    print("\n>>> ЗАВДАННЯ 1: Аналіз надійності паролів")
    run_task1()
    print("\n>>> ЗАВДАННЯ 2: Система контролю доступу")
    run_task2()
    print("\n>>> ЗАВДАННЯ 3: Хешування, CSV-база та логування")
    run_task3()
    print("\n" + "=" * 60)
    print("Всі завдання успішно виконано!")
    print("=" * 60)
if __name__ == "__main__":
    main()