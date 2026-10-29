"""Перевірка seed.json і атомарне початкове заповнення бази."""

import json
import sqlite3
from contextlib import closing

from pydantic import ValidationError

from .database import DATABASE_PATH, get_connection, initialize_database
from .schemas import CategoryCreate, RecordCreate

SEED_PATH = DATABASE_PATH.parent / "seed.json"


def seed_database() -> str:
    """Заповнити порожню базу категоріями та записами з JSON."""
    try:
        raw = json.loads(SEED_PATH.read_text(encoding="utf-8"))
        if set(raw) != {"categories", "records"}:
            raise ValueError("JSON має містити лише масиви categories і records")
        if any(set(item) != {"id", "name"} for item in raw["categories"]):
            raise ValueError("Кожна категорія seed має містити лише id та name")
        categories = [
            CategoryCreate.model_validate({"name": item["name"]})
            for item in raw["categories"]
        ]
        records = [RecordCreate.model_validate(item) for item in raw["records"]]
        if len(categories) != 3 or len(records) != 8:
            raise ValueError("Для варіанта 4 потрібно рівно 3 категорії та 8 записів")
        if len({item.name for item in categories}) != len(categories):
            raise ValueError("Назви категорій у seed мають бути унікальними")
        if len({item.code for item in records}) != len(records):
            raise ValueError("Коди записів у seed мають бути унікальними")
        if [item.get("id") for item in raw["categories"]] != [1, 2, 3]:
            raise ValueError("Ідентифікатори категорій мають дорівнювати 1, 2, 3")
    except (OSError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        raise ValueError(f"Некоректні початкові дані: {exc}") from exc

    initialize_database()
    with closing(get_connection()) as connection:
        if (
            connection.execute("SELECT COUNT(*) FROM categories").fetchone()[0]
            or connection.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        ):
            return "База вже містить дані; початкове заповнення пропущено без змін."
        try:
            with connection:
                connection.executemany(
                    "INSERT INTO categories(id, name) VALUES (?, ?)",
                    [
                        (int(item["id"]), category.name)
                        for item, category in zip(
                            raw["categories"], categories, strict=True
                        )
                    ],
                )
                connection.executemany(
                    "INSERT INTO records(code, title, category_id, value, status) VALUES (?, ?, ?, ?, ?)",
                    [
                        (
                            item.code,
                            item.title,
                            item.category_id,
                            item.value,
                            item.status,
                        )
                        for item in records
                    ],
                )
        except sqlite3.Error as exc:
            raise ValueError(
                f"Початкові дані не додано, транзакцію скасовано: {exc}"
            ) from exc
    return "Додано 3 категорії та 8 записів."


if __name__ == "__main__":
    print(seed_database())
