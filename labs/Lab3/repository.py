"""Параметризовані SQL-операції для категорій і записів."""

import sqlite3
from contextlib import closing
from typing import Any

from .database import get_connection
from .schemas import CategoryCreate, RecordCreate, RecordReplace

RECORD_SELECT = """
SELECT r.id, r.code, r.title, r.category_id, c.name AS category_name,
       r.value, r.status
FROM records AS r JOIN categories AS c ON c.id = r.category_id
"""


def _dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def create_category(data: CategoryCreate) -> dict[str, Any]:
    with closing(get_connection()) as connection, connection:
        cursor = connection.execute(
            "INSERT INTO categories(name) VALUES (?)", (data.name,)
        )
        return {"id": cursor.lastrowid, "name": data.name}


def list_categories() -> list[dict[str, Any]]:
    with closing(get_connection()) as connection:
        rows = connection.execute(
            "SELECT id, name FROM categories ORDER BY id"
        ).fetchall()
        return [dict(row) for row in rows]


def delete_category(category_id: int) -> bool:
    with closing(get_connection()) as connection, connection:
        cursor = connection.execute(
            "DELETE FROM categories WHERE id = ?", (category_id,)
        )
        return cursor.rowcount > 0


def category_exists(category_id: int) -> bool:
    with closing(get_connection()) as connection:
        return (
            connection.execute(
                "SELECT 1 FROM categories WHERE id = ?", (category_id,)
            ).fetchone()
            is not None
        )


def get_record(record_id: int) -> dict[str, Any] | None:
    with closing(get_connection()) as connection:
        return _dict(
            connection.execute(
                RECORD_SELECT + " WHERE r.id = ?", (record_id,)
            ).fetchone()
        )


def list_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: int | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    for clause, value in (
        ("r.category_id = ?", category_id),
        ("r.status = ?", status),
        ("r.value >= ?", min_value),
        ("instr(r.title, ?) > 0", q),
    ):
        if value is not None:
            clauses.append(clause)
            params.append(value)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    params.extend((limit, offset))
    with closing(get_connection()) as connection:
        rows = connection.execute(
            RECORD_SELECT + where + " ORDER BY r.id LIMIT ? OFFSET ?", params
        ).fetchall()
        return [dict(row) for row in rows]


def create_record(data: RecordCreate) -> dict[str, Any]:
    with closing(get_connection()) as connection, connection:
        cursor = connection.execute(
            "INSERT INTO records(code, title, category_id, value, status) VALUES (?, ?, ?, ?, ?)",
            (data.code, data.title, data.category_id, data.value, data.status),
        )
        row = connection.execute(
            RECORD_SELECT + " WHERE r.id = ?", (cursor.lastrowid,)
        ).fetchone()
        return dict(row)


def replace_record(record_id: int, data: RecordReplace) -> dict[str, Any] | None:
    with closing(get_connection()) as connection, connection:
        cursor = connection.execute(
            "UPDATE records SET code = ?, title = ?, category_id = ?, value = ?, status = ? WHERE id = ?",
            (
                data.code,
                data.title,
                data.category_id,
                data.value,
                data.status,
                record_id,
            ),
        )
        if cursor.rowcount == 0:
            return None
        return dict(
            connection.execute(
                RECORD_SELECT + " WHERE r.id = ?", (record_id,)
            ).fetchone()
        )


def delete_record(record_id: int) -> bool:
    with closing(get_connection()) as connection, connection:
        cursor = connection.execute("DELETE FROM records WHERE id = ?", (record_id,))
        return cursor.rowcount > 0


def create_records_bulk(items: list[RecordCreate]) -> list[dict[str, Any]]:
    """Додати пакет в одній транзакції; будь-яка помилка скасовує всі вставки."""
    with closing(get_connection()) as connection, connection:
        created: list[dict[str, Any]] = []
        for item in items:
            cursor = connection.execute(
                "INSERT INTO records(code, title, category_id, value, status) VALUES (?, ?, ?, ?, ?)",
                (item.code, item.title, item.category_id, item.value, item.status),
            )
            row = connection.execute(
                RECORD_SELECT + " WHERE r.id = ?", (cursor.lastrowid,)
            ).fetchone()
            created.append(dict(row))
        return created
