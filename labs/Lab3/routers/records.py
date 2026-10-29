"""Маршрути для записів спостережень автентифікації."""

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, Path, Query, Response

from ..config import STATUSES, VALUE_MAX, VALUE_MIN
from ..repository import (
    category_exists,
    create_record,
    create_records_bulk,
    delete_record,
    get_record,
    list_records,
    replace_record,
)
from ..schemas import RecordCreate, RecordRead, RecordReplace

router = APIRouter(tags=["Записи"])


def _check_category(category_id: int) -> None:
    if not category_exists(category_id):
        raise HTTPException(status_code=404, detail="Категорію не знайдено")


def _integrity_error(exc: sqlite3.IntegrityError) -> HTTPException:
    if "FOREIGN KEY" in str(exc):
        return HTTPException(status_code=404, detail="Категорію не знайдено")
    return HTTPException(
        status_code=409, detail="Запис із таким кодом уже існує або порушено обмеження"
    )


@router.get(
    "/records", response_model=list[RecordRead], summary="Список і фільтрація записів"
)
def get_records(
    category_id: int | None = Query(default=None, gt=0),
    status_filter: str | None = Query(default=None, alias="status"),
    min_value: int | None = Query(default=None, ge=VALUE_MIN, le=VALUE_MAX)
    if VALUE_MAX is not None
    else Query(default=None, ge=VALUE_MIN),
    q: str | None = Query(default=None, min_length=1, max_length=120),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    if status_filter is not None and status_filter not in STATUSES:
        raise HTTPException(status_code=422, detail="Недозволений статус")
    return list_records(category_id, status_filter, min_value, q, limit, offset)


@router.get("/records/{record_id}", response_model=RecordRead, summary="Отримати запис")
def get_one_record(record_id: int = Path(gt=0)) -> dict:
    record = get_record(record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Запис не знайдено")
    return record


@router.post(
    "/records", response_model=RecordRead, status_code=201, summary="Створити запис"
)
def post_record(data: RecordCreate) -> dict:
    _check_category(data.category_id)
    try:
        return create_record(data)
    except sqlite3.IntegrityError as exc:
        raise _integrity_error(exc) from exc


@router.put(
    "/records/{record_id}", response_model=RecordRead, summary="Повністю замінити запис"
)
def put_record(record_id: int, data: RecordReplace) -> dict:
    if record_id <= 0:
        raise HTTPException(status_code=422, detail="record_id має бути додатним")
    _check_category(data.category_id)
    try:
        record = replace_record(record_id, data)
    except sqlite3.IntegrityError as exc:
        raise _integrity_error(exc) from exc
    if record is None:
        raise HTTPException(status_code=404, detail="Запис не знайдено")
    return record


@router.delete("/records/{record_id}", status_code=204, summary="Видалити запис")
def remove_record(record_id: int) -> Response:
    if record_id <= 0:
        raise HTTPException(status_code=422, detail="record_id має бути додатним")
    if not delete_record(record_id):
        raise HTTPException(status_code=404, detail="Запис не знайдено")
    return Response(status_code=204)


@router.post(
    "/records/bulk",
    response_model=list[RecordRead],
    status_code=201,
    summary="Атомарно додати пакет",
)
def post_records_bulk(
    items: Annotated[list[RecordCreate], Body(min_length=1, max_length=100)],
) -> list[dict]:
    for item in items:
        _check_category(item.category_id)
    try:
        return create_records_bulk(items)
    except sqlite3.IntegrityError as exc:
        raise _integrity_error(exc) from exc
