"""Маршрути для категорій."""

import sqlite3

from fastapi import APIRouter, HTTPException, Response, status

from ..repository import create_category, delete_category, list_categories
from ..schemas import CategoryCreate, CategoryRead

router = APIRouter(tags=["Категорії"])


@router.get(
    "/categories", response_model=list[CategoryRead], summary="Список категорій"
)
def get_categories() -> list[dict]:
    return list_categories()


@router.post(
    "/categories",
    response_model=CategoryRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створити категорію",
)
def post_category(data: CategoryCreate) -> dict:
    try:
        return create_category(data)
    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            status_code=409, detail="Категорія з такою назвою вже існує"
        ) from exc


@router.delete(
    "/categories/{category_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалити порожню категорію",
)
def remove_category(category_id: int, response: Response) -> Response:
    if category_id <= 0:
        raise HTTPException(status_code=422, detail="category_id має бути додатним")
    try:
        if not delete_category(category_id):
            raise HTTPException(status_code=404, detail="Категорію не знайдено")
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Категорія містить записи") from exc
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
