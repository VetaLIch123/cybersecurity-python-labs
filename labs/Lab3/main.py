"""FastAPI-застосунок для навчального обліку подій автентифікації."""

import logging
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

from .config import DOMAIN_NAME, THRESHOLD, VALUE_LABEL, VALUE_UNIT
from .database import initialize_database
from .routers.categories import router as categories_router
from .routers.records import router as records_router
from .schemas import PingRead, StudentRead

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        initialize_database()
    except sqlite3.Error as exc:
        logger.exception("Не вдалося ініціалізувати базу даних")
        raise RuntimeError("Не вдалося ініціалізувати базу даних") from exc
    yield


app = FastAPI(
    title="Облік подій автентифікації",
    description=(
        f"{DOMAIN_NAME}. Записи зберігають {VALUE_LABEL} за навчальний інтервал; "
        f"одиниця — {VALUE_UNIT}, навчальний поріг — {THRESHOLD}."
    ),
    version="1.0.0",
    lifespan=lifespan,
)
app.include_router(categories_router)
app.include_router(records_router)


@app.get("/ping", response_model=PingRead, summary="Перевірити доступність API")
def ping() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/student", response_model=StudentRead, summary="Дані студента та варіанта")
def student() -> dict[str, str | int]:
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }
