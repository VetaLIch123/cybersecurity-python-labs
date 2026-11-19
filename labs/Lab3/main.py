"""FastAPI-застосунок для навчального обліку подій автентифікації."""

import logging
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
import uvicorn

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

from labs.Lab3.config import DOMAIN_NAME, THRESHOLD, VALUE_LABEL, VALUE_UNIT
from labs.Lab3.database import initialize_database
from labs.Lab3.routers.categories import router as categories_router
from labs.Lab3.routers.records import router as records_router
from labs.Lab3.schemas import PingRead, StudentRead
from labs.Lab3.seed import seed_database

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        initialize_database()
        seed_result = seed_database()
        logger.info("Початкові дані: %s", seed_result)
    except (sqlite3.Error, ValueError) as exc:
        logger.exception("Не вдалося підготувати базу даних")
        raise RuntimeError("Не вдалося підготувати базу даних") from exc
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


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    """Перенаправити браузер із кореневої адреси до Swagger UI."""
    return RedirectResponse(url="/docs", status_code=307)


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


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
