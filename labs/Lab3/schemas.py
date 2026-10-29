"""Pydantic-моделі API з перевіркою вхідних і вихідних даних."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .config import VALUE_MAX

Status = Literal["new", "in_progress", "done"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CategoryCreate(StrictModel):
    name: str = Field(min_length=2, max_length=40)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not value.strip() or not 2 <= len(value.strip()) <= 40:
            raise ValueError("Назва має містити від 2 до 40 непорожніх символів")
        return value.strip()


class CategoryRead(CategoryCreate):
    id: int = Field(gt=0)


class RecordCreate(StrictModel):
    code: str = Field(min_length=3, max_length=40)
    title: str = Field(min_length=3, max_length=120)
    category_id: int = Field(gt=0, strict=True)
    value: int = (
        Field(ge=0, le=VALUE_MAX, strict=True)
        if VALUE_MAX is not None
        else Field(ge=0, strict=True)
    )
    status: Status

    @field_validator("code", "title")
    @classmethod
    def validate_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Поле не може бути порожнім")
        return value


class RecordReplace(RecordCreate):
    """Повний набір змінюваних полів для PUT."""


class RecordRead(RecordCreate):
    id: int = Field(gt=0)
    category_name: str


class StudentRead(StrictModel):
    student_name: str
    group_name: str
    variant_number: int


class PingRead(StrictModel):
    status: Literal["ok"]
