# Лабораторна робота №3

## Варіант 4 — облік подій автентифікації

Сервіс зберігає кількість навчальних подій певного типу за інтервал. Категорії: `failed_login`, `blocked_account`, `mfa_failure`. Поле `value` — невід’ємне ціле число подій (`events`); навчальний поріг — 20. Статус фіксує стан перевірки: `new`, `in_progress` або `done`. Дані є синтетичними й не описують реальну інфраструктуру.

## Структура

```text
labs/Lab3/
├── main.py, config.py, database.py, repository.py, schemas.py, seed.py
├── schema.sql
├── routers/{categories.py, records.py}
├── data/seed.json
└── data/lab3.sqlite3  # створюється локально, не комітиться
```

База містить `categories(id, name)` і `records(id, code, title, category_id, value, status)`. Первинні ключі `id` додатні; `categories.name` і `records.code` унікальні; довжини та значення обмежені `CHECK`; `records.category_id` посилається на категорію із `ON DELETE RESTRICT`. Усі значення в SQL передаються параметрами.

## Підготовка та запуск

Команди виконуються з кореня репозиторію. Потрібен Python 3.10+.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m labs.Lab3.database
python -m labs.Lab3.seed
uvicorn labs.Lab3.main:app --reload --host 127.0.0.1 --port 8000
```

Початкове заповнення додає всі 3 категорії та 8 записів атомарно. Повторний запуск на непорожній базі нічого не змінює. Swagger UI: <http://127.0.0.1:8000/docs>, OpenAPI: <http://127.0.0.1:8000/openapi.json>.

## Основні запити

```powershell
Invoke-RestMethod http://127.0.0.1:8000/ping
Invoke-RestMethod http://127.0.0.1:8000/student
Invoke-RestMethod 'http://127.0.0.1:8000/records?category_id=1&status=new&min_value=20&limit=5&offset=0'
```

Створення запису (тіло JSON):

```json
{"code":"V04-DEMO","title":"Інтервал автентифікації demo","category_id":1,"value":7,"status":"new"}
```

Для повної заміни через `PUT /records/{record_id}` передайте той самий набір змінюваних полів. Для `POST /records/bulk` передається JSON-масив із 1–100 таких об’єктів. Дублікат повертає 409, неіснуюча категорія або запис — 404, некоректні поля та параметри — 422. Пошук `q` є буквальним і чутливим до регістру.

## Контрольні перевірки

| Перевірка | Очікуваний результат |
| --- | --- |
| Порожня база, потім повторний `python -m labs.Lab3.seed` | 3 категорії, 8 записів; другий запуск без змін |
| `GET /ping`, `/student`, `/categories` | 200; `status=ok`, дані з `shared.student`, 3 категорії |
| CRUD запису | POST 201, GET/PUT 200, DELETE 204 |
| `category_id=1&status=new`, `limit`, `offset` | Умови об’єднано через AND, сортування за id |
| Від’ємне/дробове `value`, порожній `title`, невідоме поле, `limit=0` | 422; база не змінюється |
| Відсутній id/категорія; дублікат коду/назви категорії | 404; 409 відповідно |
| Видалення непорожньої/порожньої категорії | 409 / 204 |
| Пакет із двох коректних нових записів | 201; обидва збережені |
| Пакет, де другий елемент має дублікат коду | 409; перший елемент також відсутній після відкату |
| Пакет, де другий елемент посилається на неіснуючу категорію | 404; жоден новий елемент пакета не збережений |
| `q=' OR 1=1 --` | Рядок обробляється як буквальне значення; дані не змінені |
| Перезапуск API | Раніше збережений запис доступний |

Перевірка стилю з кореня репозиторію:

```powershell
ruff check .
ruff format --check .
```

Базу `data/lab3.sqlite3` створює програма; у Git зберігаються лише схема, код і навчальний JSON.
