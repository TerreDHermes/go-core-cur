# CVE analysis

Бэкенд принимает задачу на анализ Git-репозитория, сохраняет её в SQLite и обрабатывает пулом воркеров. Анализ читает каждый `go.mod`. Для каждого файла, где указан `package_name`, сохраняются свои `verdict` и `report_md`. Файлы без этого пакета в результат не попадают.

Файл базы задаётся `SQLITE_PATH` и не удаляется при перезапуске. Задачи в статусе `PENDING` после старта снова ставятся в очередь.

## Запуск

Нужны Go 1.22 и `git`.

```bash
go run ./cmd/server
```

Сервер слушает `:8741`. База создаётся в `data/analysis.db`. При старте читается файл `.env` в корне проекта. Уже заданные переменные окружения он не перезаписывает. Сам файл в git не входит: в нём может лежать `GIT_TOKEN`.

Переменные окружения:

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `HTTP_ADDR` | `:8741` | Адрес HTTP |
| `SQLITE_PATH` | `data/analysis.db` | Файл SQLite |
| `WORKER_COUNT` | `2` | Число воркеров |
| `GIT_TIMEOUT` | `2m` | Таймаут clone и поиска |
| `GIT_TOKEN` | пусто | Токен для приватного HTTPS-репозитория. Без него чужой приватный репозиторий отвечает 403 |
| `CVE_PATCH_BASE` | `http://d49.dev.k8s:8080` | База ручки `GET /cve/patch/{cve_id}` |

## API

`POST /api/v1/analysis` — создать задачу, ответ `202` и `{"id":"..."}`.

```bash
curl -s -X POST localhost:8741/api/v1/analysis \
  -H 'Content-Type: application/json' \
  -d '{"component_url":"https://github.com/golang/example","branch":"master","cve_id":"CVE-2024-0001","package_name":"example"}'
```

`GET /api/v1/analysis?limit=10&offset=0&status=PENDING` — список без `verdict` и `report_md`.

`GET /api/v1/analysis/{id}` — полная задача.

`GET /api/v1/analysis/{id}/report` — markdown-отчёт, только для `COMPLETED`.

## Тесты

```bash
go test ./...
```
