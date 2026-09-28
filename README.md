# tnt-session

Сессии для Tarantool: данные посетителя между запросами. Кука несёт
случайный опознаватель, данные лежат у драйвера — в хранилище кэша
(память, спейс либо Redis) или в самой куке, зашифрованными. Слой
`session` поднимает сессию на входе запроса и ставит куку в ответе,
слой `csrf` сверяет токен от подделки запросов.

```lua
local session = require('tnt.session')
local cache = require('tnt.cache')

local sessions = session.new({ cache = cache.new({ driver = 'memory', prefix = 'sess:' }) })

local web = router.new({ entry = { sessions:layer(), session.csrf.new({ except = { '/hooks' } }) } })

web.post('/cart', function(request)
    request.session:put('user', 42)          -- следующий запрос прочтёт 42
    request.session:flash('notice', 'Сохранено')

    return { status = 200, body = 'ok' }
end)
-- POST без токена сессии: 403 session_token_mismatch
```

Зависимости: `tnt-cookie`, `tnt-hash`, `tnt-clock`, `tnt-must`
и `tnt-external`. Хранилище `tnt-cache` и шифровальщик `tnt-crypto`
приходят аргументом и нужны только своему драйверу.

## Зачем

Готового в Tarantool нет: ни модуля ядра, ни рока, а рок `http` отдаёт
заголовки как есть. Пакет даёт то, что нужно приложению со страницами
и формами:

- **Метка от клиента не становится опознавателем.** Метка, которой
  у хранилища нет, — просроченная сессия либо навязанная кука, и сессия
  заводится со своим опознавателем: 32 случайных байта, а не ULID.
  `regenerate` после входа меняет и опознаватель, и токен.
- **Своего спейса нет.** «Сессии в спейсе» — хранилище кэша на спейсе,
  «сессии в Redis» — хранилище кэша на Redis: срок, обход и чистку
  ведёт кэш. Драйвер `cookie` держит сессию в самой куке, зашифрованной
  с именем куки присоединёнными данными и сроком внутри шифровки.
- **Отказ хранилища — пара, а не тихая новая сессия.** `start`
  и `commit` отвечают `nil, err`, слой — отказом 503: хранилище, которое
  не отвечает, иначе разлогинило бы всех молча.
- **Токен сверяется за постоянное время** — полем формы `_token` или
  заголовком `x-csrf-token`, у способов, меняющих состояние. Несовпадение —
  403 с кодом `session_token_mismatch`, и токена нет ни в отказе,
  ни в журнале.

## Установка

```sh
tt rocks install tnt-session --server=https://tnt-skein.github.io/rocks
```

Или из исходников:

```sh
git clone https://github.com/tnt-skein/tnt-session.git
cd tnt-session && tt rocks make
```

## Как пользоваться

| Действие | Что делает |
|---|---|
| `session.new({ driver, cache, cipher, name, lifetime, cookie })` | менеджер: драйвер `cache` (по умолчанию), `cookie` либо свой |
| `sessions:start(заголовок Cookie)` | сессия по метке либо новая; отказ хранилища — `nil, err` |
| `sessions:commit(сессия)` | сохраняет и отдаёт `Set-Cookie`; пустую новую — `nil` |
| `sessions:regenerate`, `invalidate`, `expire` | новый опознаватель при входе, пустая сессия и погашенная кука при выходе |
| `sessions:layer(настройки)`, `sessions:factory()` | слой `session` и фабрика для реестра слоёв |
| `get`, `put`, `has`, `all`, `forget`, `flush`, `pull` | данные сессии по ключу |
| `flash`, `keep`, `token` | одноразовые значения и токен от подделки запросов |
| `session.csrf.new({ methods, field, header, session, except })` | слой сверки токена |

Сессия в самой куке — драйвер `cookie` над шифровальщиком `tnt-crypto`:

```lua
local crypto = require('tnt.crypto')

local sessions = session.new({
    driver = 'cookie',
    cipher = crypto.new({ key = crypto.derive(secret, 'session') }),
    lifetime = 3600,
})

local who = sessions:start(request.headers['cookie'])
who:put('user', 42)
response.headers['set-cookie'] = sessions:commit(who)
--> tnt_session=qMN5fFV1…; Max-Age=3600; Path=/; SameSite=Lax; Secure; HttpOnly
```

## Проверки

```sh
make deps          # luatest, luacheck, luacov с cluacov, зависимости пакета и соседи проверок в .rocks
make check         # форматирование, линт, проверки, покрытие с порогом 100 %
make mutants-all   # мутационное тестирование утилитой tnt-mutants из PATH, порог 100 % убитых
```

Покрытие строк — 100 %, убитых мутантов — 100 % (96 проверок; 255 мутантов
в восьми модулях). Драйверы проверяются настоящими хранилищем `tnt-cache`
и шифровальщиком `tnt-crypto`, слой `csrf` — с настоящим сравнением
`tnt-hash`, сессия в спейсе и драйвер по сети внутри транзакции —
на настоящем box временного узла.

## Документ

Полное описание со слоями, драйверами, защитой форм, договором отказа
и обоснованием решений: [docs/session.md](docs/session.md).

## Лицензия

MIT.
