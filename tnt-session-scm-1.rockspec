rockspec_format = '3.0'

package = 'tnt-session'
version = 'scm-1'

source = {
    url = 'git+https://github.com/tnt-skein/tnt-session.git',
    branch = 'main',
}

description = {
    summary = 'Сессии: данные посетителя между запросами — кука с опознавателем, драйвер хранилища и сверка токена',
    detailed = [[
        Данные посетителя между запросами: get, put, has, all, forget,
        flush, pull, одноразовые значения (flash, keep) и токен от
        подделки запросов. Опознаватель и токен — 32 случайных байта
        в base64url, а не ULID: опознаватель даёт силу пропуска, и время
        в старших битах сузило бы перебор. Кука несёт опознаватель
        со строгими умолчаниями: HttpOnly, Secure, SameSite=Lax.

        Драйверов два. cache — данные в хранилище кэша, пришедшем
        аргументом (память, спейс либо Redis): сессию можно отозвать,
        размер не ограничен. cookie — данные в самой куке, зашифрованные
        шифровальщиком AEAD, пришедшим аргументом, с именем куки
        присоединёнными данными и сроком внутри шифровки: хранилища
        на узле нет вовсе. Свой драйвер — таблица open, commit, close.

        Метка, которой у хранилища нет, не принимается — навязанная кука
        не станет сессией; regenerate после входа и invalidate при выходе
        меняют опознаватель и токен; новая пустая сессия не пишется
        никуда; отказ хранилища — пара nil, err, а слой session отвечает
        503 и ставит куку и ответу, и отказу обработчика.

        Слой csrf сверяет токен у способов, меняющих состояние: поле
        формы либо заголовок против токена сессии, сравнение
        за постоянное время, освобождённые адреса списком, несовпадение —
        403, и ни в отказе, ни в журнале самого токена нет.

        Зависит от tnt-cookie (разбор Cookie и сборка Set-Cookie),
        tnt-hash (сравнение за постоянное время), tnt-clock (стенные часы
        срока в куке), tnt-must (проверки аргументов) и tnt-external
        (подмена случайности, часов и признака транзакции в проверках).
    ]],
    homepage = 'https://github.com/tnt-skein/tnt-session',
    issues_url = 'https://github.com/tnt-skein/tnt-session/issues',
    maintainer = 'tnt-skein',
    license = 'MIT',
    labels = { 'tarantool', 'session', 'cookie', 'csrf', 'middleware' },
}

dependencies = {
    'lua >= 5.1',
    -- Проверки настроек слоёв на строке вызывающего и бросок без места.
    'tnt-must',
    -- Стенные часы срока, который драйвер cookie кладёт в шифровку.
    'tnt-clock',
    -- Разбор заголовка Cookie и сборка Set-Cookie со строгими умолчаниями.
    'tnt-cookie',
    -- Сравнение токена за постоянное время.
    'tnt-hash',
    -- Подмена случайных байтов, часов и признака транзакции box в проверках.
    'tnt-external',
}

build = {
    type = 'builtin',
    modules = {
        ['tnt.session'] = 'tnt/session.lua',
        ['tnt.session.cache'] = 'tnt/session/cache.lua',
        ['tnt.session.cookie'] = 'tnt/session/cookie.lua',
        ['tnt.session.csrf'] = 'tnt/session/csrf.lua',
        ['tnt.session.layer'] = 'tnt/session/layer.lua',
        ['tnt.session.manager'] = 'tnt/session/manager.lua',
        ['tnt.session.refusal'] = 'tnt/session/refusal.lua',
        ['tnt.session.state'] = 'tnt/session/state.lua',
    },
}
