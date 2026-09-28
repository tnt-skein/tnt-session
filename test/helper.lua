--- Общие средства проверок сессий.
---
--- Драйверы проверяются настоящими соседями: хранилище кэша в памяти
--- и шифровальщик `tnt-crypto`. Двойник берётся там, где настоящий
--- не даст нужного случая, — отказ хранилища, запись чужого вида,
--- шифровальщик, отдающий не нашу запись.
---
--- Исходники читаются с диска, а не через `require`: у Tarantool свой
--- загрузчик `.rocks`, он идёт раньше `package.path` и подсунул бы
--- установленную копию пакета, если она есть. Проверки тогда шли бы
--- против вчерашнего кода, а покрытие считалось бы по нему. Зависимости
--- пакета — `tnt-cookie`, `tnt-hash`, `tnt-clock`, `tnt-must`
--- и `tnt-external` — берутся из `.rocks` обычным `require`: проверяется
--- этот пакет, а не они. На временном узле они берутся так же.
---
--- Соседи проверок стоят в `.rocks` (`make deps`) и зависимостями пакета
--- не объявлены: хранилище `tnt-cache` и шифровальщик `tnt-crypto` пакету
--- приходят аргументом, а проверкам нужны настоящие.
---
--- Оснастка в `test/testing/` — загрузчик исходников, часы-двойник, запись
--- файлов и временный узел — грузится так же, файлами, и один раз
--- на процесс: второй экземпляр загрузчика не знал бы, что вытеснил
--- первый, и не вернул бы вытесненное на место.
---
--- Проверки берут всё через этот помощник, а не из оснастки напрямую:
--- помощник — единственное, чем файл проверок отличается от того же файла
--- в наборе, где пакет живёт рядом со своими зависимостями.

local digest = require('digest')
local fio = require('fio')
local t = require('luatest')

--- Модули оснастки в порядке зависимостей: узел берёт файлы и загрузчик.
local TESTING = {
    { name = 'tnt.testing.sources', path = 'test/testing/sources.lua' },
    { name = 'tnt.testing.files', path = 'test/testing/files.lua' },
    { name = 'tnt.testing.clock', path = 'test/testing/clock.lua' },
    { name = 'tnt.testing.node', path = 'test/testing/node.lua' },
}

for _, module in ipairs(TESTING) do
    if package.loaded[module.name] == nil then
        local chunk, failure = loadfile(fio.abspath(module.path))

        if chunk == nil then
            error(('оснастка %s не читается: %s'):format(module.name, tostring(failure)))
        end

        package.loaded[module.name] = chunk()
    end
end

--- Оснастка проверок под теми именами, что зовёт помощник.
local testing = {
    load_sources = package.loaded['tnt.testing.sources'].load,
    module = package.loaded['tnt.testing.sources'].module,
    clock = package.loaded['tnt.testing.clock'].new,
    start_node = package.loaded['tnt.testing.node'].start,
    stop_node = package.loaded['tnt.testing.node'].stop,
}

local helper = {
    --- Модули пакета в порядке зависимостей: имя и путь исходника.
    MODULES = {
        { name = 'tnt.session.state', path = 'tnt/session/state.lua' },
        { name = 'tnt.session.cache', path = 'tnt/session/cache.lua' },
        { name = 'tnt.session.cookie', path = 'tnt/session/cookie.lua' },
        { name = 'tnt.session.refusal', path = 'tnt/session/refusal.lua' },
        { name = 'tnt.session.layer', path = 'tnt/session/layer.lua' },
        { name = 'tnt.session.csrf', path = 'tnt/session/csrf.lua' },
        { name = 'tnt.session.manager', path = 'tnt/session/manager.lua' },
        { name = 'tnt.session', path = 'tnt/session.lua' },
    },
}

--- Фасад пакета из исходников.
---
--- Грузится один раз на процесс: состояния у пакета нет, кроме трёх внешних
--- зависимостей, а внешние зависимости проверки возвращают сами (`restore`).
helper.session = testing.load_sources(helper.MODULES, 'tnt.session')

--- Части пакета из той же загрузки, что и фасад.
helper.state = testing.module('tnt.session.state')
helper.manager = testing.module('tnt.session.manager')
helper.layer = testing.module('tnt.session.layer')
helper.csrf = testing.module('tnt.session.csrf')
helper.from_cache = testing.module('tnt.session.cache')
helper.from_cookie = testing.module('tnt.session.cookie')

--- Соседи из `.rocks`: кэш и шифрование приходят пакету аргументом,
--- куки — его зависимость.
helper.cache = require('tnt.cache')
helper.cookies = require('tnt.cookie')
helper.crypto = require('tnt.crypto')

--- Сравнение `tnt-hash` — тот же экземпляр, что берёт слой `csrf`:
--- подмена сравнения в проверке доходит до слоя.
helper.compare = require('tnt.hash.compare')

--- Менеджер над данным драйвером.
---
--- Кука без `Secure`: проверки сверяют заголовок целиком, а `Secure`
--- к делу сессии не относится и лишь удлиняет сверку.
---@param driver TntSessionDriver
---@param opts table|nil Настройки менеджера поверх обычных
---@return TntSessionManager
function helper.manager_over(driver, opts)
    local settings = { driver = driver, cookie = helper.cookies.new({ secure = false }) }

    for name, value in pairs(opts or {}) do
        settings[name] = value
    end

    return helper.manager.new(settings)
end

--- Останавливает узел и убирает его каталог.
helper.stop_node = testing.stop_node

--- Поднимает временный узел с исходниками пакета и его соседей: настоящий
--- `box`, транзакция в нём и хранилище кэша на спейсе. Узел проверка
--- обязана остановить сама — `stop_node`. Имя узла — имя пакета:
--- по нему узел находится в артефактах прогона.
---@return table server
function helper.start_node()
    return testing.start_node({ alias = 'session', modules = helper.MODULES })
end

--- Часы-двойник оснастки: стенные стоят на 1700000000, пока их
--- не подвинет проверка.
---@return TntTestingClock
function helper.clock()
    return testing.clock()
end

--- Возвращает пакету настоящие средства: случайность и часы.
function helper.restore()
    helper.state._set_source(nil)
    helper.from_cookie._set_source(nil)
    helper.manager._set_source(nil)
end

--- Случайные байты по порядку вместо настоящих: проверка сверяет
--- опознаватель дословно.
---@param ... string Байты по порядку, по 32 на тайну; кончились — по кругу
function helper.pin_secrets(...)
    local given = { ... }
    local issued = 0

    helper.state._set_source({
        random = function()
            issued = issued + 1

            return given[(issued - 1) % #given + 1]
        end,
    })
end

--- Тайна в том виде, в каком её отдаёт `state.secret`.
---@param bytes string
---@return string
function helper.secret_of(bytes)
    return digest.base64_encode(bytes, { urlsafe = true })
end

--- Хранилище кэша в памяти со своими часами.
---@param clock TntTestingClock|nil Часы; без них — настоящие
---@return TntCacheStore
function helper.store(clock)
    return helper.cache.new({
        driver = 'memory',
        prefix = 'sess:',
        now = clock ~= nil and clock.realtime or nil,
    })
end

--- Менеджер над хранилищем в памяти.
---@param opts table|nil Настройки поверх обычных
---@return TntSessionManager
function helper.manager_over_cache(opts)
    local settings = { cache = helper.store(), cookie = { secure = false } }

    for name, value in pairs(opts or {}) do
        settings[name] = value
    end

    return helper.session.new(settings)
end

--- Драйвер-двойник: помнит вызовы и отказывает, если велено.
---@param answers table|nil Поля `open` (пара) и `fail` (чем бросать)
---@return TntSessionDriver driver У драйвера поле `calls` — вызовы по порядку
function helper.recording_driver(answers)
    local given = answers or {}
    local driver = { name = 'двойник', calls = {}, remote = given.remote }

    local function note(what, value)
        table.insert(driver.calls, { what, value })

        if given.fail ~= nil then
            error(given.fail, 0)
        end
    end

    driver.open = function(token)
        note('open', token)

        return given.id, given.payload
    end

    driver.commit = function(id)
        note('commit', id)

        return given.token or id
    end

    driver.close = function(id)
        note('close', id)
    end

    return driver
end

--- Заголовок `Cookie` с меткой сессии.
---@param name string
---@param value string
---@return string
function helper.sent(name, value)
    return ('%s=%s'):format(name, value)
end

--- Значение куки из собранного заголовка `Set-Cookie`.
---@param header string|nil
---@param name string
---@return string|nil
function helper.value_of(header, name)
    return (header or ''):match(('^%s=([^;]*)'):format(name))
end

--- Сверяет, что каждый вызов бросает названный отказ и винит строку
--- вызова в файле проверок, а не внутри пакета.
---
--- Вызов стоит в замыкании первой строкой тела, то есть строкой ниже
--- слова `function`: место броска сверяется с ней целиком — файлом,
--- строкой и текстом.
---@param cases table[] Пары: замыкание с вызовом и текст броска
function helper.assert_blamed(cases)
    for _, case in ipairs(cases) do
        local _, err = pcall(case[1])
        local info = debug.getinfo(case[1], 'S') --[[@as { short_src: string, linedefined: integer }]]

        t.assert_equals(err, ('%s:%d: %s'):format(info.short_src, info.linedefined + 1, case[2]))
    end
end

--- Сверяет, что бросок случился и сказал ровно это.
---@param fn fun()
---@param message string
function helper.assert_raised(fn, message)
    local ok, err = pcall(fn)

    t.assert_equals(ok, false)
    t.assert_equals(tostring(err), message)
end

return helper
