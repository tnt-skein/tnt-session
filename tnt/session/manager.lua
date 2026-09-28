--- Менеджер сессий: кука на входе, запись у драйвера на выходе.
---
--- Он знает три вещи, которых не знает ни сессия, ни драйвер: как
--- достать метку из заголовка `Cookie`, как собрать `Set-Cookie`
--- (`tnt-cookie`) и когда сессию вообще стоит записывать.
---
---     local session, err = manager:start(request.headers['cookie'])
---     session:put('user', 42)
---     local header, failure = manager:commit(session)
---
--- **Отказ хранилища — пара `nil, err`, а не тихая новая сессия.**
--- Хранилище, которое не отвечает, разлогинило бы всех молча: посетитель
--- увидел бы пустую корзину и форму входа, а в журнале не было бы ничего.
--- Пара доходит до границы запроса, и слой отвечает 503.
---
--- **Опознаватель от клиента не принимается.** Метка, которой у хранилища
--- нет, — это либо просроченная сессия, либо навязанная кука. И в том,
--- и в другом случае заводится своя сессия со своим опознавателем: приняв
--- чужую метку, мы дали бы тому, кто её навязал, готовый пропуск
--- в сессию посетителя (session fixation).
---
--- **Новая пустая сессия не пишется никуда.** Ни записи, ни куки: обход
--- робота, который ничего в сессию не положил, иначе оставлял бы запись
--- за каждый запрос. Пришедшая из хранилища переписывается всегда, даже
--- нетронутая, — этим и продлевается её срок, пока посетитель работает.
---
--- **Драйвер по сети внутри транзакции box не зовётся** — бросок
--- до обращения к драйверу, как и у кэша: уступка на сети порвала бы
--- транзакцию memtx, и вызывающий узнал бы об этом только на фиксации,
--- а записанная сессия при откате осталась бы лежать.

local fiber = require('fiber')

local external = require('tnt.external')

--- Ошибка программиста — словом, без места в коде.
local fail = require('tnt.must.fail').raise

local layer = require('tnt.session.layer')
local state = require('tnt.session.state')

local Module = {}

--- Имя куки, если не задано иное.
---
--- Имя приложения и того, чем оно поднято, в нём не называется нарочно:
--- такая кука сама рассказывает чужому сканеру, что у нас внутри.
Module.DEFAULT_NAME = 'tnt_session'

--- Сколько живёт сессия, если не задано иное: два часа. Этого хватает на
--- работу с приложением и мало, чтобы забытая вкладка оставалась входом до
--- утра.
Module.DEFAULT_LIFETIME = 2 * 60 * 60

--- Тексты отказов хранилища.
local FAILED_READ = 'сессия: драйвер %s не отдал сессию: %s'
local FAILED_WRITE = 'сессия: драйвер %s не сохранил сессию: %s'

--- Драйвер по сети внутри транзакции box.
local REMOTE_IN_TRANSACTION = 'сессия: драйвер %s ходит по сети — внутри транзакции box его не зовут: '
    .. 'уступка порвёт транзакцию, а записанное в него при откате останется'

--- Внешнее средство: признак транзакции.
---
--- Через внешнюю зависимость затем, что проверки идут без поднятого инстанса: до `box.cfg`
--- поле `is_in_txn` бросает, а драйверу в куке box не нужен вовсе.
local source = external.install(Module, {
    in_transaction = function()
        return type(box.cfg) == 'table' and box.is_in_txn()
    end,
})

---@class TntSessionDriver Где живут данные сессии
---@field open fun(token: string): string|nil, any Опознаватель и запись по метке из куки; пусто — такой сессии нет
---@field commit fun(id: string, payload: table, ttl: number): string Сохраняет и отдаёт метку для куки
---@field close fun(id: string) Забыть сессию
---@field name string Имя драйвера — для status и отказов
---@field remote boolean|nil Ходит по сети: внутри транзакции box не зовётся

---@class TntSessionManager
---@field driver TntSessionDriver
---@field cookie TntCookie Набор кук: из него берётся разбор и сборка заголовка
---@field name string Имя куки
---@field lifetime integer Сколько живёт сессия, секунды
local Manager = {}
Manager.__index = Manager

--- Драйвер по сети внутри транзакции — ошибка программиста.
---
--- Проверяется до обращения к драйверу: иначе бросок уступки стал бы
--- отказом хранилища, и ошибка программиста ушла бы в ответ как 503.
---@param driver TntSessionDriver
local function demand_outside_transaction(driver)
    if not driver.remote then
        return
    end

    if source().in_transaction() then
        fail(REMOTE_IN_TRANSACTION:format(driver.name))
    end
end

--- Сессия по метке из куки.
---
--- Пусто без отказа — метки такой нет: сессия просрочена, стёрта либо
--- навязана. Пара — хранилище отказало.
---@param self TntSessionManager
---@param token string
---@return TntSession|nil
---@return string|nil err
local function restored(self, token)
    local ok, id, payload = pcall(self.driver.open, token)

    if not ok then
        -- Отмена файбера, спрятанная в отказ, оставила бы отменённый файбер
        -- жить дальше.
        fiber.testcancel()

        return nil, FAILED_READ:format(self.driver.name, tostring(id))
    end

    if id == nil then
        return nil
    end

    return state.restore(id, payload)
end

--- Поднимает сессию по заголовку `Cookie` запроса.
---@param header any Значение заголовка; пусто — сессии не было
---@return TntSession|nil
---@return string|nil err Хранилище отказало
function Manager:start(header)
    demand_outside_transaction(self.driver)

    local token = self.cookie:parse(header)[self.name]
    local session

    if token ~= nil then
        local found, err = restored(self, token)

        if err ~= nil then
            return nil, err
        end

        session = found
    end

    return session or state.new(state.secret())
end

--- Сохраняет сессию и отдаёт заголовок `Set-Cookie`.
---
--- Пусто без отказа — ставить нечего: новая сессия, в которую ничего
--- не положили.
---@param session TntSession
---@return string|nil header
---@return string|nil err
function Manager:commit(session)
    demand_outside_transaction(self.driver)

    if not session.stored and state.empty(session) then
        return nil
    end

    local ok, token = pcall(self.driver.commit, session.id, state.payload(session), self.lifetime)

    if not ok then
        fiber.testcancel()

        return nil, FAILED_WRITE:format(self.driver.name, tostring(token))
    end

    return self.cookie:set(self.name, token, { max_age = self.lifetime })
end

--- Заголовок, которым кука сессии гасится у браузера.
---@return string|nil header
---@return string|nil err
function Manager:expire()
    return self.cookie:expire(self.name)
end

--- Меняет опознаватель сессии, а при `drop` ещё и стирает данные.
---@param self TntSessionManager
---@param session TntSession
---@param drop boolean
---@return boolean|nil
---@return string|nil err
local function migrated(self, session, drop)
    demand_outside_transaction(self.driver)

    local previous = session.id
    local stored = session.stored

    if drop then
        session:flush()
    end

    -- Токен заводится заново при первом обращении: украденный до входа
    -- иначе действовал бы и после.
    session.secret = nil
    session.id = state.secret()
    session.dirty = true
    session.stored = false

    if not stored then
        return true
    end

    local ok, err = pcall(self.driver.close, previous)

    if not ok then
        fiber.testcancel()

        return nil, FAILED_WRITE:format(self.driver.name, tostring(err))
    end

    return true
end

--- Выдаёт сессии новый опознаватель, сохранив данные.
---
--- Зовут это после входа: опознаватель, который посетитель носил до
--- входа, мог быть ему навязан, и после входа он стал бы пропуском
--- в учётную запись.
---@param session TntSession
---@return boolean|nil
---@return string|nil err
function Manager:regenerate(session)
    return migrated(self, session, false)
end

--- Обнуляет сессию: новый опознаватель и пустые данные.
---
--- Зовут это при выходе. Куку после этого гасят `expire`: сессия пуста,
--- и `commit` ставить её не станет.
---@param session TntSession
---@return boolean|nil
---@return string|nil err
function Manager:invalidate(session)
    return migrated(self, session, true)
end

--- Собирает слой `session` для роутера и `tnt-middleware`.
---@param options TntSessionLayerOptions|nil
---@return fun(request: any, next_layer: fun(request: any): any, any): any, any
function Manager:layer(options)
    return layer.new(self, options)
end

--- Фабрика слоя для реестра `tnt-middleware`.
---
--- `middleware.configure({ layers = { session = manager:factory() } })` —
--- и слой объявляется в цепочке именем, как готовые.
---@return fun(options: table): fun(request: any, next_layer: fun(request: any): any, any): any, any
function Manager:factory()
    return function(options)
        return layer.new(self, options)
    end
end

--- Что настроено; данных и ключей здесь не бывает.
---@return table
function Manager:status()
    return { driver = self.driver.name, name = self.name, lifetime = self.lifetime }
end

---@class TntSessionManagerOptions
---@field driver TntSessionDriver Где живут данные
---@field cookie TntCookie Набор кук `tnt-cookie`
---@field name string|nil Имя куки; по умолчанию `tnt_session`
---@field lifetime integer|nil Сколько живёт сессия, секунды; по умолчанию два часа

--- Заводит менеджер.
---@param opts TntSessionManagerOptions
---@return TntSessionManager
function Module.new(opts)
    if opts.name ~= nil and (type(opts.name) ~= 'string' or opts.name == '') then
        fail('сессия: name — непустая строка, имя куки')
    end

    local lifetime = opts.lifetime or Module.DEFAULT_LIFETIME

    -- Целое: срок уходит в `Max-Age` куки, а тот по RFC 6265 — целое
    -- число секунд.
    if type(lifetime) ~= 'number' or lifetime <= 0 or lifetime % 1 ~= 0 then
        fail('сессия: lifetime — целое число секунд больше нуля')
    end

    return setmetatable({
        driver = opts.driver,
        cookie = opts.cookie,
        name = opts.name or Module.DEFAULT_NAME,
        lifetime = lifetime,
    }, Manager)
end

return Module
