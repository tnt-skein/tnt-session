--- Слой `session`: сессия на входе запроса, кука в ответе.
---
--- Слой собирается менеджером — `manager:layer(настройки)`, — потому что
--- хранилище и кука живут в менеджере, а не в слое: два слоя на разных
--- группах маршрутов работают с одной сессией.
---
---     local web = router.new({ entry = { manager:layer() } })
---     -- в обработчике: request.session:put('cart', { 7 })
---
--- **Сессия кладётся в запрос полем.** Так её видит обработчик и всякий
--- слой ближе к нему; хранилище файбера для этого не берётся — довесок,
--- положенный мимо запроса, теряется на первом же обходе роутера
--- (`tnt.router.request`).
---
--- **Отказ хранилища — поломка запроса, а не тихая новая сессия.** Слой
--- отвечает отказом по договору границы HTTP: `status = 503`, слово, код.
--- Вид ответа рисует роутер, `tnt-error` либо каталог приложения — слою
--- это не по чину.
---
--- **Сохраняется сессия и тогда, когда обработчик отказал.** Одноразовое
--- сообщение кладут как раз перед отказом, а кука ставится и отказу:
--- у отказа по тому же договору есть свои заголовки.
---
--- **Чужой `Set-Cookie` не затирается**: значение становится списком,
--- и сервер пишет по строке на каждый — так он и устроен
--- (`tnt.router.takeover`).

local must = require('tnt.must')

local refusal = require('tnt.session.refusal')

local Module = {}

--- Под каким полем сессия ложится в запрос, если не сказано иного.
Module.FIELD = 'session'

--- Заголовок, которым ставится кука.
Module.HEADER = 'set-cookie'

--- Отказ, когда хранилище сессий не отвечает.
---
--- 503, а не 500: беда снаружи, она временная, и повторить запрос
--- осмысленно.
Module.STATUS = 503
Module.MESSAGE = 'сессия недоступна'
Module.CODE = 'session_unavailable'

---@class TntSessionLayerOptions
---@field field string|nil Поле запроса, куда класть сессию; по умолчанию `session`
---@field tag string|nil Журнал слоя; реестр `tnt-middleware` кладёт сюда свою метку

--- Описание настроек слоя.
---
--- `tag` здесь потому, что реестр `tnt-middleware` кладёт свою метку
--- журнала в настройки каждого слоя.
local OPTIONS = { field = '?not_empty', tag = '?string' }

--- Чем отказывает слой: хранилище сессий не отвечает.
local UNAVAILABLE = {
    status = Module.STATUS,
    message = Module.MESSAGE,
    code = Module.CODE,
}

--- Значение заголовка `Cookie` запроса.
---@param request table
---@return string|nil
local function cookie_of(request)
    if type(request.headers) ~= 'table' then
        return nil
    end

    return request.headers['cookie']
end

--- Ставит куку тому, что уходит клиенту.
---
--- Заголовки не таблицей — ставить некуда, и запрос от этого не страдает:
--- ответ собрал не роутер.
---@param carrier any Ответ либо отказ
---@param header string
local function attach(carrier, header)
    if type(carrier) ~= 'table' or (carrier.headers ~= nil and type(carrier.headers) ~= 'table') then
        return
    end

    local headers = carrier.headers or {}
    local present = headers[Module.HEADER]

    if present == nil then
        headers[Module.HEADER] = header
    elseif type(present) == 'table' then
        table.insert(present, header)
    else
        headers[Module.HEADER] = { present, header }
    end

    carrier.headers = headers
end

--- Собирает слой.
---
--- Негодные настройки — бросок при сборке, на строку того, кто собирает:
--- опечатка в имени поля обязана найтись при объявлении цепочки, а не
--- на первом запросе.
---@param manager TntSessionManager
---@param options TntSessionLayerOptions|nil
---@return fun(request: any, next_layer: fun(request: any): any, any): any, any
function Module.new(manager, options)
    local settings = options or {}

    must.at(2).options(settings, 'настройки слоя', OPTIONS)

    local field = settings.field or Module.FIELD

    return function(request, next_layer)
        local session, err = manager:start(cookie_of(request))

        if session == nil then
            return nil, refusal.of(UNAVAILABLE, err)
        end

        request[field] = session

        local response, failure = next_layer(request)
        local header, broken = manager:commit(session)

        if broken ~= nil then
            return nil, refusal.of(UNAVAILABLE, broken)
        end

        if header ~= nil then
            attach(failure or response, header)
        end

        return response, failure
    end
end

return Module
