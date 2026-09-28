--- Сессии: данные посетителя между запросами.
---
---     local session = require('tnt.session')
---     local cache = require('tnt.cache')
---
---     local sessions = session.new({
---         driver = 'cache',
---         cache = cache.new({ driver = 'space', space = 'app_sessions', prefix = 'sess:' }),
---         lifetime = 2 * 60 * 60,
---         cookie = { domain = 'example.org' },
---     })
---
---     local who, err = sessions:start(request.headers['cookie'])
---     who:put('user', 42)
---     response.headers['set-cookie'] = sessions:commit(who)
---
--- Кука несёт опознаватель, данные лежат у драйвера. Драйвера два:
--- `cache` — хранилище `tnt-cache` аргументом (память, спейс либо Redis),
--- `cookie` — данные едут в самой куке, зашифрованные `tnt-crypto`.
--- Своего спейса у сессий нет нарочно: запись со сроком, обход кусками
--- и чистка просроченного уже написаны в `tnt-cache`, и второй такой
--- обход разошёлся бы с первым.
---
--- Части: `state` — сама сессия (данные, одноразовые, токен);
--- `manager` — кука, драйвер и жизнь сессии; `cache` и `cookie` —
--- драйверы; `layer` — слой для роутера и `tnt-middleware`; `csrf` —
--- слой сверки токена от подделки запросов; `refusal` — вид отказа,
--- которым отвечают оба слоя.
---
---     middleware.configure({ layers = {
---         session = sessions:factory(),
---         csrf = session.csrf.new,
---     } })
---
--- Чего здесь нет: входа и учётных записей (вход своим паролем —
--- `tnt-webauth`, поверх сессии) и отзыва сессий списком.

local cookies = require('tnt.cookie')

local cache = require('tnt.session.cache')
local cookie = require('tnt.session.cookie')
local csrf = require('tnt.session.csrf')
local layer = require('tnt.session.layer')
local manager = require('tnt.session.manager')
local refusal = require('tnt.session.refusal')
local state = require('tnt.session.state')

--- Отказ настройки — словом, без места в коде.
local raise = require('tnt.must.fail').raise

local Module = {}

Module.cache = cache
Module.cookie = cookie
Module.csrf = csrf
Module.layer = layer
Module.manager = manager
Module.refusal = refusal
Module.state = state

---@class TntSessionOptions
---@field driver string|TntSessionDriver|nil `cache` (по умолчанию), `cookie` либо свой драйвер
---@field cache TntCacheStore|nil Хранилище `tnt-cache` — для драйвера `cache`
---@field cipher TntSessionCipher|nil Шифровальщик `tnt-crypto` — для драйвера `cookie`
---@field name string|nil Имя куки; по умолчанию `tnt_session`
---@field lifetime integer|nil Сколько живёт сессия, секунды; по умолчанию два часа
---@field cookie table|nil Настройки куки `tnt-cookie`: path, domain, secure, same_site

--- Драйвер по имени либо как дан.
---@param opts TntSessionOptions
---@param name string Имя куки: драйверу `cookie` оно же присоединённые данные
---@return TntSessionDriver
local function driver_of(opts, name)
    local declared = opts.driver or 'cache'

    if type(declared) == 'table' then
        return declared
    end

    if declared == 'cache' then
        return cache.new(opts.cache)
    end

    -- Отказ стоит условием, а не последней строкой: бросок помощником
    -- разбор типов концом функции не считает, и функция кончается
    -- возвратом драйвера.
    if declared ~= 'cookie' then
        raise(('сессия: драйвера %s нет, есть cache и cookie'):format(tostring(declared)))
    end

    return cookie.new(opts.cipher, { name = name })
end

--- Заводит менеджер сессий.
---@param opts TntSessionOptions|nil
---@return TntSessionManager
function Module.new(opts)
    opts = opts or {}

    local name = opts.name or manager.DEFAULT_NAME

    return manager.new({
        driver = driver_of(opts, name),
        cookie = cookies.new(opts.cookie),
        name = opts.name,
        lifetime = opts.lifetime,
    })
end

return Module
