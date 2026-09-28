--- Драйвер «сессия в куке»: данные едут у посетителя, зашифрованными.
---
--- Хранилища на узле нет вовсе: любой узел читает куку, выданную любым
--- другим, и во время аварии вход не зависит ни от спейса, ни от
--- репликации. Плата — размер: кука не бесконечна, и сессия в ней
--- держится маленькой.
---
--- Шифровальщик приходит аргументом — это `tnt-crypto`:
--- AES-CBC с меткой HMAC по RFC 7518, смена ключа прежними ключами,
--- присоединённые данные. Своего шифра здесь нет и не будет.
---
---     local cipher = crypto.new({ key = crypto.derive(secret, 'session') })
---     session.new({ driver = 'cookie', cipher = cipher })
---
--- **Подписи мало, нужна шифровка.** В куке лежат сами данные, а не
--- опознаватель: подписанные, они читались бы глазами у посетителя
--- и у всякого, кто видел его экран.
---
--- **Присоединённые данные — имя куки.** Шифровка, перенесённая в чужую
--- куку того же приложения, не расшифруется. Переименовали куку — прежние
--- сессии кончились, и это честно: другое имя значит другое место.
---
--- **Срок лежит внутри шифровки.** `Max-Age` куки решает только браузер,
--- а он у посетителя: кука, отданная обратно через год, без своего срока
--- открывала бы годовалую сессию.
---
--- **Записи о сессии на узле нет, и отозвать её нечем.** Выход гасит куку
--- у того браузера, который пришёл; у остальных сессия доживёт свой срок.
--- Кому нужен отзыв — драйвер `cache`.

local msgpack = require('msgpack')

local clock = require('tnt.clock')
local external = require('tnt.external')

--- Ошибка программиста — словом, без места в коде.
local fail = require('tnt.must.fail').raise

local Module = {}

--- Сколько байт значения куки браузеры принимают наверняка.
---
--- RFC 6265 велит хранить не меньше 4096 байт на куку вместе с именем
--- и атрибутами; запас в сотню байт — на `Path`, `Domain`, `Max-Age`
--- и флаги. Кука сверх предела просто не сохранится, и посетитель молча
--- останется без сессии — поэтому это отказ, а не усечение.
Module.MAX_BYTES = 3900

--- Отказ, когда сессия в куку не влезает.
local TOO_BIG = 'сессия: в куку не влезает — %d байт при пределе %d; '
    .. 'держите в сессии опознаватели, а не данные'

--- Отказ, когда аргументом пришёл не шифровальщик.
local NOT_A_CIPHER =
    'сессия: драйверу cookie нужен шифровальщик tnt-crypto аргументом cipher'

--- Внешнее средство: стенные часы.
---
--- Стенные, а не монотонные: срок кладётся в куку и сверяется тем же
--- узлом или соседним, а у монотонных часов точки отсчёта общей нет.
local source = external.install(Module, { now = clock.realtime })

--- Шифровальщик драйвера — `tnt-crypto`, и договор объявлен его типом.
---
--- Псевдоним, а не свой класс с теми же полями: у шифровальщика `self`
--- в `encrypt` и `decrypt` объявлен его классом, и договор с `self: any`
--- проверка типов считает другим типом. Приложение, передавшее
--- `crypto.new(…)` в настройку `cipher`, получало бы предупреждение
--- и приводило бы тип вручную.
---@alias TntSessionCipher TntCryptoEncrypter

--- Опознаватель живой записи; не та запись либо просроченная — пусто.
---
--- Расшифровать её могли только мы, поэтому сюда доходит либо наша
--- запись, либо запись прежнего вида после обновления: и то, и другое
--- значит «сессии нет», а не отказ.
---@param envelope any
---@return string|nil
local function alive(envelope)
    if type(envelope) ~= 'table' or type(envelope.id) ~= 'string' then
        return nil
    end

    if type(envelope.expires_at) ~= 'number' or envelope.expires_at <= source().now() then
        return nil
    end

    return envelope.id
end

---@class TntSessionCookieOptions
---@field name string Имя куки: оно же присоединённые данные шифровки

--- Заводит драйвер над шифровальщиком.
---
--- Аргумент объявлен `any`: шифровальщик приходит из настроек приложения,
--- и чужое здесь не ошибка типа, а ошибка программиста с внятным словом.
---@param cipher any Шифровальщик `tnt-crypto`
---@param opts TntSessionCookieOptions
---@return TntSessionDriver
function Module.new(cipher, opts)
    if type(cipher) ~= 'table' or type(cipher.encrypt) ~= 'function' or type(cipher.decrypt) ~= 'function' then
        fail(NOT_A_CIPHER)
    end

    local aad = opts.name

    return {
        name = 'cookie',

        open = function(token)
            local text = cipher:decrypt(token, aad)

            if text == nil then
                return nil
            end

            local ok, envelope = pcall(msgpack.decode, text)

            if not ok then
                return nil
            end

            local id = alive(envelope)

            if id == nil then
                return nil
            end

            return id, envelope.payload
        end,

        commit = function(id, payload, ttl)
            local envelope = { id = id, expires_at = source().now() + ttl, payload = payload }
            local token = cipher:encrypt(msgpack.encode(envelope), aad)

            if #token > Module.MAX_BYTES then
                fail(TOO_BIG:format(#token, Module.MAX_BYTES))
            end

            return token
        end,

        -- Записи на узле нет: забывать нечего, куку гасит менеджер.
        close = function() end,
    }
end

return Module
