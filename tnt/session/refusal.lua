--- Отказ слоя по договору границы HTTP: статус, слово, код и причина.
---
--- Слоёв, отвечающих отказом, у пакета два — сессия (`layer`) и сверка
--- токена (`csrf`), — и собран отказ в одном месте нарочно: два места
--- разошлись бы полями, а договор границы у них один
--- (`docs/session.md`, «Договор отказа»).
---
--- Вид ответа рисует роутер, `tnt-error` либо каталог приложения — слою
--- это не по чину, и каталога кодов пакет не заводит.

local Module = {}

--- Отказ строкой — для журнала.
---
--- Роутер и перехват пишут отказ `tostring`, и таблица без этого ушла бы
--- в запись как `table: 0x…`.
local REFUSAL = {
    __tostring = function(refusal)
        return ('%s: %s'):format(refusal.message, refusal.reason)
    end,
}

---@class TntSessionRefusalKind Чем отказывает слой
---@field status integer Код ответа
---@field message string Слово, которое увидит человек
---@field code string Имя рода отказа — по нему его находят в каталоге

--- Собирает отказ.
---@param kind TntSessionRefusalKind
---@param reason any Почему отказали; в тексте не бывает ни токена, ни метки
---@return table
function Module.of(kind, reason)
    return setmetatable({
        status = kind.status,
        message = kind.message,
        code = kind.code,
        reason = tostring(reason),
    }, REFUSAL)
end

return Module
