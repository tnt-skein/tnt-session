--- Сессия: данные одного посетителя между запросами.
---
--- Значение по ключу, одноразовые значения (`flash`) и токен от подделки
--- запросов. Где данные лежат и как они доезжают до следующего запроса,
--- сессия не знает — это дело драйвера и менеджера (`tnt.session.manager`).
---
---     session:put('cart', { 7, 9 })
---     session:get('cart', {})
---     session:flash('notice', 'Сохранено')   -- видно ровно один запрос
---     session:keep()                          -- продлить одноразовые ещё на запрос
---     session:token()                         -- токен от подделки запросов
---
--- **Одноразовых списков два.** `stale` — то, что пришло одноразовым
--- и живёт этот запрос последний раз; `flashed` — то, что положено
--- одноразовым сейчас и будет видно в следующем запросе. `keep`
--- переносит имена из первого во второй, а `payload` не берёт с собой
--- оставшееся в первом. Один список не разделил бы «уже показано»
--- и «показать в следующий раз», и сообщение либо жило бы вечно, либо
--- пропадало до показа.
---
--- **Токен лежит отдельно от данных.** В данных он оказался бы и в `all`,
--- и под `forget`, и приложение, вычистившее свою корзину `flush`,
--- вместе с ней выкинуло бы защиту от подделки запросов. Заводится он
--- при первом обращении: сессии, которой токен не нужен, лишняя тайна
--- ни к чему.
---
--- **Опознаватель — случайные байты, а не ULID.** Он даёт силу пропуска:
--- кто его узнал, тот и вошёл. `tnt-id` для такого не годится —
--- время в старших битах сужает перебор (RFC 9562, раздел 8), — поэтому
--- и опознаватель, и токен берутся у `digest.urandom` (`tnt.session.state.secret`).

local digest = require('digest')

local external = require('tnt.external')

--- Ошибка программиста — словом, без места в коде: текст сверяется
--- целиком, как у соседних пакетов.
local fail = require('tnt.must.fail').raise

local Module = {}

--- Сколько байт случайности в опознавателе и в токене.
---
--- 32 байта — 256 бит: перебрать такой опознаватель нельзя, а он и есть
--- пропуск в чужую сессию.
Module.SECRET_BYTES = 32

--- Сколько знаков в записи тайны: base64url без набивки.
Module.SECRET_LENGTH = math.ceil(Module.SECRET_BYTES * 4 / 3)

--- Внешнее средство: случайные байты.
---
--- Через внешнюю зависимость затем, чтобы проверки сверяли опознаватель дословно:
--- у случайного опознавателя проверить можно только его вид.
local source = external.install(Module, { random = digest.urandom })

---@class TntSession Сессия одного посетителя
---@field id string Опознаватель: он же метка в куке у серверных драйверов
---@field values table<string, any> Данные
---@field stale table<string, boolean> Одноразовые, живущие этот запрос последний раз
---@field flashed table<string, string> Одноразовые на следующий запрос: имя → оно же
---@field secret string|nil Токен от подделки запросов; заводится по требованию
---@field dirty boolean Менялось ли что-нибудь за этот запрос
---@field stored boolean Пришла ли сессия из хранилища
local Session = {}
Session.__index = Session

--- Свежая тайна: случайные байты в base64url.
---
--- Алфавит адресов: тайна ложится в куку и в ключ хранилища без
--- экранирования, а набивку `=` куке нести незачем.
---@return string
function Module.secret()
    return digest.base64_encode(source().random(Module.SECRET_BYTES), { urlsafe = true })
end

--- Похоже ли значение на нашу тайну.
---
--- Спрашивает драйвер о метке из куки: метка приходит от клиента,
--- и негодная не должна доходить до хранилища — ни ключом с чужими
--- знаками, ни пустой строкой.
---@param value any
---@return boolean
function Module.is_secret(value)
    if type(value) ~= 'string' or #value ~= Module.SECRET_LENGTH then
        return false
    end

    -- Не «совпадает с образцом», а «чужого знака нет»: у образца
    -- `^[%w_-]+$` мутанты `*` и `-` при уже проверенной длине неотличимы,
    -- и строка выглядела бы проверенной, не будучи ею.
    return value:find('[^%w_-]') == nil
end

--- Ключ сессии: непустая строка и ничего другого.
---@param key any
---@return string
local function keyed(key)
    if type(key) ~= 'string' or key == '' then
        fail('сессия: ключ должен быть непустой строкой')
    end

    return key
end

--- Значение, которое можно положить: пустое кладут через `forget`.
---@param value any
local function present(value)
    if value == nil then
        fail('сессия: пустое значение не кладут, для удаления есть forget')
    end
end

--- Помечает сессию изменённой и снимает с ключа одноразовость.
---@param session TntSession
---@param name string
local function touched(session, name)
    session.stale[name] = nil
    session.flashed[name] = nil
    session.dirty = true
end

--- Значение по ключу либо умолчание.
---@param key string
---@param default any
---@return any
function Session:get(key, default)
    local value = self.values[keyed(key)]

    if value == nil then
        return default
    end

    return value
end

--- Есть ли значение по ключу.
---@param key string
---@return boolean
function Session:has(key)
    return self.values[keyed(key)] ~= nil
end

--- Все данные копией.
---
--- Копией, а не самой таблицей: правка отданной наружу таблицы прошла бы
--- мимо `dirty`, и менеджер не сохранил бы её.
---@return table<string, any>
function Session:all()
    local copy = {}

    for name, value in pairs(self.values) do
        copy[name] = value
    end

    return copy
end

--- Кладёт значение.
---@param key string
---@param value any
function Session:put(key, value)
    present(value)

    local name = keyed(key)

    self.values[name] = value
    touched(self, name)
end

--- Кладёт значение на один следующий запрос.
---
--- Видно оно и сейчас — так пишут сообщение перед перенаправлением
--- и читают его же в том обработчике, который его положил.
---@param key string
---@param value any
function Session:flash(key, value)
    present(value)

    local name = keyed(key)

    self.values[name] = value
    touched(self, name)

    -- Значением ложится само имя: список одноразовых `payload` собирает
    -- значениями, а не ключами, и подмена значения видна проверке.
    self.flashed[name] = name
end

--- Стирает значение.
---@param key string
function Session:forget(key)
    local name = keyed(key)

    self.values[name] = nil
    touched(self, name)
end

--- Стирает все данные; токен остаётся.
function Session:flush()
    self.values = {}
    self.stale = {}
    self.flashed = {}
    self.dirty = true
end

--- Значение по ключу с удалением.
---@param key string
---@param default any
---@return any
function Session:pull(key, default)
    local name = keyed(key)
    local value = self.values[name]

    if value == nil then
        return default
    end

    self:forget(name)

    return value
end

--- Продлевает одноразовые значения ещё на один запрос.
---@param keys string[]|nil Имена; пусто — все, что пришли одноразовыми
function Session:keep(keys)
    local names = keys

    if names == nil then
        names = {}

        for name in pairs(self.stale) do
            table.insert(names, name)
        end
    end

    for _, name in ipairs(names) do
        local key = keyed(name)

        self.flashed[key] = key
        self.stale[key] = nil
    end

    self.dirty = true
end

--- Токен от подделки запросов; заводится при первом обращении.
---@return string
function Session:token()
    if self.secret == nil then
        self.secret = Module.secret()
        self.dirty = true
    end

    return self.secret
end

--- Заводит пустую сессию с данным опознавателем.
---@param id string
---@return TntSession
function Module.new(id)
    return setmetatable({
        id = id,
        values = {},
        stale = {},
        flashed = {},
        dirty = false,
        stored = false,
    }, Session)
end

--- Сессия из того, что отдал драйвер.
---
--- Запись не той породы — чужой ключ в общем Redis, старый вид записи —
--- сессией не считается: пусто, и менеджер заведёт новую. Разбирать
--- её по полю нельзя: половина чужой записи, принятая за свою, дала бы
--- посетителю чужие данные.
---@param id string
---@param payload any Что лежало у драйвера
---@return TntSession|nil
function Module.restore(id, payload)
    if type(payload) ~= 'table' or type(payload.values) ~= 'table' then
        return nil
    end

    local session = Module.new(id)

    session.stored = true
    session.values = payload.values

    if type(payload.token) == 'string' then
        session.secret = payload.token
    end

    for _, name in ipairs(type(payload.flash) == 'table' and payload.flash or {}) do
        session.stale[name] = true
    end

    return session
end

--- Что уходит драйверу.
---
--- Одноразовые, пришедшие из прошлого запроса и не продлённые `keep`,
--- сюда не попадают: этот запрос был у них последним. Имена одноразовых
--- отдаются по порядку — одна и та же сессия даёт одну и ту же запись,
--- и сверить её целиком можно строкой.
---@param session TntSession
---@return table
function Module.payload(session)
    local values = {}

    for name, value in pairs(session.values) do
        if not session.stale[name] then
            values[name] = value
        end
    end

    local flash = {}

    for _, name in pairs(session.flashed) do
        table.insert(flash, name)
    end

    table.sort(flash)

    return { values = values, flash = flash, token = session.secret }
end

--- Пуста ли сессия: ни данных, ни токена.
---
--- По этому признаку менеджер решает, заводить ли запись в хранилище
--- и ставить ли куку: иначе каждый обход робота оставлял бы запись,
--- которую никто не прочитает.
---@param session TntSession
---@return boolean
function Module.empty(session)
    if session.secret ~= nil then
        return false
    end

    return next(session.values) == nil
end

return Module
