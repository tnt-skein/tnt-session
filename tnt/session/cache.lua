--- Драйвер на хранилище `tnt-cache`: сессия — запись кэша.
---
--- Своего спейса у сессий нет нарочно. Всё, что для него нужно, —
--- запись со сроком, обход кусками и чистка просроченного — уже написано
--- в `tnt-cache`, и второй такой обход разошёлся бы с первым на первой же
--- поправке. Поэтому «сессии в спейсе» — это хранилище кэша на спейсе,
--- «сессии в Redis» — хранилище кэша на Redis, а драйвер сессий поверх
--- них один:
---
---     -- в памяти процесса: на один узел, до перезапуска
---     cache.new({ driver = 'memory' })
---
---     -- в спейсе: переживает перезапуск, виден репликам
---     -- (шаг миграции: require('tnt.cache.space').migrate(box, 'app_sessions'))
---     cache.new({ driver = 'space', space = 'app_sessions' })
---
---     -- в Redis: одна сессия на все узлы
---     cache.new({ driver = 'redis', redis = client, prefix = 'sess:' })
---
--- Хранилище приходит аргументом, как клиент Redis к самому кэшу: приставка,
--- спейс, срок по умолчанию и договор отказа — его, и заводить их второй
--- раз здесь незачем. Свой `prefix` кэшу сессий задают всегда, когда
--- хранилище общее с обычным кэшем: `flush` кэша чужих приставок
--- не разбирает.
---
--- **Метка из куки — сам опознаватель**, и вид её проверяется до
--- обращения к хранилищу. Кука приходит от клиента: `sid=` дал бы кэшу
--- пустой ключ, а это у него ошибка программиста и бросок посреди живого
--- запроса; ключ с чужими знаками ушёл бы в Redis как есть.
---
--- **Срок ведёт кэш.** Просроченная запись читается как отсутствующая
--- и стирается по дороге; чистит заранее `sweep` хранилища — его зовёт
--- приложение тактом `tnt-loop`, как и для обычного кэша.

--- Ошибка программиста — словом, без места в коде.
local fail = require('tnt.must.fail').raise

local state = require('tnt.session.state')

local Module = {}

--- Заводит драйвер над хранилищем кэша.
---
--- Аргумент объявлен `any`: хранилище приходит из настроек приложения,
--- и чужое здесь не ошибка типа, а ошибка программиста с внятным словом.
---@param store any Хранилище `tnt-cache`
---@return TntSessionDriver
function Module.new(store)
    if type(store) ~= 'table' or type(store.get) ~= 'function' or type(store.driver) ~= 'table' then
        fail('сессия: драйверу cache нужно хранилище tnt-cache')
    end

    return {
        name = 'cache',

        -- Признак берётся у драйвера кэша: сессия в Redis ходит по сети
        -- так же, как кэш в нём, и в транзакции box её не зовут.
        remote = store.driver.remote,

        open = function(token)
            if not state.is_secret(token) then
                return nil
            end

            local payload = store:get(token)

            if type(payload) ~= 'table' then
                return nil
            end

            return token, payload
        end,

        commit = function(id, payload, ttl)
            store:put(id, payload, ttl)

            return id
        end,

        close = function(id)
            store:forget(id)
        end,
    }
end

return Module
