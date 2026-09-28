--- Слой `csrf`: сверка токена от подделки запросов.
---
--- Форма, отправленная посетителю с чужого сайта, приходит к нам с его
--- куками: браузер шлёт куки по адресу, куда идёт запрос, а не по тому,
--- кто его послал. Для узла такой запрос неотличим от своего — если
--- не потребовать того, чего у чужого сайта нет. Это токен сессии: он
--- лежит на странице, а страницу нашего узла чужой сайт прочитать
--- не может.
---
---     middleware.configure({ layers = { csrf = session.csrf.new } })
---     -- { 'csrf', { except = { '/hooks' } } }
---
---     router.new({ entry = { sessions:layer(), session.csrf.new({ except = { '/hooks' } }) } })
---
--- **Слой живёт здесь, а не в `tnt-middleware`.** Сверять он умеет ровно
--- одно — токен сессии, — а сессию берёт из запроса по договору слоя
--- `session`. Встав готовым слоем конвейера, он принёс бы конвейеру
--- знание о сессии, о поле формы и о заголовке разом, а конвейер
--- о виде запроса не знает намеренно. Объявляется он фабрикой в реестре —
--- как ограничитель частоты, сжатие и права.
---
--- **Спрашивается токен только у способов, меняющих состояние** — POST,
--- PUT, PATCH, DELETE. GET, HEAD и OPTIONS по RFC 9110 (§9.2.1) ничего
--- не меняют, и токен у них значил бы токен у всякой ссылки.
---
--- **Ищется он в поле формы, потом в заголовке.** Форма браузера несёт
--- его полем `_token` (директива `@csrf` в `tnt-template`), запрос
--- из сценария — заголовком `x-csrf-token` (метка `@csrf_meta`). Сперва
--- форма: браузер шлёт её сам, а заголовок ставит только сценарий.
--- В строке запроса токен не ищется вовсе: адрес уезжает в журналы
--- доступа посредников и в заголовок `Referer` чужой страницы, и токен
--- из него утёк бы туда же.
---
--- **Сравнение — за постоянное время** (`tnt-hash`): сравнение, выходящее
--- на первом несовпавшем байте, отвечает не «сошлось ли», а «сколько
--- сошлось», и по времени ответа токен подбирается побайтно.
---
--- **Отказ — 403, а не 419.** 419 нет в перечне IANA: посредник, кэш
--- и клиент обязаны считать незнакомый код обобщённым `400` (RFC 9110,
--- §15), и отличать «страница устарела» от «запрос кривой» станет нечем.
--- 403 в перечне есть и значит ровно то, что случилось: запрос понят,
--- но выполнен не будет (§15.5.4). Что именно стряслось, говорят код
--- отказа (`session_token_mismatch`) и его причина — по ним приложение
--- и рисует «страница устарела, откройте её заново».
---
--- **Токена нет ни в отказе, ни в журнале.** Записи читают глазами, возят
--- в сборщик и держат неделями, и одной строки с токеном хватило бы, чтобы
--- подделать запрос от имени посетителя, пока жива его сессия. Поэтому
--- в причине отказа названы поле и заголовок, но не их содержимое.
--- Своей записи слой не пишет: об отклонённом запросе пишет тот, кто
--- отвечает отказом, — роутер делает это всегда («запрос отклонён»
--- со способом, путём и причиной, `tnt-router`), в цепочке без
--- роутера — перехват `rescue`. Вторая запись о том же запросе повторяла
--- бы первую слово в слово, а разойдясь — заставила бы гадать, какая
--- из них правда.
---
--- **Освобождённые адреса — список в настройке `except`.** Сессии там
--- быть не должно вовсе: освобождённый адрес не защищён ничем, и если
--- он меняет состояние от имени посетителя, дыра ровно та же, от которой
--- слой и поставлен. Годный случай один — приём от чужой службы (вебхук):
--- такой запрос подписан самой службой, подпись проверяет обработчик,
--- а о посетителе он не знает вовсе.

local must = require('tnt.must')

--- Ошибка программиста — словом, без места в коде: текст сверяется
--- целиком, как у соседних частей пакета.
local fail = require('tnt.must.fail').raise

local compare = require('tnt.hash.compare')

local layer = require('tnt.session.layer')
local refusal = require('tnt.session.refusal')

local Module = {}

--- Способы, у которых токен спрашивают, если не сказано иного.
Module.METHODS = { 'POST', 'PUT', 'PATCH', 'DELETE' }

--- Поле формы с токеном; то же имя пишет директива `@csrf`.
Module.FIELD = '_token'

--- Заголовок с токеном — для запросов из сценариев.
Module.HEADER = 'x-csrf-token'

--- Отказ, когда запрос не подтверждён токеном.
Module.STATUS = 403
Module.MESSAGE = 'запрос не подтверждён токеном'
Module.CODE = 'session_token_mismatch'

--- Чем отказывает слой.
local MISMATCH = {
    status = Module.STATUS,
    message = Module.MESSAGE,
    code = Module.CODE,
}

--- Почему не пустили: токена не прислали вовсе.
local NO_TOKEN = 'токена нет: ни поля «%s» формы, ни заголовка «%s»'

--- Почему не пустили: прислали не тот.
---
--- «Страница устарела» — самая частая причина несовпадения: токен меняется
--- при входе и выходе, а сессия кончается по сроку, и открытая вчера
--- вкладка шлёт вчерашний токен.
local NO_MATCH =
    'токен не совпал с токеном сессии: страница устарела — откройте её заново'

--- Бросок: слой стоит без слоя сессии.
local NO_SESSION =
    'сверка токена: в запросе нет поля «%s» — слой csrf ставят после слоя session'

--- Бросок: освобождён весь узел.
local ALL_EXEMPT = 'сверка токена: освободить «/» — значит снять сверку со всего узла; '
    .. 'тогда снимайте и слой, иначе он только кажется защитой'

--- Бросок: список способов пуст.
local NO_METHODS = 'сверка токена: methods — непустой список способов; '
    .. 'пустой значит «не спрашивать ни у кого», и слой только кажется защитой'

--- Бросок: адрес в списке освобождённых — не начало пути.
local NOT_A_PATH =
    'сверка токена: освобождённый адрес — начало пути с косой черты, а не «%s»'

--- Знаки образца Lua, которых в начале пути не бывает.
---
--- Образец здесь не принимается по той же причине, что и в фильтре слоя
--- (`tnt-middleware`): `.` в `/v1.0` значил бы «любой знак», и адрес,
--- освобождённый шире задуманного, остался бы без сверки — а это ровно
--- та дыра, от которой слой и поставлен.
local PATTERN_MARKS = '[%*%?%^%$]'

--- Описание настроек слоя.
---
--- `tag` здесь потому, что реестр `tnt-middleware` кладёт свою метку
--- журнала в настройки каждого слоя; слою она не нужна — своих записей
--- он не пишет.
local OPTIONS = {
    field = '?not_empty',
    header = '?not_empty',
    session = '?not_empty',
    methods = { '?array_of', 'not_empty' },
    except = { '?array_of', 'not_empty' },
    tag = '?string',
}

---@class TntSessionCsrfOptions
---@field field string|nil Поле формы с токеном; по умолчанию `_token`
---@field header string|nil Заголовок с токеном; по умолчанию `x-csrf-token`
---@field session string|nil Поле запроса с сессией; по умолчанию `session`
---@field methods string[]|nil Способы, у которых спрашивают токен; по умолчанию POST, PUT, PATCH, DELETE
---@field except string[]|nil Освобождённые адреса: начало пути по участкам
---@field tag string|nil Метка журнала; её кладёт реестр `tnt-middleware`, слою она не нужна

--- Способы, у которых спрашивают токен, множеством заглавными.
---
--- Пустой список — не «у всех» и не «у никого по недосмотру», а опечатка:
--- слой с ним стоял бы в цепочке, ничего не сверяя, и выглядел бы защитой.
---@param listed string[]
---@return table<string, boolean>
local function methods_of(listed)
    if listed[1] == nil then
        fail(NO_METHODS)
    end

    local asked = {}

    for _, name in ipairs(listed) do
        asked[name:upper()] = true
    end

    return asked
end

--- Освобождённые адреса: начало пути без хвостовой косой черты.
---
--- Черта снимается, чтобы `/hooks` и `/hooks/` значили одно: сам адрес
--- и всё под ним.
---@param listed string[]
---@return string[]
local function exempted_of(listed)
    local subtrees = {}

    for _, path in ipairs(listed) do
        if path == '/' then
            fail(ALL_EXEMPT)
        end

        if not path:startswith('/') or path:find(PATTERN_MARKS) ~= nil then
            fail(NOT_A_PATH:format(path))
        end

        table.insert(subtrees, (path:gsub('/$', '')))
    end

    return subtrees
end

--- Начало пути, которое освобождает этот адрес; пусто — не освобождён.
---
--- Не «да или нет», а само начало: `false` и `nil` в Lua неотличимы
--- под `if`, и проверка «здесь сверяем, а здесь нет» выглядела бы
--- проверенной, не будучи ею. Найденное начало сверяется с `nil` явно.
---
--- Путь не строкой — не освобождён: запрос без пути пришёл не из HTTP,
--- и судить о нём по списку адресов нечем.
---@param path any
---@param subtrees string[]
---@return string|nil
local function exemption_of(path, subtrees)
    if type(path) ~= 'string' then
        return nil
    end

    for _, prefix in ipairs(subtrees) do
        if path == prefix or path:startswith(prefix .. '/') then
            return prefix
        end
    end

    return nil
end

--- Значение поля таблицы, которой может не быть вовсе.
---@param source any
---@param name string
---@return any
local function field_of(source, name)
    if type(source) ~= 'table' then
        return nil
    end

    return source[name]
end

--- Собирает слой.
---
--- Негодные настройки — бросок при сборке, на строку того, кто собирает:
--- опечатка в освобождённом адресе обязана найтись при объявлении цепочки,
--- а не на первом запросе — и уж точно не тем, что дыра осталась открытой.
---@param options TntSessionCsrfOptions|nil
---@return fun(request: any, next_layer: fun(request: any): any, any): any, any
function Module.new(options)
    local settings = options or {}

    must.at(2).options(settings, 'настройки слоя', OPTIONS)

    local field = settings.field or Module.FIELD

    -- Имя заголовка — к нижнему регистру: в запросе их приводит роутер,
    -- а по RFC 9110 (§5.1) имя заголовка регистра не различает. Без этого
    -- настройка `X-CSRF-Token` не нашла бы ничего и отказывала бы всем
    -- запросам из сценариев.
    local header = (settings.header or Module.HEADER):lower()
    local carrier = settings.session or layer.FIELD
    local asked = methods_of(settings.methods or Module.METHODS)
    local subtrees = exempted_of(settings.except or {})

    -- Текст собирается один раз: имена полей заданы настройкой и от
    -- запроса к запросу не меняются.
    local missing = NO_TOKEN:format(field, header)

    --- Почему запрос не подтверждён; пусто — подтверждён.
    ---@param session TntSession
    ---@param request table
    ---@return string|nil
    local function refused_because(session, request)
        local given = field_of(request.form, field)

        if given == nil then
            given = field_of(request.headers, header)
        end

        if given == nil then
            return missing
        end

        -- Токен сессии берётся полем, а не `session:token()`: тот завёл бы
        -- его при первом обращении, и подделанный запрос к сессии без
        -- токена сравнивался бы со свежевыданным — то есть заводил бы
        -- запись в хранилище и куку тому, кого мы не пустили.
        if session.secret == nil or not compare.equals(session.secret, given) then
            return NO_MATCH
        end

        return nil
    end

    return function(request, next_layer)
        -- Контекст не запрос — спрашивать токен не у кого: способа у него
        -- нет, а конвейер один и тот же для запроса к узлу и для сообщения
        -- очереди.
        if type(request) ~= 'table' or type(request.method) ~= 'string' then
            return next_layer(request)
        end

        if not asked[request.method:upper()] or exemption_of(request.path, subtrees) ~= nil then
            return next_layer(request)
        end

        local session = request[carrier]

        -- Слой без сессии сверять нечем, и молчаливый отказ выглядел бы
        -- как обычная работа: цепочка, собранная без слоя `session`, —
        -- ошибка программиста, и находиться она должна шумно.
        if type(session) ~= 'table' then
            fail(NO_SESSION:format(carrier))
        end

        local reason = refused_because(session, request)

        if reason == nil then
            return next_layer(request)
        end

        return nil, refusal.of(MISMATCH, reason)
    end
end

return Module
