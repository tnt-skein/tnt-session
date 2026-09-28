--- Проверки слоя `csrf`: у кого спрашивают токен, чем он приходит,
--- что бывает при несовпадении и что уходит наружу вместе с отказом.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local csrf = helper.csrf
local state = helper.state

local g = t.group('tnt.session.csrf')

--- 32 байта, из которых выходит токен сессии.
local SECRET = ('t'):rep(32)

--- Токен в том виде, в каком его получает страница.
local TOKEN = helper.secret_of(SECRET)

--- Чужой токен: такой же длины, той же азбуки, но не наш.
local FOREIGN = helper.secret_of(('f'):rep(32))

g.before_each(function()
    helper.pin_secrets(SECRET)
end)

g.after_each(function()
    helper.restore()
end)

--- Сессия с уже выданным токеном.
---@return TntSession
local function session_with_token()
    local session = state.new('id')

    session:token()

    return session
end

--- Запрос, как его собирает роутер.
---@param fields table|nil Поля запроса поверх обычных
---@return table
local function request_with(fields)
    local request = { method = 'POST', path = '/customers', session = session_with_token() }

    for name, value in pairs(fields or {}) do
        request[name] = value
    end

    return request
end

--- Обработчик, который помнит, звали ли его.
---@return fun(request: any): table
---@return table seen Поле `called` — звали ли
local function handler()
    local seen = {}

    return function(request)
        seen.called = true
        seen.request = request

        return { status = 200, body = 'ok' }
    end,
        seen
end

--- Проводит запрос через слой.
---@param request any
---@param options table|nil Настройки слоя
---@return any response
---@return any err
---@return table seen
local function through(request, options)
    local act, seen = handler()
    local response, err = csrf.new(options)(request, act)

    return response, err, seen
end

-- ── Что проходит ─────────────────────────────────────────────────────

g.test_a_form_with_the_token_passes = function()
    local response, err, seen = through(request_with({ form = { _token = TOKEN } }))

    t.assert_equals({ response, err }, { { status = 200, body = 'ok' }, nil })
    t.assert_equals(seen.called, true)
end

g.test_a_script_passes_the_token_in_the_header = function()
    local response = through(request_with({ headers = { ['x-csrf-token'] = TOKEN } }))

    t.assert_equals(response, { status = 200, body = 'ok' })
end

-- Способ читается без учёта регистра: способ пишет клиент, и `post`
-- от него — тот же POST.
g.test_the_method_is_read_without_case = function()
    local _, err = through(request_with({ method = 'post' }))

    t.assert_equals(err.status, 403)
end

g.test_reading_methods_are_not_asked_for_a_token = function()
    for _, method in ipairs({ 'GET', 'HEAD', 'OPTIONS' }) do
        local response, err, seen = through(request_with({ method = method }))

        t.assert_equals({ response, err }, { { status = 200, body = 'ok' }, nil })
        t.assert_equals(seen.called, true)
    end
end

g.test_the_asked_methods_are_named_by_the_settings = function()
    local response = through(request_with({ method = 'PUT' }), { methods = { 'POST' } })

    t.assert_equals(response, { status = 200, body = 'ok' })
    t.assert_equals(select(2, through(request_with({}), { methods = { 'POST' } })).status, 403)
end

-- Контекст конвейеру непрозрачен: слой, поставленный в цепочку очереди,
-- ничего не сверяет, а не роняет сообщение.
g.test_a_context_that_is_not_a_request_passes_untouched = function()
    for _, context in ipairs({ 'строка', { path = '/customers' }, { method = 7 } }) do
        local response, err, seen = through(context)

        t.assert_equals({ response, err }, { { status = 200, body = 'ok' }, nil })
        t.assert_equals(seen.called, true)
    end
end

-- ── Что не проходит ──────────────────────────────────────────────────

g.test_a_form_without_a_token_is_refused = function()
    local response, err, seen = through(request_with({}))

    t.assert_equals(response, nil)
    t.assert_equals(err, {
        status = 403,
        message = 'запрос не подтверждён токеном',
        code = 'session_token_mismatch',
        reason = 'токена нет: ни поля «_token» формы, ни заголовка «x-csrf-token»',
    })
    t.assert_equals(
        tostring(err),
        'запрос не подтверждён токеном: токена нет: ни поля «_token» формы, ни заголовка «x-csrf-token»'
    )
    -- Обработчика не звали вовсе: подделанный запрос не должен дойти
    -- до дела ни в каком виде.
    t.assert_equals(seen.called, nil)
end

g.test_a_foreign_token_is_refused = function()
    local _, err = through(request_with({ form = { _token = FOREIGN } }))

    t.assert_equals(
        err.reason,
        'токен не совпал с токеном сессии: страница устарела — откройте её заново'
    )
end

-- Длина не скрывается: она видна и так, а огрызок токена — не «почти
-- сошлось», а другой токен.
g.test_a_prefix_of_the_token_is_refused = function()
    local _, err = through(request_with({ form = { _token = TOKEN:sub(1, 10) } }))

    t.assert_equals(err.status, 403)
end

-- Повторённое имя поля роутер собирает в список: список — не токен.
g.test_a_repeated_field_is_refused = function()
    local _, err = through(request_with({ form = { _token = { TOKEN, TOKEN } } }))

    t.assert_equals(err.status, 403)
end

-- Сессия без токена — та, что завелась заново: срок вышел, был выход
-- либо куку не приняли. Страница, с которой пришли, устарела.
g.test_a_session_without_a_token_refuses_and_stays_without_one = function()
    local session = state.new('id')
    local _, err = through(request_with({ session = session, form = { _token = TOKEN } }))

    t.assert_equals(err.status, 403)
    -- Токен не заводится сверкой: иначе отклонённый запрос оставлял бы
    -- запись в хранилище и куку у того, кого не пустили.
    t.assert_equals({ session.secret, session.dirty }, { nil, false })
end

-- ── Чем сравнивается ─────────────────────────────────────────────────

--- Проводит `fn`, подменив сравнение `tnt-hash` двойником.
---
--- Двойник помнит, что с чем сравнивали, и отвечает данным приговором.
--- Настоящее сравнение возвращается и тогда, когда `fn` упала: иначе
--- двойник достался бы соседним проверкам.
---@param verdict boolean Чем отвечает двойник
---@param fn fun()
---@return table[] compared Пары «известное, присланное» по порядку
local function comparing(verdict, fn)
    local real = helper.compare.equals
    local compared = {}

    helper.compare.equals = function(known, given)
        table.insert(compared, { known, given })

        return verdict
    end

    local ok, err = pcall(fn)

    helper.compare.equals = real

    if not ok then
        error(err, 0)
    end

    return compared
end

-- Токен сверяется сравнением `tnt-hash` за постоянное время, а не `==`:
-- постоянного времени у `==` никто не обещает (`docs/session.md`, «Что
-- сделано ради безопасности»). Ответом этого не видно — совпадение оба
-- сравнения признают одинаково, — и отличает их только двойник: признав
-- чужой токен, он пропускает запрос, отвергнув свой — останавливает,
-- то есть приговор слой берёт у `tnt-hash` целиком.
--
-- Известное идёт первым: строку `tnt-hash` требует только от него,
-- а присланное приходит снаружи чем угодно, и список из повторённого поля
-- на первом месте был бы броском вместо отказа.
g.test_the_token_is_compared_in_constant_time = function()
    local passed
    local compared = comparing(true, function()
        passed = through(request_with({ form = { _token = FOREIGN } }))
    end)

    t.assert_equals(passed, { status = 200, body = 'ok' })
    t.assert_equals(compared, { { TOKEN, FOREIGN } })

    local response, err
    compared = comparing(false, function()
        response, err = through(request_with({ form = { _token = TOKEN } }))
    end)

    t.assert_equals(response, nil)
    t.assert_equals(
        tostring(err),
        'запрос не подтверждён токеном: токен не совпал с токеном сессии: '
            .. 'страница устарела — откройте её заново'
    )
    t.assert_equals(compared, { { TOKEN, TOKEN } })
end

-- ── Где ищется токен ─────────────────────────────────────────────────

-- Имена — договор с разметкой страницы: поле `_token` пишет директива
-- `@csrf`, а заголовок `x-csrf-token` шлёт сценарий, взяв токен из метки
-- `csrf-token` (`@csrf_meta`). Объявлены они дважды — здесь и в пакете
-- шаблонов, — потому что пакеты друг от друга не зависят; разойдутся —
-- форма перестанет проходить, и заметить это нечем, кроме этой сверки
-- и такой же в проверках шаблонов.
g.test_the_names_are_the_contract_with_the_page = function()
    t.assert_equals({ csrf.FIELD, csrf.HEADER }, { '_token', 'x-csrf-token' })
end

g.test_the_form_field_is_read_before_the_header = function()
    local right = through(request_with({
        form = { _token = TOKEN },
        headers = { ['x-csrf-token'] = FOREIGN },
    }))

    t.assert_equals(right, { status = 200, body = 'ok' })

    -- Обратный случай: в форме чужой, в заголовке наш — заголовок
    -- до дела не доходит.
    local _, err = through(request_with({
        form = { _token = FOREIGN },
        headers = { ['x-csrf-token'] = TOKEN },
    }))

    t.assert_equals(err.status, 403)
end

-- Имя заголовка регистра не различает, а в запросе их приводит к нижнему
-- роутер: настройка заглавными обязана найти тот же заголовок, иначе она
-- отказывала бы всем запросам из сценариев.
g.test_the_header_name_is_read_without_case = function()
    t.assert_equals(
        through(request_with({ headers = { ['x-token'] = TOKEN } }), { header = 'X-Token' }),
        { status = 200, body = 'ok' }
    )
end

g.test_the_names_of_the_field_and_the_header_are_settings = function()
    local options = { field = 'authenticity', header = 'x-token' }

    t.assert_equals(through(request_with({ form = { authenticity = TOKEN } }), options), { status = 200, body = 'ok' })
    t.assert_equals(
        through(request_with({ headers = { ['x-token'] = TOKEN } }), options),
        { status = 200, body = 'ok' }
    )
    t.assert_equals(
        select(2, through(request_with({ form = { _token = TOKEN } }), options)).reason,
        'токена нет: ни поля «authenticity» формы, ни заголовка «x-token»'
    )
end

g.test_the_session_field_of_the_request_is_a_setting = function()
    local request = request_with({ form = { _token = TOKEN } })

    request.visitor = request.session
    request.session = nil

    t.assert_equals(through(request, { session = 'visitor' }), { status = 200, body = 'ok' })
end

-- ── Освобождённые адреса ─────────────────────────────────────────────

g.test_an_exempt_path_covers_itself_and_everything_under_it = function()
    local options = { except = { '/hooks' } }

    for _, path in ipairs({ '/hooks', '/hooks/', '/hooks/bank/paid' }) do
        t.assert_equals(through(request_with({ path = path }), options), { status = 200, body = 'ok' }, path)
    end

    -- Сосед по буквам — не участок под адресом.
    for _, path in ipairs({ '/hooksx', '/api/hooks' }) do
        t.assert_equals(select(2, through(request_with({ path = path }), options)).status, 403, path)
    end
end

-- Запрос без пути пришёл не из HTTP, и судить о нём по списку адресов
-- нечем: освобождённым он не считается, а токен с него спрашивается,
-- как со всякого меняющего состояние.
g.test_a_request_without_a_path_is_not_exempt = function()
    local options = { except = { '/hooks' } }
    local passing = request_with({ form = { _token = TOKEN } })
    local refused = request_with({})

    passing.path = nil
    refused.path = nil

    t.assert_equals(through(passing, options), { status = 200, body = 'ok' })
    t.assert_equals(select(2, through(refused, options)).status, 403)
end

g.test_a_trailing_slash_in_the_exempt_path_means_the_same = function()
    t.assert_equals(
        through(request_with({ path = '/hooks/bank' }), { except = { '/hooks/' } }),
        { status = 200, body = 'ok' }
    )
end

-- Пустой список способов — та же беда, что освобождённый корень: слой
-- стоит, а не сверяет ничего.
g.test_an_empty_list_of_methods_is_refused = function()
    helper.assert_raised(
        function()
            csrf.new({ methods = {} })
        end,
        'сверка токена: methods — непустой список способов; '
            .. 'пустой значит «не спрашивать ни у кого», и слой только кажется защитой'
    )
end

g.test_exempting_the_whole_node_is_refused = function()
    helper.assert_raised(
        function()
            csrf.new({ except = { '/hooks', '/' } })
        end,
        'сверка токена: освободить «/» — значит снять сверку со всего узла; '
            .. 'тогда снимайте и слой, иначе он только кажется защитой'
    )
end

g.test_an_exempt_path_is_a_path_and_not_a_pattern = function()
    for _, given in ipairs({ 'hooks', '/api/.*', '/api/^v1', '/api/v1$', '/api/?' }) do
        helper.assert_raised(
            function()
                csrf.new({ except = { given } })
            end,
            ('сверка токена: освобождённый адрес — начало пути с косой черты, а не «%s»'):format(
                given
            )
        )
    end
end

-- ── Токен не уходит наружу ───────────────────────────────────────────

-- Отказ доезжает и до ответа, и до журнала — его пишет тот, кто отвечает
-- отказом. Токена в нём нет ни своего, ни присланного: записи читают
-- глазами и возят в сборщик, и одной такой строки хватило бы на подделку.
g.test_neither_token_leaks_into_the_refusal = function()
    for _, given in ipairs({ FOREIGN, TOKEN:sub(1, 10), 'что-то своё' }) do
        local _, err = through(request_with({ form = { _token = given } }))
        local whole = ('%s %s %s %s'):format(err.message, err.code, err.reason, tostring(err))

        t.assert_equals(whole:find(TOKEN, nil, true), nil)
        t.assert_equals(whole:find(given, nil, true), nil)
    end
end

-- Метку журнала реестр кладёт в настройки каждого слоя, и слой обязан
-- её принять, хотя своих записей не пишет.
g.test_the_registry_tag_is_accepted_and_changes_nothing = function()
    t.assert_equals(
        through(request_with({ form = { _token = TOKEN } }), { tag = 'app.web' }),
        { status = 200, body = 'ok' }
    )
end

-- ── Ошибки того, кто собирает цепочку ────────────────────────────────

-- Слою без сессии сверять нечем, и молчать об этом нельзя: цепочка,
-- собранная без слоя `session`, пропускала бы подделку «на законных
-- основаниях».
g.test_a_chain_without_the_session_layer_is_a_programmer_error = function()
    local request = request_with({ form = { _token = TOKEN } })

    request.session = nil

    helper.assert_raised(
        function()
            csrf.new()(request, handler())
        end,
        'сверка токена: в запросе нет поля «session» — слой csrf ставят после слоя session'
    )
end

g.test_bad_settings_are_a_programmer_error_at_build_time = function()
    helper.assert_blamed({
        {
            function()
                csrf.new({ excepts = { '/hooks' } })
            end,
            'настройки слоя: ключа «excepts» нет, есть except, field, header, methods, session, tag',
        },
        {
            function()
                csrf.new({ field = '' })
            end,
            'настройки слоя.field — непустая строка, а не пустая',
        },
        {
            function()
                csrf.new({ methods = { 7 } })
            end,
            'настройки слоя.methods[1] — непустая строка, а не число',
        },
        {
            function()
                csrf.new({ except = '/hooks' })
            end,
            'настройки слоя.except — массив, а не строка',
        },
    })
end
