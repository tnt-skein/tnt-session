--- Проверки слоя `session`: сессия в запросе, кука в ответе, отказ 503
--- и чужой `Set-Cookie`.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local state = helper.state

local g = t.group('tnt.session.layer')

--- 32 байта, из которых выходит опознаватель сессии.
local FIRST = ('a'):rep(32)

g.before_each(function()
    helper.pin_secrets(FIRST)
end)

g.after_each(function()
    helper.restore()
end)

--- Запрос, как его собирает роутер.
---@param cookie string|nil Значение заголовка Cookie
---@return table
local function request_with(cookie)
    return { method = 'GET', path = '/cart', headers = { cookie = cookie } }
end

--- Обработчик, который кладёт в сессию и отвечает тем, чем велено.
---@param answer any
---@return fun(request: any): any, any
---@return table seen Поле `session` — что досталось обработчику
local function handler_putting(answer)
    local seen = {}

    return function(request)
        seen.session = request.session
        seen.session:put('user', 42)

        if type(answer) == 'table' and answer.status ~= nil and answer.status >= 400 then
            return nil, answer
        end

        return answer
    end,
        seen
end

g.test_the_session_goes_into_the_request_and_the_cookie_into_the_response = function()
    local driver = helper.recording_driver()
    local sessions = helper.manager_over(driver)
    local layer = sessions:layer()
    local handler, seen = handler_putting({ status = 200, body = 'ok' })
    local request = request_with(nil)
    local response, err = layer(request, handler)

    t.assert_equals(err, nil)
    t.assert_equals(seen.session.id, helper.secret_of(FIRST))
    t.assert_equals(request.session, seen.session)
    t.assert_equals(response, {
        status = 200,
        body = 'ok',
        headers = {
            ['set-cookie'] = ('tnt_session=%s; Max-Age=7200; Path=/; SameSite=Lax; HttpOnly'):format(
                helper.secret_of(FIRST)
            ),
        },
    })
    t.assert_equals(driver.calls, { { 'commit', helper.secret_of(FIRST) } })
end

g.test_a_failing_store_becomes_a_503 = function()
    local sessions = helper.manager_over(helper.recording_driver({ fail = 'redis молчит' }))
    local handler, seen = handler_putting({ status = 200 })
    local response, err = sessions:layer()(request_with('tnt_session=метка'), handler)

    t.assert_equals(response, nil)
    t.assert_equals(err, {
        status = 503,
        message = 'сессия недоступна',
        code = 'session_unavailable',
        reason = 'сессия: драйвер двойник не отдал сессию: redis молчит',
    })
    t.assert_equals(
        tostring(err),
        'сессия недоступна: сессия: драйвер двойник не отдал сессию: redis молчит'
    )
    -- Обработчика не звали вовсе.
    t.assert_equals(seen.session, nil)
end

g.test_a_failing_write_becomes_a_503_too = function()
    local driver = helper.recording_driver()
    local sessions = helper.manager_over(driver)

    driver.commit = function()
        error('спейс только для чтения', 0)
    end

    local response, err = sessions:layer()(request_with(nil), handler_putting({ status = 200 }))

    t.assert_equals(response, nil)
    t.assert_equals(err.status, 503)
    t.assert_equals(
        err.reason,
        'сессия: драйвер двойник не сохранил сессию: спейс только для чтения'
    )
end

g.test_a_foreign_set_cookie_is_not_overwritten = function()
    local sessions = helper.manager_over(helper.recording_driver())
    local ours = ('tnt_session=%s; Max-Age=7200; Path=/; SameSite=Lax; HttpOnly'):format(helper.secret_of(FIRST))

    local one = sessions:layer()(
        request_with(nil),
        handler_putting({
            status = 200,
            headers = { ['set-cookie'] = 'theme=dark' },
        })
    )

    t.assert_equals(one.headers['set-cookie'], { 'theme=dark', ours })

    local many = sessions:layer()(
        request_with(nil),
        handler_putting({
            status = 200,
            headers = { ['set-cookie'] = { 'theme=dark', 'lang=ru' } },
        })
    )

    t.assert_equals(many.headers['set-cookie'], { 'theme=dark', 'lang=ru', ours })
end

g.test_a_refusal_from_the_handler_gets_the_cookie = function()
    local sessions = helper.manager_over(helper.recording_driver())
    local response, err = sessions:layer()(request_with(nil), handler_putting({ status = 422, message = 'не то' }))

    t.assert_equals(response, nil)
    -- Одноразовое сообщение кладут как раз перед отказом.
    t.assert_str_contains(err.headers['set-cookie'], 'tnt_session=')
    t.assert_equals(err.status, 422)
end

g.test_an_answer_without_a_place_for_headers_passes_as_it_is = function()
    local sessions = helper.manager_over(helper.recording_driver())

    t.assert_equals(
        sessions:layer()(request_with(nil), handler_putting('просто строка')),
        'просто строка'
    )
    t.assert_equals(
        sessions:layer()(request_with(nil), handler_putting({ status = 200, headers = 'не таблица' })),
        { status = 200, headers = 'не таблица' }
    )
end

g.test_a_request_without_headers_starts_a_fresh_session = function()
    local sessions = helper.manager_over(helper.recording_driver())
    local handler, seen = handler_putting({ status = 200 })

    sessions:layer()({ method = 'GET', path = '/cart' }, handler)

    t.assert_equals(seen.session.id, helper.secret_of(FIRST))
end

g.test_the_field_of_the_request_is_named_by_the_settings = function()
    local sessions = helper.manager_over(helper.recording_driver())
    local request = request_with(nil)
    local seen = {}

    sessions:layer({ field = 'visitor' })(request, function(given)
        seen.visitor = given.visitor
        given.visitor:put('user', 42)

        return { status = 200 }
    end)

    t.assert_equals(seen.visitor, request.visitor)
    t.assert_equals(request.session, nil)
end

g.test_the_factory_builds_the_same_layer = function()
    local sessions = helper.manager_over(helper.recording_driver())
    local layer = sessions:factory()({ tag = 'app' })
    local request = request_with(nil)

    layer(request, handler_putting({ status = 200 }))

    t.assert_equals(request.session.id, helper.secret_of(FIRST))
end

g.test_bad_settings_are_a_programmer_error_at_build_time = function()
    local sessions = helper.manager_over(helper.recording_driver())

    -- Место в сообщении принадлежит тому, кто собирает цепочку: опечатка
    -- в имени поля обязана показывать на его строку, а не на строку слоя.
    helper.assert_blamed({
        {
            function()
                sessions:layer({ fields = 'session' })
            end,
            'настройки слоя: ключа «fields» нет, есть field, tag',
        },
        {
            function()
                sessions:layer({ field = '' })
            end,
            'настройки слоя.field — непустая строка, а не пустая',
        },
    })
end

g.test_a_session_the_handler_did_not_touch_leaves_no_trace = function()
    local driver = helper.recording_driver()
    local sessions = helper.manager_over(driver)
    local response = sessions:layer()(request_with(nil), function(request)
        t.assert_equals(state.empty(request.session), true)

        return { status = 200 }
    end)

    t.assert_equals(response, { status = 200 })
    t.assert_equals(driver.calls, {})
end
