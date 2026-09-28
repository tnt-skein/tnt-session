--- Проверки самой сессии: данные, одноразовые значения, токен, запись
--- для драйвера.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local state = helper.state

local g = t.group('tnt.session.state')

g.after_each(function()
    helper.restore()
end)

--- Сессия с данными: опознаватель проверке неважен.
---@param values table|nil
---@return TntSession
local function session_with(values)
    local session = state.new('id-1')

    for name, value in pairs(values or {}) do
        session:put(name, value)
    end

    session.dirty = false

    return session
end

g.test_values_are_put_read_and_forgotten = function()
    local session = state.new('id-1')

    t.assert_equals(session.dirty, false)
    t.assert_equals(session:get('cart'), nil)
    t.assert_equals(session:get('cart', 'нет'), 'нет')
    t.assert_equals(session:has('cart'), false)

    session:put('cart', { 7, 9 })

    t.assert_equals(session.dirty, true)
    t.assert_equals(session:get('cart'), { 7, 9 })
    t.assert_equals(session:has('cart'), true)
    t.assert_equals(session:all(), { cart = { 7, 9 } })

    session:forget('cart')

    t.assert_equals(session:get('cart', 'нет'), 'нет')
    t.assert_equals(session:all(), {})
end

g.test_all_gives_a_copy = function()
    local session = session_with({ user = 42 })
    local copy = session:all()

    copy.user = 7

    t.assert_equals(session:get('user'), 42)
    -- Правка отданной наружу таблицы прошла бы мимо `dirty`.
    t.assert_equals(session.dirty, false)
end

g.test_pull_takes_the_value_once = function()
    local session = session_with({ token = 'один раз' })

    t.assert_equals(session:pull('token'), 'один раз')
    t.assert_equals(session.dirty, true)
    t.assert_equals(session:pull('token', 'нет'), 'нет')

    -- Промах ничего не забрал и сессию не менял.
    local fresh = session_with({})

    t.assert_equals(fresh:pull('token', 'нет'), 'нет')
    t.assert_equals(fresh.dirty, false)
end

g.test_flush_clears_values_and_keeps_the_token = function()
    helper.pin_secrets(('t'):rep(32))

    local session = session_with({ user = 42 })
    local token = session:token()

    session:flash('notice', 'Сохранено')
    session:flush()

    t.assert_equals(session:all(), {})
    t.assert_equals(session.dirty, true)
    t.assert_equals(session:token(), token)
    t.assert_equals(state.payload(session).flash, {})
end

g.test_the_token_is_made_once_and_lies_outside_the_values = function()
    helper.pin_secrets(('t'):rep(32), ('u'):rep(32))

    local session = state.new('id-1')

    t.assert_equals(session:token(), helper.secret_of(('t'):rep(32)))
    t.assert_equals(session.dirty, true)
    -- Второе обращение отдаёт тот же токен, а не свежий.
    t.assert_equals(session:token(), helper.secret_of(('t'):rep(32)))
    t.assert_equals(session:all(), {})
    t.assert_equals(state.empty(session), false)
end

g.test_a_flashed_value_lives_one_request = function()
    local session = state.new('id-1')

    session:flash('notice', 'Сохранено')

    -- Видно сразу: сообщение кладут и читают в одном обработчике.
    t.assert_equals(session:get('notice'), 'Сохранено')
    t.assert_equals(state.payload(session), {
        values = { notice = 'Сохранено' },
        flash = { 'notice' },
        token = nil,
    })

    local next_request = state.restore('id-1', state.payload(session))

    t.assert_equals(next_request:get('notice'), 'Сохранено')
    -- А в запись следующего запроса оно уже не уходит.
    t.assert_equals(state.payload(next_request), { values = {}, flash = {} })
end

g.test_keep_prolongs_the_flashed_values = function()
    local first = state.new('id-1')

    first:flash('notice', 'Сохранено')
    first:flash('level', 'info')

    local second = state.restore('id-1', state.payload(first))

    second:keep({ 'notice' })

    t.assert_equals(second.dirty, true)
    t.assert_equals(state.payload(second), {
        values = { notice = 'Сохранено' },
        flash = { 'notice' },
    })

    -- Без имён продлеваются все одноразовые разом.
    local third = state.restore('id-1', state.payload(first))

    third:keep()

    t.assert_equals(state.payload(third), {
        values = { level = 'info', notice = 'Сохранено' },
        flash = { 'level', 'notice' },
    })
end

g.test_a_value_put_over_a_flashed_one_stops_being_flashed = function()
    local first = state.new('id-1')

    first:flash('notice', 'Сохранено')
    first:put('notice', 'Навсегда')

    t.assert_equals(state.payload(first), { values = { notice = 'Навсегда' }, flash = {} })

    -- И наоборот: пришедшее одноразовым, положенное заново, остаётся.
    local second = state.restore('id-1', { values = { notice = 'Старое' }, flash = { 'notice' } })

    second:put('notice', 'Новое')

    t.assert_equals(state.payload(second), { values = { notice = 'Новое' }, flash = {} })
end

g.test_forgetting_a_flashed_value_removes_it_from_both_lists = function()
    local session = state.restore('id-1', { values = { notice = 'Старое' }, flash = { 'notice' } })

    session:flash('level', 'info')
    session:forget('level')

    t.assert_equals(state.payload(session), { values = {}, flash = {} })
end

g.test_a_secret_is_random_bytes_in_base64url = function()
    local secret = state.secret()

    t.assert_equals(#secret, 43)
    t.assert_equals(state.is_secret(secret), true)
    t.assert_not_equals(secret, state.secret())

    t.assert_equals(state.is_secret(secret .. 'x'), false)
    t.assert_equals(state.is_secret(secret:sub(2)), false)
    t.assert_equals(state.is_secret(('.'):rep(43)), false)
    t.assert_equals(state.is_secret(nil), false)
    t.assert_equals(state.is_secret(42), false)
    t.assert_equals(state.is_secret(''), false)
end

g.test_a_foreign_record_is_not_a_session = function()
    t.assert_equals(state.restore('id-1', nil), nil)
    t.assert_equals(state.restore('id-1', 'строка'), nil)
    t.assert_equals(state.restore('id-1', {}), nil)
    t.assert_equals(state.restore('id-1', { values = 'не таблица' }), nil)

    -- Токен и список одноразовых не той породы просто не берутся.
    local session = state.restore('id-1', { values = { user = 42 }, token = 7, flash = 'нет' })

    t.assert_equals(session.id, 'id-1')
    t.assert_equals(session.stored, true)
    t.assert_equals(session.secret, nil)
    t.assert_equals(session:get('user'), 42)
end

g.test_a_restored_session_keeps_its_token = function()
    local session = state.restore('id-1', { values = {}, token = 'прежний' })

    t.assert_equals(session:token(), 'прежний')
    t.assert_equals(session.dirty, false)
    t.assert_equals(state.empty(session), false)
end

g.test_an_empty_session_is_the_one_without_values_and_token = function()
    t.assert_equals(state.empty(state.new('id-1')), true)
    t.assert_equals(state.empty(session_with({ user = 42 })), false)
end

g.test_a_bad_key_and_an_empty_value_are_programmer_errors = function()
    local session = state.new('id-1')

    for _, call in ipairs({
        function()
            session:get(42)
        end,
        function()
            session:has('')
        end,
        function()
            session:put(nil, 1)
        end,
        function()
            session:forget({})
        end,
        function()
            session:pull(true)
        end,
        function()
            session:flash(42, 1)
        end,
        function()
            session:keep({ 42 })
        end,
    }) do
        helper.assert_raised(call, 'сессия: ключ должен быть непустой строкой')
    end

    helper.assert_raised(function()
        session:put('cart', nil)
    end, 'сессия: пустое значение не кладут, для удаления есть forget')

    helper.assert_raised(function()
        session:flash('notice', nil)
    end, 'сессия: пустое значение не кладут, для удаления есть forget')
end
