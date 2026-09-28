--- Проверки менеджера: кука на входе, запись у драйвера на выходе,
--- смена опознавателя и отказ хранилища.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local manager = helper.manager
local state = helper.state

local g = t.group('tnt.session.manager')

--- 32 байта, из которых выходит опознаватель первой сессии.
local FIRST = ('a'):rep(32)
local SECOND = ('b'):rep(32)

g.before_each(function()
    helper.pin_secrets(FIRST, SECOND)
end)

g.after_each(function()
    helper.restore()
end)

g.test_a_request_without_a_cookie_gets_a_fresh_session = function()
    local driver = helper.recording_driver()
    local sessions = helper.manager_over(driver)
    local session, err = sessions:start(nil)

    t.assert_equals(err, nil)
    t.assert_equals(session.id, helper.secret_of(FIRST))
    t.assert_equals(session.stored, false)
    t.assert_equals(session:all(), {})
    -- Метки не было — у драйвера ничего не спрашивали.
    t.assert_equals(driver.calls, {})
end

g.test_a_known_token_restores_the_session = function()
    local driver = helper.recording_driver({
        id = 'stored-1',
        payload = { values = { user = 42 }, flash = { 'notice' } },
    })
    local sessions = helper.manager_over(driver)
    local session = sessions:start(helper.sent('tnt_session', 'метка'))

    t.assert_equals(driver.calls, { { 'open', 'метка' } })
    t.assert_equals(session.id, 'stored-1')
    t.assert_equals(session.stored, true)
    t.assert_equals(session:get('user'), 42)
end

g.test_an_unknown_token_is_not_taken_as_an_identifier = function()
    local driver = helper.recording_driver()
    local sessions = helper.manager_over(driver)
    local session = sessions:start(helper.sent('tnt_session', 'навязанная'))

    t.assert_equals(driver.calls, { { 'open', 'навязанная' } })
    -- Опознаватель свой, а не тот, что принёс клиент.
    t.assert_equals(session.id, helper.secret_of(FIRST))
    t.assert_equals(session.stored, false)
end

g.test_a_record_of_a_foreign_shape_starts_a_fresh_session = function()
    local driver = helper.recording_driver({ id = 'stored-1', payload = { foreign = true } })
    local sessions = helper.manager_over(driver)
    local session = sessions:start(helper.sent('tnt_session', 'метка'))

    t.assert_equals(session.id, helper.secret_of(FIRST))
    t.assert_equals(session.stored, false)
end

g.test_a_cookie_of_another_name_is_not_a_session = function()
    local driver = helper.recording_driver({ id = 'stored-1', payload = { values = {} } })
    local sessions = helper.manager_over(driver, { name = 'app_sid' })

    sessions:start(helper.sent('tnt_session', 'метка'))

    t.assert_equals(driver.calls, {})
    t.assert_equals(sessions:status(), { driver = 'двойник', name = 'app_sid', lifetime = 7200 })
end

g.test_a_failing_store_refuses_instead_of_logging_everyone_out = function()
    local driver = helper.recording_driver({ fail = 'redis молчит' })
    local sessions = helper.manager_over(driver)
    local session, err = sessions:start(helper.sent('tnt_session', 'метка'))

    t.assert_equals(session, nil)
    t.assert_equals(err, 'сессия: драйвер двойник не отдал сессию: redis молчит')
end

g.test_a_fresh_empty_session_is_written_nowhere = function()
    local driver = helper.recording_driver()
    local sessions = helper.manager_over(driver)
    local header, err = sessions:commit(sessions:start(nil))

    t.assert_equals(header, nil)
    t.assert_equals(err, nil)
    t.assert_equals(driver.calls, {})
end

g.test_a_touched_session_is_written_and_the_cookie_is_set = function()
    local driver = helper.recording_driver()
    local sessions = helper.manager_over(driver)
    local session = sessions:start(nil)

    session:put('user', 42)

    local header, err = sessions:commit(session)

    t.assert_equals(err, nil)
    t.assert_equals(driver.calls, { { 'commit', helper.secret_of(FIRST) } })
    t.assert_equals(
        header,
        ('tnt_session=%s; Max-Age=7200; Path=/; SameSite=Lax; HttpOnly'):format(helper.secret_of(FIRST))
    )
end

g.test_a_stored_session_is_rewritten_even_untouched = function()
    local driver = helper.recording_driver({ id = 'stored-1', payload = { values = { user = 42 } } })
    local sessions = helper.manager_over(driver, { lifetime = 60 })
    local session = sessions:start(helper.sent('tnt_session', 'метка'))
    local header = sessions:commit(session)

    -- Тем и продлевается срок, пока посетитель работает.
    t.assert_equals(driver.calls[2], { 'commit', 'stored-1' })
    t.assert_equals(header, 'tnt_session=stored-1; Max-Age=60; Path=/; SameSite=Lax; HttpOnly')
end

g.test_the_driver_decides_what_goes_into_the_cookie = function()
    local driver = helper.recording_driver({ token = 'sealed-1' })
    local sessions = helper.manager_over(driver)
    local session = sessions:start(nil)

    session:put('user', 42)

    t.assert_equals(helper.value_of(sessions:commit(session), 'tnt_session'), 'sealed-1')
end

g.test_a_failing_write_is_a_pair = function()
    local driver = helper.recording_driver({ fail = 'спейс только для чтения' })
    local sessions = helper.manager_over(driver)
    local session = state.new('свой')

    session:put('user', 42)

    local header, err = sessions:commit(session)

    t.assert_equals(header, nil)
    t.assert_equals(
        err,
        'сессия: драйвер двойник не сохранил сессию: спейс только для чтения'
    )
end

g.test_a_token_the_cookie_refuses_is_a_pair_too = function()
    local driver = helper.recording_driver({ token = 'с пробелом' })
    local sessions = helper.manager_over(driver)
    local session = state.new('свой')

    session:put('user', 42)

    local header, err = sessions:commit(session)

    t.assert_equals(header, nil)
    t.assert_str_contains(tostring(err), 'в значении куки недопустим байт')
end

g.test_expire_asks_the_browser_to_forget_the_cookie = function()
    local sessions = helper.manager_over(helper.recording_driver())

    t.assert_str_contains(sessions:expire(), 'tnt_session=; Expires=')
    t.assert_str_contains(sessions:expire(), 'Max-Age=0; Path=/; SameSite=Lax; HttpOnly')
end

g.test_regenerate_gives_a_new_identifier_and_keeps_the_values = function()
    local driver =
        helper.recording_driver({ id = 'before-1', payload = { values = { user = 42 }, token = 'старый' } })
    local sessions = helper.manager_over(driver)
    local session = sessions:start(helper.sent('tnt_session', 'метка'))

    t.assert_equals(sessions:regenerate(session), true)
    t.assert_equals(session.id, helper.secret_of(FIRST))
    t.assert_equals(session:get('user'), 42)
    t.assert_equals(session.stored, false)
    t.assert_equals(session.dirty, true)
    -- Токен заводится заново: украденный до входа иначе действовал бы и после.
    t.assert_equals(session:token(), helper.secret_of(SECOND))
    t.assert_equals(driver.calls[2], { 'close', 'before-1' })
end

g.test_invalidate_empties_the_session = function()
    local driver = helper.recording_driver({ id = 'before-1', payload = { values = { user = 42 } } })
    local sessions = helper.manager_over(driver)
    local session = sessions:start(helper.sent('tnt_session', 'метка'))

    t.assert_equals(sessions:invalidate(session), true)
    t.assert_equals(session:all(), {})
    t.assert_equals(session.id, helper.secret_of(FIRST))
    t.assert_equals(driver.calls[2], { 'close', 'before-1' })

    -- Сессия пуста, и `commit` ставить её не станет: куку гасят `expire`.
    t.assert_equals(sessions:commit(session), nil)
end

g.test_a_session_that_was_never_stored_is_not_closed = function()
    local driver = helper.recording_driver()
    local sessions = helper.manager_over(driver)
    local session = sessions:start(nil)

    session:put('user', 42)

    t.assert_equals(sessions:regenerate(session), true)
    t.assert_equals(session.id, helper.secret_of(SECOND))
    t.assert_equals(driver.calls, {})
end

g.test_a_failing_close_is_a_pair = function()
    local driver = helper.recording_driver({ id = 'before-1', payload = { values = {} }, fail = nil })
    local sessions = helper.manager_over(driver)
    local session = sessions:start(helper.sent('tnt_session', 'метка'))

    driver.close = function()
        error('спейс снесли', 0)
    end

    local ok, err = sessions:regenerate(session)

    t.assert_equals(ok, nil)
    t.assert_equals(
        err,
        'сессия: драйвер двойник не сохранил сессию: спейс снесли'
    )
    -- Опознаватель сменился всё равно: прежний уже не вернуть.
    t.assert_equals(session.id, helper.secret_of(FIRST))
end

g.test_a_network_driver_inside_a_box_transaction_raises = function()
    local sessions = helper.manager_over(helper.recording_driver({ remote = true }))
    local session = state.new('свой')

    manager._set_source({
        in_transaction = function()
            return true
        end,
    })

    local message = 'сессия: драйвер двойник ходит по сети — внутри транзакции box его не зовут: '
        .. 'уступка порвёт транзакцию, а записанное в него при откате останется'

    helper.assert_raised(function()
        sessions:start(nil)
    end, message)

    helper.assert_raised(function()
        sessions:commit(session)
    end, message)

    helper.assert_raised(function()
        sessions:regenerate(session)
    end, message)
end

g.test_a_local_driver_inside_a_box_transaction_works = function()
    local sessions = helper.manager_over(helper.recording_driver())

    manager._set_source({
        in_transaction = function()
            return true
        end,
    })

    t.assert_equals(sessions:start(nil).id, helper.secret_of(FIRST))
end

g.test_bad_settings_are_programmer_errors = function()
    helper.assert_raised(function()
        helper.manager_over(helper.recording_driver(), { name = '' })
    end, 'сессия: name — непустая строка, имя куки')

    helper.assert_raised(function()
        helper.manager_over(helper.recording_driver(), { name = 42 })
    end, 'сессия: name — непустая строка, имя куки')

    for _, lifetime in ipairs({ 0, -1, 1.5, 'час' }) do
        helper.assert_raised(function()
            helper.manager_over(helper.recording_driver(), { lifetime = lifetime })
        end, 'сессия: lifetime — целое число секунд больше нуля')
    end

    -- Секунда — годный срок, и нечётный тоже: границей стоит ноль,
    -- а целым число считается остатком от единицы.
    t.assert_equals(helper.manager_over(helper.recording_driver(), { lifetime = 1 }):status().lifetime, 1)
end
