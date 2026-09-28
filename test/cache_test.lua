--- Проверки драйвера на хранилище `tnt-cache`: настоящее хранилище
--- в памяти, негодная метка и срок.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local from_cache = helper.from_cache
local state = helper.state

local g = t.group('tnt.session.cache')

g.after_each(function()
    helper.restore()
end)

--- Запись сессии: то, что кладёт менеджер.
local PAYLOAD = { values = { user = 42 }, flash = {}, token = nil }

g.test_a_session_is_written_read_and_forgotten = function()
    local driver = from_cache.new(helper.store())
    local id = state.secret()

    t.assert_equals(driver.open(id), nil)
    t.assert_equals(driver.commit(id, PAYLOAD, 60), id)
    t.assert_equals({ driver.open(id) }, { id, PAYLOAD })

    driver.close(id)

    t.assert_equals(driver.open(id), nil)
    t.assert_equals(driver.name, 'cache')
end

g.test_the_store_keeps_the_session_for_the_given_time = function()
    local clock = helper.clock()
    local driver = from_cache.new(helper.store(clock))
    local id = state.secret()

    driver.commit(id, PAYLOAD, 60)
    clock.advance(59)

    t.assert_equals({ driver.open(id) }, { id, PAYLOAD })

    clock.advance(2)

    t.assert_equals(driver.open(id), nil)
end

g.test_a_token_that_is_not_ours_never_reaches_the_store = function()
    local driver = from_cache.new(helper.store())

    -- Пустой ключ у кэша — ошибка программиста и бросок посреди живого
    -- запроса; ключ с чужими знаками ушёл бы в Redis как есть.
    for _, token in ipairs({ '', 'коротко', ('x'):rep(44), 'с точкой.' }) do
        t.assert_equals(driver.open(token), nil)
    end
end

g.test_a_record_of_another_kind_under_our_key_is_not_a_session = function()
    local store = helper.store()
    local driver = from_cache.new(store)
    local id = state.secret()

    store:put(id, 'чужое значение')

    t.assert_equals(driver.open(id), nil)
end

g.test_the_network_mark_is_taken_from_the_cache_driver = function()
    local store = { get = function() end, put = function() end, forget = function() end, driver = { remote = true } }

    t.assert_equals(from_cache.new(store).remote, true)
    t.assert_equals(from_cache.new(helper.store()).remote, nil)
end

g.test_a_store_of_another_kind_is_a_programmer_error = function()
    for _, store in ipairs({ 'строка', {}, { get = 42 }, { get = function() end } }) do
        helper.assert_raised(function()
            from_cache.new(store)
        end, 'сессия: драйверу cache нужно хранилище tnt-cache')
    end
end
