--- Проверки фасада: выбор драйвера, настройки куки и полный круг
--- «положили — записали — прочитали» на каждом драйвере.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local session = helper.session

local g = t.group('tnt.session')

g.after_each(function()
    helper.restore()
end)

--- Возит сессию по кругу: запись, кука, чтение следующим запросом.
---@param sessions TntSessionManager
---@param name string Имя куки
---@return TntSession restored
local function round_trip(sessions, name)
    local first = sessions:start(nil)

    -- Отказать хранилищу здесь нечем: оно своё, в памяти этого процесса.
    ---@cast first TntSession
    first:put('user', 42)
    first:flash('notice', 'Сохранено')

    local header = sessions:commit(first)
    local second = sessions:start(helper.sent(name, helper.value_of(header, name)))

    ---@cast second TntSession
    return second
end

g.test_a_session_lives_in_the_cache_store = function()
    local sessions = helper.manager_over_cache()

    t.assert_equals(sessions:status(), { driver = 'cache', name = 'tnt_session', lifetime = 7200 })

    local restored = round_trip(sessions, 'tnt_session')

    t.assert_equals(restored:get('user'), 42)
    t.assert_equals(restored:get('notice'), 'Сохранено')
    t.assert_equals(restored.stored, true)
end

g.test_a_session_lives_in_the_cookie_itself = function()
    local sessions = session.new({
        driver = 'cookie',
        cipher = helper.crypto.new({ key = helper.crypto.key() }),
        name = 'app_sid',
        lifetime = 60,
        cookie = { secure = false, domain = 'example.org' },
    })

    t.assert_equals(sessions:status(), { driver = 'cookie', name = 'app_sid', lifetime = 60 })

    local restored = round_trip(sessions, 'app_sid')

    t.assert_equals(restored:get('user'), 42)
    t.assert_equals(restored:get('notice'), 'Сохранено')
end

g.test_a_sealed_cookie_is_bound_to_its_name = function()
    local cipher = helper.crypto.new({ key = helper.crypto.key() })
    local settings = { driver = 'cookie', cipher = cipher, cookie = { secure = false } }
    local here = session.new({ driver = 'cookie', cipher = cipher, name = 'app_sid', cookie = settings.cookie })
    local there = session.new({ driver = 'cookie', cipher = cipher, name = 'remember', cookie = settings.cookie })

    local mine = here:start(nil)

    mine:put('user', 42)

    local value = helper.value_of(here:commit(mine), 'app_sid')
    local alien = there:start(helper.sent('remember', value))

    -- Шифровка привязана к имени куки присоединёнными данными: в чужой
    -- куке того же приложения она не расшифруется.
    t.assert_equals(alien:get('user'), nil)
    t.assert_not_equals(alien.id, mine.id)
end

g.test_the_cookie_settings_reach_the_header = function()
    local sessions = helper.manager_over_cache({ cookie = { secure = false, domain = 'example.org', path = '/app' } })
    local first = sessions:start(nil)

    ---@cast first TntSession
    first:put('user', 42)

    t.assert_str_contains(sessions:commit(first), '; Domain=example.org; Path=/app; SameSite=Lax; HttpOnly')
end

g.test_a_driver_given_as_a_table_is_taken_as_it_is = function()
    local driver = helper.recording_driver()
    local sessions = session.new({ driver = driver, cookie = { secure = false } })

    t.assert_equals(sessions:status().driver, 'двойник')
end

g.test_a_driver_that_does_not_exist_is_a_programmer_error = function()
    helper.assert_raised(function()
        session.new({ driver = 'file' })
    end, 'сессия: драйвера file нет, есть cache и cookie')

    helper.assert_raised(function()
        session.new({ driver = 42 })
    end, 'сессия: драйвера 42 нет, есть cache и cookie')
end

g.test_the_cache_driver_without_a_store_is_a_programmer_error = function()
    helper.assert_raised(function()
        session.new()
    end, 'сессия: драйверу cache нужно хранилище tnt-cache')
end

g.test_the_cookie_driver_without_a_cipher_is_a_programmer_error = function()
    helper.assert_raised(
        function()
            session.new({ driver = 'cookie' })
        end,
        'сессия: драйверу cookie нужен шифровальщик tnt-crypto аргументом cipher'
    )
end

g.test_the_parts_of_the_package_are_at_hand = function()
    t.assert_equals(session.state, helper.state)
    t.assert_equals(session.manager, helper.manager)
    t.assert_equals(session.layer, helper.layer)
    t.assert_equals(session.cache, helper.from_cache)
    t.assert_equals(session.cookie, helper.from_cookie)
end
