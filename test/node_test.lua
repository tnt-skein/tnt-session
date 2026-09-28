--- Живые проверки на настоящем узле: сессия в спейсе через хранилище
--- `tnt-cache` и драйвер по сети внутри транзакции box.
---
--- Настоящим узлом, а не двойником: признак транзакции пакет спрашивает
--- у самого box, и до `box.cfg` его нет вовсе — у неподнятого инстанса
--- `box.is_in_txn` отказывает «Please call box.cfg{} first».

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.session.node')

-- Исходники пакета узел берёт при подъёме, и проверки зовут их обычным
-- `require`: состояния у пакета нет, и собирать его заново на каждую
-- проверку незачем.
g.before_all(function()
    g.server = helper.start_node()
end)

g.after_all(function()
    helper.stop_node(g.server)
end)

g.test_a_session_lives_in_a_space_and_comes_back_by_the_cookie = function()
    local seen = g.server:exec(function()
        ---@type any
        local session = require('tnt.session')
        ---@type any
        local cache = require('tnt.cache')

        cache.space.migrate(box, 'app_sessions')

        local sessions = session.new({
            cache = cache.new({ driver = 'space', space = 'app_sessions', prefix = 'sess:' }),
            cookie = { secure = false },
        })

        local first = sessions:start(nil)

        first:put('user', 42)
        first:flash('notice', 'Сохранено')

        local header = sessions:commit(first)
        local second = sessions:start('tnt_session=' .. header:match('^tnt_session=([^;]*)'))
        local stored = box.space.app_sessions:select({}, { limit = 1 })

        return {
            user = second:get('user'),
            notice = second:get('notice'),
            same = second.id == first.id,
            rows = box.space.app_sessions:count(),
            key = stored[1] ~= nil and stored[1].key or nil,
        }
    end)

    t.assert_equals(seen.user, 42)
    t.assert_equals(seen.notice, 'Сохранено')
    t.assert_equals(seen.same, true)
    t.assert_equals(seen.rows, 1)
    -- Ключ в спейсе — приставка хранилища и опознаватель сессии.
    t.assert_str_matches(seen.key, 'sess:[%w_-]+')
end

g.test_a_network_driver_is_called_outside_a_transaction_and_refused_inside = function()
    local seen = g.server:exec(function()
        ---@type any
        local session = require('tnt.session')

        local remote = {
            name = 'redis',
            remote = true,
            open = function() end,
            commit = function(id)
                return id
            end,
            close = function() end,
        }

        local sessions = session.new({ driver = remote, cookie = { secure = false } })

        -- Вне транзакции драйвер по сети зовётся как обычно.
        local outside = sessions:start(nil) ~= nil

        box.begin()

        local ok, err = pcall(sessions.start, sessions, nil)

        box.rollback()

        return { outside = outside, ok = ok, err = tostring(err) }
    end)

    t.assert_equals(seen.outside, true)
    t.assert_equals(seen.ok, false)
    t.assert_equals(
        seen.err,
        'сессия: драйвер redis ходит по сети — внутри транзакции box его не зовут: '
            .. 'уступка порвёт транзакцию, а записанное в него при откате останется'
    )
end
