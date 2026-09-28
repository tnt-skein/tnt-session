--- Проверки драйвера «сессия в куке»: настоящий шифровальщик
--- `tnt-crypto`, чужая шифровка, срок внутри и предел размера.

local msgpack = require('msgpack')
local t = require('luatest')

local helper = dofile('test/helper.lua')

local from_cookie = helper.from_cookie

local g = t.group('tnt.session.cookie')

g.after_each(function()
    helper.restore()
end)

--- Запись сессии: то, что кладёт менеджер.
local PAYLOAD = { values = { user = 42 }, flash = { 'notice' } }

--- Драйвер над настоящим шифровальщиком.
---@param name string|nil Имя куки: оно же присоединённые данные
---@return TntSessionDriver
local function sealed(name)
    return from_cookie.new(helper.crypto.new({ key = helper.crypto.key() }), { name = name or 'tnt_session' })
end

--- Драйвер над шифровальщиком-двойником: он отдаёт что велено.
---@param answers table Поля `token` (чем шифрует) и `text` (что расшифровывает)
---@return TntSessionDriver
local function faked(answers)
    return from_cookie.new({
        encrypt = function()
            return answers.token
        end,
        decrypt = function()
            return answers.text
        end,
    }, { name = 'tnt_session' })
end

g.test_the_session_goes_into_the_cookie_and_comes_back = function()
    local driver = sealed()
    local token = driver.commit('id-1', PAYLOAD, 60)

    t.assert_equals(driver.name, 'cookie')
    -- Шифровка — base64url: она ложится в куку без экранирования.
    t.assert_str_matches(token, '[%w_-]+')
    t.assert_equals({ driver.open(token) }, { 'id-1', PAYLOAD })

    -- Забывать на узле нечего: записи там нет.
    t.assert_equals(driver.close('id-1'), nil)
end

g.test_a_cookie_of_another_name_does_not_open = function()
    local token = sealed('tnt_session').commit('id-1', PAYLOAD, 60)

    t.assert_equals(sealed('remember').open(token), nil)
end

g.test_a_foreign_or_broken_ciphertext_is_not_a_session = function()
    local driver = sealed()

    for _, token in ipairs({ '', 'не шифровка', sealed().commit('id-1', PAYLOAD, 60) }) do
        t.assert_equals(driver.open(token), nil)
    end
end

g.test_the_deadline_lies_inside_the_ciphertext = function()
    local clock = helper.clock()

    from_cookie._set_source({ now = clock.realtime })

    local driver = sealed()
    local token = driver.commit('id-1', PAYLOAD, 60)

    clock.advance(59)

    t.assert_equals({ driver.open(token) }, { 'id-1', PAYLOAD })

    clock.advance(1)

    -- Ровно в срок сессия уже кончилась: срок — миг, до которого она жива.
    t.assert_equals(driver.open(token), nil)

    clock.advance(2)

    -- Кука, отданная браузером после срока, сессии не открывает.
    t.assert_equals(driver.open(token), nil)
end

g.test_a_record_of_a_former_shape_is_not_a_session = function()
    for _, text in ipairs({
        -- Запись, на которой msgpack отказывает: незаконный код и обрубок.
        string.char(0xc1),
        string.char(0x93, 0x01),
        'не msgpack вовсе',
        msgpack.encode('строка'),
        msgpack.encode({ payload = PAYLOAD }),
        msgpack.encode({ id = 42, expires_at = 1e12, payload = PAYLOAD }),
        msgpack.encode({ id = 'id-1', payload = PAYLOAD }),
        msgpack.encode({ id = 'id-1', expires_at = 'скоро', payload = PAYLOAD }),
    }) do
        t.assert_equals(faked({ text = text }).open('метка'), nil)
    end
end

g.test_a_session_that_does_not_fit_the_cookie_refuses = function()
    -- Предел сверяется по самой шифровке, поэтому её длину задаёт двойник:
    -- у настоящей длина растёт блоками по шестнадцать байт.
    t.assert_equals(#faked({ token = ('x'):rep(3900) }).commit('id-1', PAYLOAD, 60), 3900)

    helper.assert_raised(
        function()
            faked({ token = ('x'):rep(3901) }).commit('id-1', PAYLOAD, 60)
        end,
        'сессия: в куку не влезает — 3901 байт при пределе 3900; держите в сессии опознаватели, а не данные'
    )
end

g.test_a_cipher_of_another_kind_is_a_programmer_error = function()
    for _, cipher in ipairs({ 'строка', {}, { encrypt = function() end }, { encrypt = 42, decrypt = 42 } }) do
        helper.assert_raised(
            function()
                from_cookie.new(cipher, { name = 'tnt_session' })
            end,
            'сессия: драйверу cookie нужен шифровальщик tnt-crypto аргументом cipher'
        )
    end
end
