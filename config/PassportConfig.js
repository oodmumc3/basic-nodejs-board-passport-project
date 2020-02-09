const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const UserService = require('../service/UserService');

/**
 * Strategy 성공 시 호출됨
 */
function initSerializeUser () {
    passport.serializeUser((user, done) => {
        done(null, user);
    });
}

/**
 * 매개변수 user는 serializeUser의 done의 인자 user를 받은 것
 */
function initDeSerializeUser () {
    passport.deserializeUser((user, done) => {
        done(null, user);
    });
}

/**
 * 로그인 전략을 직접 설정한다.
 */
async function initLocalStrategy () {
    passport.use('local-strategy', new LocalStrategy({
        usernameField: 'userId',
        passwordField: 'password',
        session: true,
        passReqToCallback: false
    }, async (userId, password, done) => {
        if (!userId || !password) {
            return done(null, false, { message: '정상적이 요청이 아닙니다.' });
        }

        const user = await UserService.findByUserId(userId);
        if (!user || user.get('password') !== password) {
            return done(null, false, { message: '회원정보가 존재하지 않습니다.' });
        }

        done(null, { userId: user.userId, username: user.username });
    }));
}

async function init() {
    initSerializeUser();
    initDeSerializeUser();
    await initLocalStrategy();
}

exports.init = init;
