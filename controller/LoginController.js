const UserService = require('../service/UserService');

exports.index = (req, res) => {
    res.render('index.html', { });
};

exports.joinView = (req, res) => {
    res.render('join.html', { });
};

exports.join = async (req, res) => {
    const { userId, username, password } = req.body;
    if (!userId || !username || !password) {
        res.status(400).send('정상적이 요청이 아닙니다.');
        return;
    }

    const user = await UserService.findByUserId(userId);
    if (user) {
        res.status(400).send('아이디가 중복됩니다.');
        return;
    }

    const result = await UserService.createNewOne(userId, password, username);
    res.sendStatus(result ? 200 : 500);
};

exports.login = async (req, res) => {
    const { userId, password } = req.body;

    if (!userId || !password) {
        res.status(400).send('정상적이 요청이 아닙니다.');
        return;
    }

    const user = await UserService.findByUserId(userId);
    if (!user || user.get('password') !== password) {
        res.status(400).send('회원정보가 존재하지 않습니다.');
        return;
    }

    req.session.userId = user.get('userId');
    req.session.username = user.get('username');

    res.sendStatus(200);
};

exports.logout = async (req, res) => {
    req.session && await req.session.destroy();
    res.redirect('/');
};
