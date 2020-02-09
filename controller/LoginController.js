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

exports.logout = async (req, res) => {
    req.logout();
    res.redirect('/');
};
