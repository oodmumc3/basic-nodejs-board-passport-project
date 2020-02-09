const User = require('../model/User');

exports.createNewOne = async function (userId, password, username) {
    try {
        await User.create(userId, password, username);
        return true;
    } catch (e) {
        console.error('user create error :: ', e);
        return false;
    }
};

exports.findByPk = User.findByPk;
exports.findByUserId = User.findByUserId;
