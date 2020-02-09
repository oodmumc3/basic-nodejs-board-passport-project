const Sequelize = require('sequelize');

let _user;
exports.init = async (sequelize) => {
    _user = await sequelize.define('tl_board_user', {
        id: {
            type: Sequelize.INTEGER,
            primaryKey: true,
            autoIncrement: true
        },
        userId: {
            type: Sequelize.STRING(100),
            allowNull: false,
            unique: true
        },
        password: {
            type: Sequelize.STRING(100),
            allowNull: false
        },
        name: {
            type: Sequelize.STRING(20),
            allowNull: false
        },
        isAdmin: {
            type: Sequelize.BOOLEAN,
            allowNull: false,
            defaultValue: false
        }
    }, {
        sequelize,
        modelName: 'user',
        tableName: 'tl_board_user'
    });
};

exports.sync = async (force) => {
    _user && await _user.sync({ force });
};

exports.create = async (userId, password, name) => {
    await _user.create({userId, password, name});
};

exports.findByUserId = async (userId) => {
    return await _user.findOne({ where: { userId } });
};

exports.findByPk = async (id) => {
    return await _user.findByPk(id);
};

