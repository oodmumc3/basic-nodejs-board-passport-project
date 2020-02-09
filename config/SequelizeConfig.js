const Sequelize = require('sequelize');

exports.init = (host, database, username, password) => {
    return new Sequelize(database, username, password, {
        host,
        dialect: 'mysql'
    });
};