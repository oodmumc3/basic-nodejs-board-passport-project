require('dotenv').config();
const express = require('express');
const ExpressConfig = require('./config/ExpressConfig');
const SequelizeConfig = require('./config/SequelizeConfig');
const PassportConfig = require('./config/PassportConfig');
const User = require('./model/User');
const Board = require('./model/Board');

/**
 * passport 전략 설정
 * @return {Promise<void>}
 */
async function initPassport () {
    await PassportConfig.init();
}

/**
 * express 초기화 설정
 * @return {Promise<void>}
 */
async function initExpress () {
    const app = await ExpressConfig.init(express, process.env.PORT || process.env.EXPRESS_PORT || 3000);
    app.use(await ExpressConfig.route(express.Router()));
}

/**
 * sequelize 및 model 초기화
 * @return {Promise<void>}
 */
async function initSequelizeAndModels () {
    const sequelize = await SequelizeConfig.init(
        process.env.DB_HOST,
        process.env.DB_DATABASE,
        process.env.DB_USERNAME,
        process.env.DB_PASSWORD
    );

    await User.init(sequelize);
    // await User.sync(process.env.DB_SYNC_FORCE);

    await Board.init(sequelize);
    // await Board.sync(process.env.DB_SYNC_FORCE);
}

(async () => {
    try {
        await initPassport();
        await initExpress();
        await initSequelizeAndModels();
    } catch (e) {
        console.error(e);
    }
})();
