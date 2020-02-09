const Board = require('../model/Board');
const User = require('../model/User');

exports.findBoardListWithPaging = async (page, perPage, searchType, searchTerm) => {
    const offset = page > 1 ? perPage * (page - 1) : 0;

    const { boards, totalCnt, totalPage } =
        await Board.findAllAngGetPagingData(offset, perPage, searchType, searchTerm);

    let startBoardNum = totalCnt - (page - 1) * perPage;
    for (const board of boards) {
        const user = await User.findByPk(board.userId);
        board.username = user.name;
        board.num = startBoardNum--;
    }

    return { boards, totalCnt, totalPage };
};

exports.findByPk = Board.findByPk;
exports.deleteById = Board.deleteById;
exports.save = Board.save;
exports.updateById = Board.updateById;
