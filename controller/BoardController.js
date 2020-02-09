const BoardService = require('../service/BoardService');
const UserService = require('../service/UserService');
const appRootPath = require('app-root-path');

exports.index = async (req, res) => {
    const perPage = req.query.perPage || 2;
    const page = req.query.page || 1;
    let { searchType, searchTerm } = req.query;
    if (searchTerm && !['title', 'contents'].includes(searchType)) {
        searchType = 'title';
    }

    const { totalPage, totalCnt, boards } =
        await BoardService.findBoardListWithPaging(page, perPage, searchType, searchTerm);

    res.render('board/index.html', { boards, totalPage, totalCnt, currentPage: page, searchTerm, searchType });
};

exports.formPage = async (req, res) => {
    const boardId = req.params.id;
    if (!boardId) { return res.render('board/write.html', { board: {} }); }

    const board = await BoardService.findByPk(boardId);
    if (!board) { return res.redirect('/board'); }

    const user = await UserService.findByUserId(req.user.userId);
    if (user.id !== board.userId) { return res.redirect('/board'); }

    res.render('board/write.html', { board });
};

exports.delete = async (req, res) => {
    const boardId = req.body.id;
    const board = await BoardService.findByPk(boardId);
    const user = await UserService.findByUserId(req.user.userId);

    if (user.id !== board.userId) { return res.redirect('/board'); }

    await BoardService.deleteById(board.id);

    res.redirect('/board');
};

exports.viewPage = async (req, res) => {
    const board = await BoardService.findByPk(req.params.id);
    if (!board) { return res.redirect('/board'); }

    const user = await UserService.findByPk(board.userId);
    board.username = user.name;
    board.isOwner = user.userId === req.user.userId;

    res.render('board/view.html', { board });
};

exports.save = async (req, res) => {
    const userId = req.user.userId;
    const { title, contents } = req.body;

    const user = await UserService.findByUserId(userId);
    let fileName;
    try {
        if (req.files && req.files.file && req.files.file.name !== '') {
            const file = req.files.file;
            fileName = file.name.split('.')[0] + '_' + Date.now() + '.' + file.name.split('.')[1];
            const filePath = `${appRootPath}/upload/${fileName}`;
            await file.mv(filePath);
        }
        await BoardService.save(user.id, title, contents, fileName);
    } catch (e) {
        console.error(`board save error :: ${e}`);
    }
    res.redirect('/board');
};

exports.update = async (req, res) => {
    const {id, title, contents} = req.body;

    const board = await BoardService.findByPk(id);
    if (!board) { return res.redirect('/board'); }

    const user = await UserService.findByUserId(req.user.userId);
    if (user.id !== board.userId) { return res.redirect('/board'); }

    await BoardService.updateById(id, title, contents);

    res.redirect(`/board/view/${id}`);
};

