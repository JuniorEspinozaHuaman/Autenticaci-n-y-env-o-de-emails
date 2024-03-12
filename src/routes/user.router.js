const { getAll, create, getOne, remove, update, verifyEmail, login, loggedUser, resetPassword, updatePassword } = require('../controllers/user.controllers');
const express = require('express');
const verifyJWT = require('../utils/verifyJWT');

const userRouter = express.Router();

userRouter.route('/users')
    .get(verifyJWT, getAll)
    .post(create);

userRouter.route('/users/verify/:code')
    .get(verifyEmail)

userRouter.route('/users/login')
    .post(login)

userRouter.route('/users/me')
    .get(verifyJWT, loggedUser)

userRouter.route('/users/reset_password')
    .post(resetPassword)

userRouter.route('/users/reset_password/:code')
    .post(updatePassword)

userRouter.route('/users/:id')
    .get(verifyJWT, getOne)
    .delete(verifyJWT, remove)
    .put(verifyJWT, update);

module.exports = userRouter;