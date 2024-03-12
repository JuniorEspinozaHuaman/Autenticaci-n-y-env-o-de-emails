const express = require('express');
const userRouter = require('./user.router');
const router = express.Router();

// colocar las rutas aquí
router.use(userRouter)

module.exports = router;