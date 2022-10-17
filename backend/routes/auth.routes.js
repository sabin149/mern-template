const express = require('express')
const router = express.Router()
const {register,
    login,
    verifyUser,
    refresh,
    logout,
    sendUserPaswordResetEmail,
    resetUserPassword,
    changeUserPassword} = require('../controllers/authCtrl')
const loginLimiter = require('../middleware/loginLimiter')
const verifyJWT = require('../middleware/verifyJWT')

router.route('/login')
    .post(loginLimiter, login)

router.route('/register')
    .post( register)

router.route('/verify-user/:id/:token')
    .get( verifyUser)

router.route('/refresh')
    .get(refresh)

router.route('/send-reset-password-email')
    .post(sendUserPaswordResetEmail)

router.route('/reset-password/:id/:token')
    .post(resetUserPassword)

router.route('/change-password')
    .post(verifyJWT,changeUserPassword)

router.route('/logout')
    .post(verifyJWT,logout)

module.exports = router