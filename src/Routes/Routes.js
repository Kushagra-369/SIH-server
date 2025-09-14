const express = require("express");
const router = express.Router();

const { createuser ,  getUserById , UserOtpVerify , LogInUser,ResendOTP ,newEmail,newEmailVerify} = require("../Controller/UserController");
const {UserAuthenticate , UserAuthorize} = require("../middleware/UserAuth")


router.post('/createuser', createuser);
router.post('/LogInUser', LogInUser);
router.get('/getUserById/:id', getUserById);
router.post('/user_otp_verify/:id', UserOtpVerify);
router.get('/ResendOTP/:id', ResendOTP);
router.put('/newEmail/:id', UserAuthenticate, UserAuthorize, newEmail);
router.post('/newEmailVerify/:id', UserAuthenticate, UserAuthorize, newEmailVerify);

module.exports = router;
