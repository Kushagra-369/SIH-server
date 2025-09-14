const UserModel = require("../Model/UserModel");
const { otpVerificationTourist, otpVerificationResearcher, changeEmail, sendOTPByRole } = require("../Mail/UserMail");
const { errorHandlingdata } = require('../Error/ErrorHandling');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const dotenv = require("dotenv");
dotenv.config();



exports.createuser = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password || !role) {
      return res.status(400).send({ status: false, msg: "All fields are required" });
    }

    // 🔹 Validate password before saving
    const { ValidPassword } = require("../Validation/AllVallidatios");
    if (!ValidPassword(password)) {
      return res.status(400).send({
        status: false,
        msg: "Password is not valid. Minimum 6 chars, at least 1 letter & 1 number"
      });
    }

    // 🔹 Check if user already exists
    let existingUser = await UserModel.findOne({ email });
    if (existingUser) {
      if (existingUser.Verification.user.isDeleted) {
        return res.status(400).send({ status: false, msg: "User deleted" });
      }
      if (!existingUser.Verification.admin.isAccountActive) {
        return res.status(400).send({ status: false, msg: "Blocked by admin" });
      }
      if (existingUser.Verification.user.isVerify) {
        return res.status(200).send({
          status: true,
          msg: "already_verified",
          data: {
            name: existingUser.name,
            email: existingUser.email,
            _id: existingUser._id,
            role: existingUser.role
          }
        });
      }

      // Resend OTP if not verified
      const randomOTP = Math.floor(1000 + Math.random() * 9000);
      const expireOTPAt = new Date(Date.now() + 10 * 60 * 1000);
      existingUser.Verification.user.UserOTP = randomOTP;
      existingUser.Verification.user.expireOTP = expireOTPAt;
      await existingUser.save();

      const sendOTP = sendOTPByRole(role);
      await sendOTP(existingUser.name, existingUser.email, randomOTP);

      return res.status(200).send({
        status: true,
        msg: "OTP resent successfully",
        data: {
          name: existingUser.name,
          email: existingUser.email,
          _id: existingUser._id,
          role: existingUser.role
        }
      });
    }

    // 🔹 Create new user
    const randomOTP = Math.floor(1000 + Math.random() * 9000);
    const expireOTPAt = new Date(Date.now() + 10 * 60 * 1000);

    const newUser = await UserModel.create({
      name,
      email,
      password, // pre-save hook hashes this
      role,
      Verification: { user: { UserOTP: randomOTP, expireOTP: expireOTPAt } }
    });

    const sendOTP = sendOTPByRole(role);
    await sendOTP(newUser.name, newUser.email, randomOTP);

    return res.status(201).send({
      status: true,
      msg: "User created and OTP sent",
      data: {
        name: newUser.name,
        email: newUser.email,
        _id: newUser._id,
        role: newUser.role
      }
    });

  } catch (e) {
    return res.status(500).send({ status: false, msg: e.message });
  }
};

exports.UserOtpVerify = async (req, res) => {
  try {
    const { otp } = req.body;
    const { id } = req.params;
    if (!otp) return res.status(400).send({ status: false, msg: "Please provide OTP" });

    const user = await UserModel.findById(id);
    if (!user) return res.status(404).send({ status: false, msg: "User not found" });

    const dbOtp = user.Verification.user.UserOTP;
    const expireTime = user.Verification.user.expireOTP;

    if (Date.now() > new Date(expireTime)) return res.status(400).send({ status: false, msg: "OTP expired" });
    if (otp != dbOtp) return res.status(400).send({ status: false, msg: "Wrong OTP" });

    await UserModel.findByIdAndUpdate(id, { $set: { "Verification.user.isVerify": true } });
    return res.status(200).send({ status: true, msg: "User verified successfully" });

  } catch (e) { errorHandlingdata(e, res) }
};

exports.LogInUser = async (req, res) => {
    try {

        const data = req.body
        const { email, password } = data

        const CheckUser = await UserModel.findOne({ email: email, role: "user" })

        if (!CheckUser) return res.status(400).send({ status: false, msg: "User Not Found" })

        const userVerification = CheckUser.Verification?.user || {};
        const adminVerification = CheckUser.Verification?.admin || {};

        const comparePass = await bcrypt.compare(password, CheckUser.password)

        if (!comparePass) return res.status(400).send({ status: false, msg: "Wrong Password" })

        if (CheckUser) {
            console.log(CheckUser);
            const DBDATABASE = { name: CheckUser.name, email: CheckUser.email, _id: CheckUser._id }

            const userVerification = CheckUser.Verification?.user || {};
            const adminVerification = CheckUser.Verification?.admin || {};

            const { isDeleted, isVerify, isAccountActive } = userVerification
            if (userVerification.isDeleted) return res.status(400).send({ status: false, msg: 'User already deleted' });
            if (!userVerification.isVerify) return res.status(400).send({ status: false, msg: ' please verify your OTP' });
            if (!adminVerification.isAccountActive) return res.status(400).send({ status: false, msg: 'User is blocked by admin' });
        }

        const DBDATA = { profileIMG: CheckUser.profileIMG, name: CheckUser.name, email: CheckUser.email }

        const token = jwt.sign({ userId: CheckUser._id }, process.env.JWT_User_SECRET_KEY, { expiresIn: '24h' })
        return res.status(200).send({ status: true, msg: "Login Successfully", data: { token, id: CheckUser._id, DBDATA } })
    }

    catch (e) {
        errorHandlingdata(e, res)
    }

}

exports.getUserById = async (req, res) => {
    try {

        const id = req.params.id

        const DB = await UserModel.findById(id)

        if (!DB) return res.status(400).send({ status: false, msg: 'Data Not Found' })
        return res.status(200).send({ status: true, data: DB })
    }
    catch (e) { res.status(500).send({ status: false, msg: e.message }) }
}

exports.ResendOTP = async (req, res) => {
    try {
        const id = req.params.id;
        const user = await UserModel.findById(id);
        if (!user) return res.status(400).send({ status: false, msg: "User not found" });

        const randomOTP = Math.floor(1000 + Math.random() * 9000);

        const updatedUser = await UserModel.findByIdAndUpdate(
            id,
            { $set: { 'verification.user.userOTP': randomOTP } },
            { new: true }
        );

        if (!updatedUser) {
            return res.status(500).send({ status: false, msg: "Failed to update OTP" });
        }

        otpVerificationResearcher(updatedUser.name, updatedUser.email, randomOTP);

        res.status(200).send({ status: true, msg: "OTP sent successfully" });
    } catch (e) {
        console.error(e);
        errorHandlingdata(e, res);
    }
};

exports.newEmail = async (req, res) => {
    try {
        const { id } = req.params;
        const { password, newEmail } = req.body;

        if (!id || !password || !newEmail) {
            return res.status(400).send({ status: false, msg: "Missing required fields" });
        }

        // Find the user by ID
        const user = await UserModel.findById(id);
        if (!user) return res.status(404).send({ status: false, msg: "User not found" });

        // Check if new email is already in use
        const emailExists = await UserModel.findOne({ email: newEmail, role: 'user' });
        if (emailExists) {
            return res.status(400).send({ status: false, msg: "Email already registered" });
        }

        // Check password
        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (!isPasswordCorrect) {
            return res.status(400).send({ status: false, msg: "Wrong password" });
        }

        // Account status checks
        const userVerification = user.Verification?.user || {};
        const adminVerification = user.Verification?.admin || {};

        if (userVerification.isDeleted) {
            return res.status(400).send({ status: false, msg: "User already deleted" });
        }

        if (!adminVerification?.isAccountActive) {
            return res.status(400).send({ status: false, msg: "User is blocked by admin" });
        }

        // Generate OTP and expiry time
        const randomOTP = Math.floor(1000 + Math.random() * 9000);
        const expireOTPAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes validity

        // Update user document with new email OTP info
        await UserModel.findByIdAndUpdate(
            id,
            {
                $set: {
                    "Verification.email.newEmail": newEmail,
                    "Verification.email.UserOTP": randomOTP,
                    "Verification.email.expireOTP": expireOTPAt
                }
            },
            { new: true }
        );

        // Send email with OTP
        changeEmail(user.name, newEmail, randomOTP);

        return res.status(200).send({ status: true, msg: "OTP sent to new email successfully" });

    } catch (e) {
        errorHandlingdata(e, res);
    }
};

exports.newEmailVerify = async (req, res) => {
    try {
        const data = req.body
        const otp = req.body.otp;
        const id = req.params.id;
        console.log(otp, id)

        const randomOTP = Math.floor(1000 + Math.random() * 9000)

        const UpdateOTP = await UserModel.findOneAndUpdate(
            { email: data.email, 'Verification.user.isDeleted': false, 'Verification.admin.isAccountActive': true },
            {
                $set: {
                    "Verification.user.UserOTP": randomOTP,
                    // "Verification.user.expireOTP": expireOTPAt
                }
            },
            { new: true }
        );

        const CheckId = await UserModel.findById(id);
        if (!CheckId) return res.status(400).send({ status: false, msg: "User not found" });

        const nowTime = Math.floor((Date.now()) / 1000);
        const DBTime = CheckId.Verification.email.expireTime

        if (nowTime >= DBTime) return res.status(400).send({ status: false, msg: "OTP Expired" });

        if (otp == CheckId.Verification.email.UserOTP) {
            await UserModel.findByIdAndUpdate({ _id: id },
                { $set: { email: CheckId.Verification.email.newEmail, 'Verification.email.UserOTP': randomOTP } });
            res.status(200).send({ status: true, msg: "Email Verify successfully" });
        }
        else {
            res.status(400).send({ status: false, msg: "Wrong OTP" });
        }


    }
    catch (e) { errorHandlingdata(e, res) }
};

