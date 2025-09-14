const nodemailer = require("nodemailer");
const dotenv = require("dotenv");
dotenv.config();

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: { 
    user: process.env.NodeMailerUser,
    pass: process.env.NodeMailerPassword
  }
});

// Tourist OTP
exports.otpVerificationTourist = async (name, email, randomOTP) => {
  try {
    await transporter.sendMail({
      from: `"Your App" <${process.env.NodeMailerUser}>`,
      to: email,
      subject: "Tourist OTP Verification",
      text: `Hello ${name}, your OTP is ${randomOTP}. It will expire in 10 minutes.`,
      html: `<h2>Hello ${name}</h2><p>OTP: ${randomOTP}</p><p>Valid for 10 minutes</p>`
    });
    console.log("✅ Tourist OTP sent");
  } catch (e) {
    console.error("❌ Tourist OTP failed:", e);
    throw e;
  }
};

// Researcher OTP
exports.otpVerificationResearcher = async (name, email, randomOTP) => {
  try {
    await transporter.sendMail({
      from: `"Your App" <${process.env.NodeMailerUser}>`,
      to: email,
      subject: "Researcher OTP Verification",
      text: `Hello ${name}, your OTP is ${randomOTP}. It will expire in 10 minutes.`,
      html: `<h2>Hello ${name}</h2><p>OTP: ${randomOTP}</p><p>Valid for 10 minutes</p>`
    });
    console.log("✅ Researcher OTP sent");
  } catch (e) {
    console.error("❌ Researcher OTP failed:", e);
    throw e;
  }
};

// Change Email OTP
exports.changeEmail = async (name, email, randomOTP) => {
  try {
    await transporter.sendMail({
      from: `"Your App" <${process.env.NodeMailerUser}>`,
      to: email,
      subject: "Confirm New Email – OTP",
      text: `Hi ${name}, OTP: ${randomOTP}. It will expire in 10 minutes.`,
      html: `<h2>Hi ${name}</h2><p>OTP: ${randomOTP}</p><p>Valid for 10 minutes</p>`
    });
    console.log("✅ Change Email OTP sent");
  } catch (e) {
    console.error("❌ Change Email OTP failed:", e);
    throw e;
  }
};

// Helper: Send OTP based on role
exports.sendOTPByRole = (role) => {
  return role === "researcher" ? exports.otpVerificationResearcher : exports.otpVerificationTourist;
};
