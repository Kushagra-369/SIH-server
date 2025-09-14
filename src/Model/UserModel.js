const mongoose = require("mongoose");
const { ValidName, ValidEmail, ValidPassword } = require("../Validation/AllVallidatios");
const bcrypt = require("bcrypt");

const userSchema = new mongoose.Schema(
  {
    profileIMG: {
      type: {
        secure_url: { type: String, required: true, trim: true },
        public_id: { type: String, required: true, trim: true },
      },
      required: false, // optional field
    },
    name: {
      type: String,
      required: [true, "Name is required"],
      validate: [ValidName, "Name is not valid"],
      trim: true,
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      validate: [ValidEmail, "Email is not valid"],
      trim: true,
      lowercase: true,
      unique: true,
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      validate: [ValidPassword, "Password is not valid"],
      trim: true,
    },
    Verification: {
      email: {
        newEmail: { type: String, trim: true },
        UserOTP: { type: Number, default: 0 },
        expireOTP: { type: Date, default: null },
      },
      user: {
        UserOTP: { type: Number, default: 0 },
        isDeleted: { type: Boolean, default: false },
        isVerify: { type: Boolean, default: false },
        isOtpVerified: { type: Boolean, default: false },
        expireOTP: { type: Date, default: null },
      },
      admin: {
        isAccountActive: { type: Boolean, default: true },
        AdminOTP: { type: Number, default: 0 },
        isOtpVerified: { type: Boolean, default: false },
        expireOTP: { type: Date, default: null },
      },
    },
    role: {
      type: String,
      enum: ["tourist", "researcher", "admin"], // fixed enum
      required: true,
      trim: true,
    },
  },
  { timestamps: true }
);

// Hash password before saving
userSchema.pre("save", async function (next) {
  try {
    if (this.isModified("password")) {
      this.password = await bcrypt.hash(this.password, 10);
    }
    next();
  } catch (err) {
    next(err);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model("User", userSchema);
