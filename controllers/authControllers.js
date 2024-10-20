import bcryptjs from "bcryptjs";
import * as crypto from "crypto";
import jsonwebtoken from "jsonwebtoken";
import path from "path";
import { fileURLToPath } from "url";
import User from "../models/User.js";
import { sendResetPasswordEmail } from "../utils/sendEmail.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const setTokenCookie = (res, token) => {
  const cookieOptions = {
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000), // 1 day
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // Use secure cookies in production
    sameSite: "none", // Protect against CSRF
  };
  res.cookie("token", token, cookieOptions);
};

const signToken = (id) => {
  return jsonwebtoken.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: "1d",
  });
};

export async function signup(req, res, next) {
  try {
    const { email, password } = req.body;
    const user = await User.create({ email, password });
    const token = signToken(user._id);
    setTokenCookie(res, token);
    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    next(error);
  }
}

export async function login(req, res, next) {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ message: "Invalid email or password" });
    }
    const token = signToken(user._id);
    setTokenCookie(res, token);
    res.json({ message: "Logged in successfully" });
  } catch (error) {
    next(error);
  }
}

export async function forgotPassword(req, res, next) {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res
        .status(404)
        .json({ message: "No user with that email address" });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    user.resetPasswordToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");
    user.resetPasswordExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();

    const resetURL = `${req.protocol}://${req.get(
      "host"
    )}/api/auth/reset-password/${resetToken}`;
    await sendResetPasswordEmail(user.email, resetURL);

    res.json({ message: "Password reset email sent" });
  } catch (error) {
    next(error);
  }
}

export async function resetPassword(req, res, next) {
  try {
    const hashedToken = crypto
      .createHash("sha256")
      .update(req.params.token)
      .digest("hex");
    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    // Instead of changing the password here, we'll render the reset password form
    res.sendFile(path.join(__dirname, "../views/resetPassword.html"));
  } catch (error) {
    next(error);
  }
}

export async function updatePassword(req, res, next) {
  try {
    const { email, currentPassword, newPassword, confirmPassword } = req.body;
    const user = await User.findOne({
      email,
    });

    if (!(await bcryptjs.compare(currentPassword, user.password))) {
      return res.status(401).json({ message: "Current password is incorrect" });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: "New passwords do not match" });
    }

    user.password = newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    const token = signToken(user._id);
    setTokenCookie(res, token);

    res.json({ message: "Password updated successfully" });
  } catch (error) {
    next(error);
  }
}

export function logout(req, res) {
  res.clearCookie("token");
  res.json({ message: "Logged out successfully" });
}

export async function protect(req, res, next) {
  try {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ message: "You are not logged in" });
    }
    const decoded = jsonwebtoken.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({ message: "User no longer exists" });
    }
    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
}
