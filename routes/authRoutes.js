import { Router } from "express";
import {
  forgotPassword,
  login,
  logout,
  protect,
  resetPassword,
  signup,
  updatePassword,
} from "../controllers/authControllers.js";

const router = Router();

router.post("/signup", signup);
router.post("/login", login);
router.post("/forgot-password", forgotPassword);
router.get("/reset-password/:token", resetPassword);
router.post("/update-password", updatePassword);
router.post("/logout", logout);

// Protected route example
router.get("/protected", protect, (req, res) => {
  res.json({ message: "This is a protected route", user: req.user });
});

export default router;
