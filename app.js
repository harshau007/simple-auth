import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import express, { json } from "express";
import { connect } from "mongoose";
import path from "path";
import { fileURLToPath } from "url";
import { errorHandler } from "./middleware/errorHandler.js";
import authRoutes from "./routes/authRoutes.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
dotenv.config();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "views")));
// Routes
app.use("/api/auth", authRoutes);

// Error handling middleware
app.use(errorHandler);

// Connect to MongoDB
connect(process.env.MONGODB_URI, {})
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
