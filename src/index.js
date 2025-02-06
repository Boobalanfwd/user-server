import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import rateLimit from "express-rate-limit";
import cors from "cors";
import { User } from "./models/user.js";
import connectDB from "./config/database.js";
import authRoutes from "./routes/authRoutes.js";

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

app.options("*", cors());

const MAX_LOGIN_ATTEMPTS = 3;
const ONE_TIME_LINK_EXPIRY = 30;

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many login attempts from this IP, try again later",
});

app.post("/api/login", loginLimiter, async (req, res) => {
  const { identifier, password } = req.body;
  const user = await User.findOne({ identifier });

  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  if (user.locked) {
    return res.status(403).json({ message: "Account locked" });
  }

  if (!(await bcrypt.compare(password, user.password))) {
    user.loginAttempts += 1;
    if (user.loginAttempts >= MAX_LOGIN_ATTEMPTS) {
      user.locked = true;
    }
    await user.save();
    return res.status(401).json({ message: "Invalid credentials" });
  }

  user.loginAttempts = 0;
  await user.save();

  const token = jwt.sign(
    { identifier: user.identifier },
    process.env.JWT_SECRET,
    {
      expiresIn: "1h",
    }
  );
  res.json({ token });
});

app.post("/api/register", async (req, res) => {
  try {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
      return res.status(400).json({
        message: "Both identifier and password are required",
      });
    }

    if (password.length < 5) {
      return res.status(400).json({
        message: "Password must be at least 5 characters",
      });
    }

    const existingUser = await User.findOne({ identifier });
    if (existingUser) {
      return res.status(400).json({
        message: "User already exists",
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({
      identifier,
      password: hashedPassword,
      loginAttempts: 0,
      locked: false,
    });

    const savedUser = await user.save();

    if (!savedUser) {
      throw new Error("Failed to save user");
    }

    res.status(201).json({
      message: "User registered successfully",
      userId: savedUser._id,
    });
  } catch (error) {
    console.error("Registration error:", error);

    if (error.name === "ValidationError") {
      return res.status(400).json({
        message: "Invalid input data",
        details: error.message,
      });
    }

    if (error.code === 11000) {
      return res.status(400).json({
        message: "This email or phone is already registered",
      });
    }

    res.status(500).json({
      message: "Server error during registration",
      details: error.message,
    });
  }
});

app.post("/api/request-login-link", async (req, res) => {
  try {
    const { identifier } = req.body;
    
    if (!identifier) {
      return res.status(400).json({ success: false, message: "Email or phone is required" });
    }

    const user = await User.findOne({ identifier });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const oneTimeToken = jwt.sign(
      { userId: user._id.toString(), type: 'one-time' },
      process.env.JWT_SECRET,
      { expiresIn: '30m' }
    );

    if (!user.oneTimeLinks) {
      user.oneTimeLinks = [];
    }

    const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
    user.oneTimeLinks.push({
      token: oneTimeToken,
      expiresAt,
      used: false
    });

    await user.save();
    const loginLink = `http://localhost:3000/verify-link/${oneTimeToken}`;

    res.json({
      success: true,
      message: "Login link generated successfully",
      loginLink,
      expiresAt
    });

  } catch (error) {
    console.error('Link generation error:', error);
    res.status(500).json({ success: false, message: "Failed to generate link" });
  }
});

app.get("/api/verify-link/:token", async (req, res) => {
  try {
    const { token } = req.params;
    
    if (!token) {
      return res.status(400).json({ success: false, message: "Token is required" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({
      _id: decoded.userId,
      'oneTimeLinks.token': token,
      'oneTimeLinks.used': false,
      'oneTimeLinks.expiresAt': { $gt: new Date() }
    });

    if (!user) {
      return res.status(401).json({ success: false, message: "Invalid or expired link" });
    }

    const tokenIndex = user.oneTimeLinks.findIndex(link => link.token === token);
    if (tokenIndex !== -1) {
      user.oneTimeLinks[tokenIndex].used = true;
      await user.save();
    }

    const accessToken = jwt.sign(
      { userId: user._id, identifier: user.identifier },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      success: true,
      message: "Login successful",
      token: accessToken,
      user: { identifier: user.identifier }
    });

  } catch (error) {
    console.error('Token verification error:', error);
    if (error instanceof jwt.TokenExpiredError) {
      return res.status(401).json({ success: false, message: "Link has expired" });
    }
    if (error instanceof jwt.JsonWebTokenError) {
      return res.status(401).json({ success: false, message: "Invalid link" });
    }
    res.status(500).json({ success: false, message: "Error verifying link" });
  }
});

const blacklistedUsers = new Set();

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (blacklistedUsers.has(decoded.identifier)) {
      return res.status(401).json({ message: "User has been kicked out" });
    }

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

app.get("/api/time", verifyToken, (req, res) => {
  res.json({
    serverTime: new Date().toISOString(),
    user: req.user.identifier,
  });
});

app.post("/api/admin/kickout", async (req, res) => {
  const { identifier } = req.body;

  try {
    const user = await User.findOne({ identifier });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    blacklistedUsers.add(identifier);

    res.json({
      message: "User has been kicked out successfully",
      identifier,
    });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/test", (req, res) => {
  res.json({ message: "Server is running!" });
});

// Routes
app.use("/api", authRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ success: false, message: 'Something went wrong!' });
});

const PORT = process.env.PORT || 8080;

const startServer = async () => {
  try {
    await connectDB();
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();
