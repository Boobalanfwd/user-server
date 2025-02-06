import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import mongoose from 'mongoose';
import { User, initializeIndexes } from '../models/user.js';

const ONE_TIME_LINK_EXPIRY = 30; 
const blacklistedUsers = new Set();

export const resetDatabase = async (req, res) => {
  try {
    await mongoose.connection.dropDatabase();
    
    await initializeIndexes();
    
    res.json({ message: 'Database reset successfully' });
  } catch (error) {
    console.error('Reset database error:', error);
    res.status(500).json({ message: 'Failed to reset database' });
  }
};

export const register = async (req, res) => {
  try {
    const { identifier, password } = req.body;
    
    if (!identifier || !password) {
      return res.status(400).json({ 
        message: "Both identifier and password are required" 
      });
    }
    
    if (password.length < 5) {
      return res.status(400).json({ 
        message: "Password must be at least 5 characters" 
      });
    }

    const existingUser = await User.findOne({ identifier });
    if (existingUser) {
      return res.status(400).json({ 
        message: "This email or phone is already registered" 
      });
    }
    
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    const user = new User({
      identifier,
      password: hashedPassword
    });

    const savedUser = await user.save();
    
    res.status(201).json({ 
      message: "User registered successfully",
      userId: savedUser._id 
    });

  } catch (error) {
    console.error('Registration error:', error);
    
    if (error.code === 11000) {
      return res.status(400).json({ 
        message: "This email or phone is already registered" 
      });
    }
    
    res.status(500).json({ 
      message: "Server error during registration",
      error: error.message
    });
  }
};

export const login = async (req, res) => {
  try {
    const { identifier, password } = req.body;
    const user = await User.findOne({ identifier });
    
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (user.locked) {
      return res.status(403).json({ message: "Account locked" });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      user.loginAttempts += 1;
      if (user.loginAttempts >= process.env.MAX_LOGIN_ATTEMPTS) {
        user.locked = true;
      }
      await user.save();
      return res.status(401).json({ message: "Invalid credentials" });
    }

    user.loginAttempts = 0;
    await user.save();

    const token = jwt.sign({ identifier: user.identifier }, process.env.JWT_SECRET, {
      expiresIn: "1h"
    });
    
    res.json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: "Server error during login" });
  }
};

export const generateOneTimeLink = async (req, res) => {
  try {
    console.log('Request body:', req.body);
    const { identifier } = req.body;

    if (!identifier) {
      console.log('Missing identifier in request');
      return res.status(400).json({
        success: false,
        message: "Email or phone is required"
      });
    }

    console.log('Searching for user with identifier:', identifier);
    
    const user = await User.findOne({
      identifier: { $regex: new RegExp(`^${identifier}$`, 'i') }
    });

    if (!user) {
      console.log('User not found for identifier:', identifier);
      return res.status(404).json({
        success: false,
        message: "No user found with this email/phone"
      });
    }

    console.log('User found:', user._id);

    if (!process.env.JWT_SECRET) {
      console.error('JWT_SECRET is not set in environment variables');
      return res.status(500).json({
        success: false,
        message: "Server configuration error"
      });
    }

    try {
      const token = jwt.sign(
        {
          userId: user._id.toString(),
          identifier: user.identifier,
          type: 'one-time'
        },
        process.env.JWT_SECRET,
        { expiresIn: '30m' }
      );

      console.log('Token generated successfully');

      const loginLink = `http://localhost:3000/verify-link/${token}`;
      console.log('Login link created:', loginLink);

      return res.status(200).json({
        success: true,
        message: "Login link generated successfully",
        loginLink,
        expiresIn: '30 minutes'
      });

    } catch (jwtError) {
      console.error('JWT signing error:', jwtError);
      return res.status(500).json({
        success: false,
        message: "Error generating secure token"
      });
    }

  } catch (error) {
    console.error('Full error object:', error);
    console.error('Error stack:', error.stack);
    return res.status(500).json({
      success: false,
      message: "Failed to generate login link",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

export const verifyOneTimeLink = async (req, res) => {
  try {
    console.log('Verifying token:', req.params.token);
    const { token } = req.params;

    if (!token) {
      return res.status(400).json({
        success: false,
        message: "Token is required"
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log('Decoded token:', decoded);
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }

    const accessToken = jwt.sign(
      { 
        userId: user._id,
        identifier: user.identifier 
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    return res.status(200).json({
      success: true,
      message: "Login successful",
      token: accessToken
    });

  } catch (error) {
    console.error('Token verification error:', error);
    return res.status(401).json({
      success: false,
      message: error instanceof jwt.TokenExpiredError 
        ? "Link has expired" 
        : "Invalid link"
    });
  }
};

export const getServerTime = async (req, res) => {
  res.json({
    serverTime: new Date().toISOString(),
    user: req.user.identifier
  });
};

export const kickoutUser = async (req, res) => {
  try {
    const { identifier } = req.body;
    const user = await User.findOne({ identifier });
    
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    blacklistedUsers.add(identifier);
    
    res.json({ 
      message: "User has been kicked out successfully",
      identifier
    });
  } catch (error) {
    console.error('Kickout error:', error);
    res.status(500).json({ message: "Failed to kickout user" });
  }
};

export const isUserBlacklisted = (identifier) => {
  return blacklistedUsers.has(identifier);
};