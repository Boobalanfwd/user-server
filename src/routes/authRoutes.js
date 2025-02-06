import express from 'express';
import { verifyToken, loginLimiter } from '../middleware/auth.js';
import {
  register,
  login,
  generateOneTimeLink,
  verifyOneTimeLink,
  getServerTime,
  kickoutUser,
  resetDatabase
} from '../controllers/authController.js';

const router = express.Router();

// Auth routes
router.post('/register', register);
router.post('/login', loginLimiter, login);
router.post('/request-login-link', generateOneTimeLink);
router.get('/verify-link/:token', verifyOneTimeLink);
router.get('/time', verifyToken, getServerTime);
router.post('/admin/kickout', kickoutUser);
router.post('/reset-database', resetDatabase);

export default router;