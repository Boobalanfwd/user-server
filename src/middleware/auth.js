import jwt from 'jsonwebtoken';
import { isUserBlacklisted } from '../controllers/authController.js';
import rateLimit from 'express-rate-limit';

export const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    if (isUserBlacklisted(decoded.identifier)) {
      return res.status(401).json({ message: 'User has been kicked out' });
    }
    
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many login attempts from this IP, try again later"
}); 