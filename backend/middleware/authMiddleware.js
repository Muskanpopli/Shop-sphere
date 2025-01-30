import User from '../models/userModel.js';
import jwt from 'jsonwebtoken';

const protect = async (req, res, next) => {
  try {
    console.log('Cookies:', req.cookies);
    const token = req.cookies?.jwt;

    if (!token) {
      res.statusCode = 401;
      throw new Error('Authentication failed: Token not provided.');
    }
      // Log the token before verification
      console.log('Token:', token);
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

    if (!decodedToken) {
      res.statusCode = 401;
      throw new Error('Authentication failed: Invalid token.');
    }

    req.user = await User.findById(decodedToken.userId).select('-password');
    console.log('Authenticated User:', req.user);

    next();
  } catch (error) {
    next(error);
  }
};

// Middleware to check if the user is an admin.
const admin = (req, res, next) => {
  try {
    if (!req.user || !req.user.isAdmin) {
      res.statusCode = 401;
      throw new Error('Authorization failed: Not authorized as an admin.');
    }
    next();
  } catch (error) {
    next(error);
  }
};

export { protect, admin };
