import rateLimit from 'express-rate-limit';

export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 'fail',
    message:
      'Too many requests from this IP, please try again after 15 minutes',
  },
});

export const authLimiter = rateLimit({
  windowMs: 50 * 60 * 1000,
  max: 10,
  message: {
    status: 'fail',
    message:
      'Too many login attempts from this IP, please try again after an hour',
  },
});
