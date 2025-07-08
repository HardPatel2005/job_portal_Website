// backend/middlewares/rate.js

import rateLimit from 'express-rate-limit';

// Global API Rate Limiter
export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per 15 minutes
  message: "Too many requests from this IP, please try again after 15 minutes.",
  statusCode: 429, // Too Many Requests
  headers: true, // Include X-RateLimit-* headers
  handler: (req, res, next, options) => {
    console.warn(`[RATE-LIMIT] Rate limit exceeded for IP: ${req.ip} on route ${req.originalUrl}`);
    res.status(options.statusCode).send(options.message);
  }
});

// Stricter Rate Limiter for Authentication Routes (e.g., login, register)
export const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 5, // Limit each IP to 5 requests per 5 minutes
  message: "Too many authentication attempts from this IP, please try again after 5 minutes.",
  statusCode: 429,
  headers: true,
  handler: (req, res, next, options) => {
    console.warn(`[RATE-LIMIT] Auth rate limit exceeded for IP: ${req.ip} on route ${req.originalUrl}`);
    res.status(options.statusCode).send(options.message);
  }
});