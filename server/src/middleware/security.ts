import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { config } from '../config';

// Helmet security headers
export const helmetMiddleware = helmet();

// CORS configuration
export const corsMiddleware = cors({
  origin: config.corsOrigin,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
});

// Rate limiting for auth routes (100 requests per 15 minutes)
export const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many authentication attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

// General rate limiting (1000 requests per 15 minutes)
export const generalRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

// CSRF protection with double-submit cookie pattern
export function csrfProtection(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  // Skip CSRF for GET, HEAD, OPTIONS
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  const cookieToken = req.cookies?.['csrf-token'];
  const headerToken = req.headers['x-csrf-token'];

  if (typeof cookieToken !== 'string' || typeof headerToken !== 'string') {
    res.status(403).json({ error: 'CSRF token validation failed' });
    return;
  }

  const cookieBuf = Buffer.from(cookieToken);
  const headerBuf = Buffer.from(headerToken);

  if (
    cookieBuf.length === 0 ||
    cookieBuf.length !== headerBuf.length ||
    !crypto.timingSafeEqual(cookieBuf, headerBuf)
  ) {
    res.status(403).json({ error: 'CSRF token validation failed' });
    return;
  }

  next();
}

// Generate CSRF token endpoint helper
export function generateCsrfToken(req: Request, res: Response): void {
  const token = crypto.randomBytes(32).toString('hex');
  res.cookie('csrf-token', token, {
    httpOnly: false,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  });
  res.json({ csrfToken: token });
}
