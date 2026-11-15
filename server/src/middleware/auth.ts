import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { config } from '../config';
import { query } from '../db';

export interface AuthUser {
  id: string;
  username: string;
  email: string;
}

export interface AuthRequest extends Request {
  user?: AuthUser;
}

export async function authMiddleware(
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  // Extract token from cookie or Authorization header
  let token = req.cookies?.token;
  if (!token) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    }
  }

  if (!token) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  try {
    const decoded = jwt.verify(token, config.jwtSecret) as {
      id: string;
      username: string;
      email: string;
    };

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const sessionRes = await query<{ is_active: boolean; expires_at: Date; is_email_verified: any }>(
      `SELECT s.is_active, s.expires_at, u.is_email_verified
       FROM sessions s
       JOIN users u ON s.user_id = u.id
       WHERE s.token_hash = $1 LIMIT 1`,
      [tokenHash]
    );

    if (
      sessionRes.rows.length > 0 &&
      (!sessionRes.rows[0].is_active ||
        new Date(sessionRes.rows[0].expires_at) < new Date())
    ) {
      res.status(401).json({ error: 'Session expired or revoked' });
      return;
    }

    if (
      sessionRes.rows.length > 0 &&
      config.requireEmailVerification &&
      process.env.NODE_ENV !== 'test' &&
      !Boolean(sessionRes.rows[0].is_email_verified)
    ) {
      res.status(403).json({ error: 'Email verification required', needsVerification: true });
      return;
    }

    req.user = {
      id: decoded.id,
      username: decoded.username,
      email: decoded.email,
    };
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}
