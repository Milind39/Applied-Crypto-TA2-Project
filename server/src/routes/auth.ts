import { Router, Response } from 'express';
import { body, validationResult } from 'express-validator';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config';
import { query } from '../db';
import { authMiddleware, AuthRequest } from '../middleware/auth';
import { authRateLimit } from '../middleware/security';
import { sendVerificationEmail, sendPasswordResetEmail } from '../services/emailService';

const router = Router();

// Helper to issue JWT and set cookie
function issueToken(
  res: Response,
  user: { id: string; username: string; email: string }
): string {
  const token = jwt.sign(
    { id: user.id, username: user.username, email: user.email },
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn as jwt.SignOptions['expiresIn'] }
  );

  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000, // 24h
  });

  return token;
}

// POST /api/auth/register
router.post(
  '/register',
  authRateLimit,
  [
    body('username')
      .isString()
      .trim()
      .isLength({ min: 3, max: 50 })
      .withMessage('Username must be 3-50 characters'),
    body('email')
      .isEmail()
      .normalizeEmail()
      .withMessage('Valid email required'),
    body('password')
      .isString()
      .isLength({ min: 8 })
      .matches(/[a-z]/)
      .withMessage('Password must contain a lowercase letter')
      .matches(/[A-Z]/)
      .withMessage('Password must contain an uppercase letter')
      .matches(/\d/)
      .withMessage('Password must contain a digit'),
    body('confirmPassword')
      .isString()
      .custom((value, { req }) => value === req.body.password)
      .withMessage('Passwords must match'),
  ],
  async (req: AuthRequest, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const { username, email, password } = req.body;
    const isEmailVerified = process.env.NODE_ENV === 'test' || !config.requireEmailVerification;

    try {
      // Check if user already exists
      const existing = await query(
        'SELECT id FROM users WHERE username = $1 OR email = $2',
        [username, email]
      );
      if (existing.rows.length > 0) {
        res.status(409).json({ error: 'Username or email already taken' });
        return;
      }

      const passwordHash = await argon2.hash(password, {
        type: argon2.argon2id,
      });
      const id = uuidv4();

      await query(
        `INSERT INTO users (id, username, email, password_hash, is_email_verified)
         VALUES ($1, $2, $3, $4, $5)`,
        [id, username, email, passwordHash, isEmailVerified]
      );

      // Generate verification token and send verification email
      const verificationToken = crypto.randomBytes(48).toString('hex');
      const verificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
      await query(
        `INSERT INTO verification_tokens (email, token, expiry)
         VALUES ($1, $2, $3)`,
        [email, verificationToken, verificationExpiry]
      );

      // Asynchronously send email (don't block registration if SMTP takes a moment)
      sendVerificationEmail(email, verificationToken).catch((err) => {
        console.warn('[Auth] Verification email dispatch notice:', err.message);
      });

      // If email verification is required and not yet verified, do NOT log the user in!
      if (!isEmailVerified) {
        res.status(201).json({
          message: 'User registered successfully. A verification link has been sent to your email. Please verify your email before logging in.',
          user: { id, username, email, isEmailVerified: false },
          needsVerification: true,
        });
        return;
      }

      // If email is verified (e.g. test environment), create session & issue token
      const user = { id, username, email };
      const token = issueToken(res, user);
      const tokenHash = crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

      await query(
        `INSERT INTO sessions (user_id, token_hash, expires_at)
         VALUES ($1, $2, $3)`,
        [id, tokenHash, expiresAt]
      );

      res.status(201).json({
        message: 'User registered successfully.',
        user: { id, username, email, isEmailVerified: true },
        token,
      });
    } catch (err) {
      console.error('[Auth] Registration error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// POST /api/auth/verify-email
router.post(
  '/verify-email',
  [body('token').isString().notEmpty().withMessage('Verification token required')],
  async (req: AuthRequest, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const { token } = req.body;

    try {
      const tokenRes = await query<{ id: string; email: string; expiry: Date }>(
        'SELECT id, email, expiry FROM verification_tokens WHERE token = $1 LIMIT 1',
        [token]
      );

      if (tokenRes.rows.length === 0) {
        res.status(400).json({ error: 'Invalid or expired verification token' });
        return;
      }

      const record = tokenRes.rows[0];
      const now = new Date();

      if (new Date(record.expiry) < now) {
        const newToken = crypto.randomBytes(48).toString('hex');
        const newExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await query(
          'UPDATE verification_tokens SET token = $1, expiry = $2 WHERE id = $3',
          [newToken, newExpiry, record.id]
        );
        sendVerificationEmail(record.email, newToken).catch(() => { });
        res.status(400).json({
          error: 'Verification token has expired. A fresh verification link has been sent to your email.',
          expired: true,
        });
        return;
      }

      await query('UPDATE users SET is_email_verified = TRUE, updated_at = NOW() WHERE email = $1', [
        record.email,
      ]);
      await query('DELETE FROM verification_tokens WHERE email = $1', [record.email]);

      res.json({
        message: 'Email verified successfully! You may now log in.',
        email: record.email,
      });
    } catch (err) {
      console.error('[Auth] Verify email error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// GET /api/auth/verify-email?token=...
router.get(
  '/verify-email',
  async (req: AuthRequest, res: Response): Promise<void> => {
    const token = req.query.token as string;
    if (!token) {
      res.status(400).json({ error: 'Verification token required' });
      return;
    }

    try {
      const tokenRes = await query<{ id: string; email: string; expiry: Date }>(
        'SELECT id, email, expiry FROM verification_tokens WHERE token = $1 LIMIT 1',
        [token]
      );

      if (tokenRes.rows.length === 0) {
        res.status(400).json({ error: 'Invalid or expired verification token' });
        return;
      }

      const record = tokenRes.rows[0];
      if (new Date(record.expiry) < new Date()) {
        const newToken = crypto.randomBytes(48).toString('hex');
        const newExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await query(
          'UPDATE verification_tokens SET token = $1, expiry = $2 WHERE id = $3',
          [newToken, newExpiry, record.id]
        );
        sendVerificationEmail(record.email, newToken).catch(() => { });
        res.status(400).json({
          error: 'Verification token has expired. A fresh verification link has been sent to your email.',
          expired: true,
        });
        return;
      }

      await query('UPDATE users SET is_email_verified = TRUE, updated_at = NOW() WHERE email = $1', [
        record.email,
      ]);
      await query('DELETE FROM verification_tokens WHERE email = $1', [record.email]);

      res.redirect(`${config.frontendUrl}/login?verified=true`);
    } catch (err) {
      console.error('[Auth] Verify email error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// POST /api/auth/resend-verification
router.post(
  '/resend-verification',
  [body('email').isEmail().normalizeEmail().withMessage('Valid email required')],
  async (req: AuthRequest, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const { email } = req.body;

    try {
      const userRes = await query<{ id: string; is_email_verified: boolean }>(
        'SELECT id, is_email_verified FROM users WHERE email = $1',
        [email]
      );

      if (userRes.rows.length === 0) {
        res.json({ message: 'If the email exists, a verification link has been sent.' });
        return;
      }

      if (userRes.rows[0].is_email_verified) {
        res.status(400).json({ error: 'This email is already verified.' });
        return;
      }

      await query('DELETE FROM verification_tokens WHERE email = $1', [email]);
      const newToken = crypto.randomBytes(48).toString('hex');
      const expiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
      await query(
        'INSERT INTO verification_tokens (email, token, expiry) VALUES ($1, $2, $3)',
        [email, newToken, expiry]
      );

      await sendVerificationEmail(email, newToken);

      res.json({ message: 'Verification email resent successfully.' });
    } catch (err) {
      console.error('[Auth] Resend verification error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// POST /api/auth/login
router.post(
  '/login',
  authRateLimit,
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isString().notEmpty(),
  ],
  async (req: AuthRequest, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const { email, password } = req.body;

    try {
      const result = await query(
        'SELECT id, username, email, password_hash, is_email_verified FROM users WHERE email = $1',
        [email]
      );

      if (result.rows.length === 0) {
        res.status(401).json({ error: 'Invalid credentials' });
        return;
      }

      const user = result.rows[0];
      const validPassword = await argon2.verify(user.password_hash, password);

      if (!validPassword) {
        res.status(401).json({ error: 'Invalid credentials' });
        return;
      }

      const isVerified = Boolean(user.is_email_verified);
      if (config.requireEmailVerification && process.env.NODE_ENV !== 'test' && !isVerified) {
        res.status(403).json({
          error: 'Your account is not verified. Please check your email to verify your account before logging in.',
          needsVerification: true,
          email: user.email,
        });
        return;
      }

      const token = issueToken(res, {
        id: user.id,
        username: user.username,
        email: user.email,
      });

      // Create session
      const tokenHash = crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

      await query(
        `INSERT INTO sessions (user_id, token_hash, expires_at)
         VALUES ($1, $2, $3)`,
        [user.id, tokenHash, expiresAt]
      );

      res.json({
        message: 'Login successful',
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          isEmailVerified: isVerified,
        },
        token,
      });
    } catch (err) {
      console.error('[Auth] Login error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// POST /api/auth/logout
router.post(
  '/logout',
  authMiddleware,
  async (req: AuthRequest, res: Response): Promise<void> => {
    try {
      // Get token to invalidate session
      let token = req.cookies?.token;
      if (!token) {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
          token = authHeader.substring(7);
        }
      }

      if (token) {
        const tokenHash = crypto
          .createHash('sha256')
          .update(token)
          .digest('hex');
        await query(
          'UPDATE sessions SET is_active = FALSE WHERE token_hash = $1',
          [tokenHash]
        );
      }

      res.clearCookie('token');
      res.json({ message: 'Logged out successfully' });
    } catch (err) {
      console.error('[Auth] Logout error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// GET /api/auth/me
router.get(
  '/me',
  authMiddleware,
  async (req: AuthRequest, res: Response): Promise<void> => {
    try {
      const result = await query(
        'SELECT id, username, email, is_email_verified, created_at, is_online, last_seen FROM users WHERE id = $1',
        [req.user!.id]
      );

      if (result.rows.length === 0) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      const u = result.rows[0];
      res.json({
        user: {
          id: u.id,
          username: u.username,
          email: u.email,
          isEmailVerified: Boolean(u.is_email_verified),
          createdAt: u.created_at,
          isOnline: u.is_online,
          lastSeen: u.last_seen,
        },
      });
    } catch (err) {
      console.error('[Auth] Me error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// POST /api/auth/refresh
router.post(
  '/refresh',
  authMiddleware,
  async (req: AuthRequest, res: Response): Promise<void> => {
    try {
      // Invalidate old session
      let oldToken = req.cookies?.token;
      if (!oldToken) {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
          oldToken = authHeader.substring(7);
        }
      }

      if (oldToken) {
        const oldHash = crypto
          .createHash('sha256')
          .update(oldToken)
          .digest('hex');
        await query(
          'UPDATE sessions SET is_active = FALSE WHERE token_hash = $1',
          [oldHash]
        );
      }

      // Issue new token
      const user = req.user!;
      const token = issueToken(res, user);

      const tokenHash = crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

      await query(
        `INSERT INTO sessions (user_id, token_hash, expires_at)
         VALUES ($1, $2, $3)`,
        [user.id, tokenHash, expiresAt]
      );

      res.json({ message: 'Token refreshed', token });
    } catch (err) {
      console.error('[Auth] Refresh error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// POST /api/auth/password-reset/request
router.post(
  '/password-reset/request',
  authRateLimit,
  [body('email').isEmail().normalizeEmail().withMessage('Valid email required')],
  async (req: AuthRequest, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const { email } = req.body;

    try {
      const userRes = await query<{ id: string }>(
        'SELECT id FROM users WHERE email = $1',
        [email]
      );

      let devResetToken: string | undefined;

      if (userRes.rows.length > 0) {
        const userId = userRes.rows[0].id;
        // Invalidate previous unused reset tokens for this user
        await query(
          'UPDATE password_resets SET used = TRUE WHERE user_id = $1 AND used = FALSE',
          [userId]
        );

        const resetToken = crypto.randomBytes(32).toString('hex');
        const tokenHash = crypto
          .createHash('sha256')
          .update(resetToken)
          .digest('hex');
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

        await query(
          `INSERT INTO password_resets (user_id, token_hash, expires_at)
           VALUES ($1, $2, $3)`,
          [userId, tokenHash, expiresAt]
        );

        // Send reset email via Nodemailer
        sendPasswordResetEmail(email, resetToken).catch((err) => {
          console.warn('[Auth] Password reset email dispatch notice:', err.message);
        });

        // Only return resetToken in response during automated test execution
        if (process.env.NODE_ENV === 'test') {
          devResetToken = resetToken;
        }
      }

      res.json({
        message:
          'If an account with that email exists, a password reset token has been sent to your email.',
        ...(devResetToken ? { resetToken: devResetToken } : {}),
      });
    } catch (err) {
      console.error('[Auth] Password reset request error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// POST /api/auth/password-reset/confirm
router.post(
  '/password-reset/confirm',
  authRateLimit,
  [
    body('token').isString().notEmpty().withMessage('Reset token required'),
    body('newPassword')
      .isString()
      .isLength({ min: 8 })
      .matches(/[a-z]/)
      .withMessage('Password must contain a lowercase letter')
      .matches(/[A-Z]/)
      .withMessage('Password must contain an uppercase letter')
      .matches(/\d/)
      .withMessage('Password must contain a digit'),
    body('confirmPassword')
      .isString()
      .custom((value, { req }) => value === req.body.newPassword)
      .withMessage('Passwords must match'),
  ],
  async (req: AuthRequest, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const { token, newPassword } = req.body;

    try {
      const tokenHash = crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');

      const resetRes = await query<{
        id: string;
        user_id: string;
        expires_at: Date;
        used: boolean;
      }>(
        `SELECT id, user_id, expires_at, used
         FROM password_resets
         WHERE token_hash = $1`,
        [tokenHash]
      );

      if (resetRes.rows.length === 0) {
        res.status(400).json({ error: 'Invalid or expired reset token' });
        return;
      }

      const resetRow = resetRes.rows[0];
      if (resetRow.used || new Date(resetRow.expires_at) < new Date()) {
        res.status(400).json({ error: 'Invalid or expired reset token' });
        return;
      }

      const newPasswordHash = await argon2.hash(newPassword, {
        type: argon2.argon2id,
      });

      await query(
        'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
        [newPasswordHash, resetRow.user_id]
      );

      await query('UPDATE password_resets SET used = TRUE WHERE id = $1', [
        resetRow.id,
      ]);

      // Invalidate all active sessions for security
      await query(
        'UPDATE sessions SET is_active = FALSE WHERE user_id = $1',
        [resetRow.user_id]
      );

      res.json({ message: 'Password has been reset successfully' });
    } catch (err) {
      console.error('[Auth] Password reset confirm error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

export default router;
