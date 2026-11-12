import { Router, Response } from 'express';
import { body, validationResult } from 'express-validator';
import { authMiddleware, AuthRequest } from '../middleware/auth';
import { query } from '../db';

const router = Router();

// POST /api/keys/backup - store encrypted private key backup
router.post(
  '/backup',
  authMiddleware,
  [
    body('encryptedPrivateKey')
      .isString()
      .notEmpty()
      .withMessage('encryptedPrivateKey required'),
    body('salt').isString().notEmpty().withMessage('salt required'),
    body('iv').isString().notEmpty().withMessage('iv required'),
  ],
  async (req: AuthRequest, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const userId = req.user!.id;
    const { encryptedPrivateKey, salt, iv } = req.body;

    try {
      // Remove previous backup or store latest; keeping one active backup per user via replace
      await query('DELETE FROM key_backups WHERE user_id = $1', [userId]);

      const result = await query(
        `INSERT INTO key_backups (user_id, encrypted_private_key, salt, iv)
         VALUES ($1, $2, $3, $4)
         RETURNING id, user_id, created_at`,
        [userId, encryptedPrivateKey, salt, iv]
      );

      res.status(201).json({
        message: 'Key backup stored successfully',
        backup: result.rows[0],
      });
    } catch (err) {
      console.error('[Keys] Backup store error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// GET /api/keys/backup - retrieve encrypted private key backup
router.get(
  '/backup',
  authMiddleware,
  async (req: AuthRequest, res: Response): Promise<void> => {
    const userId = req.user!.id;

    try {
      const result = await query(
        `SELECT id, user_id, encrypted_private_key, salt, iv, created_at
         FROM key_backups
         WHERE user_id = $1
         ORDER BY created_at DESC
         LIMIT 1`,
        [userId]
      );

      if (result.rows.length === 0) {
        res.status(404).json({ error: 'No key backup found' });
        return;
      }

      res.json({ backup: result.rows[0] });
    } catch (err) {
      console.error('[Keys] Backup retrieve error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

export default router;
