import { Router, Response } from 'express';
import { param, validationResult } from 'express-validator';
import { authMiddleware, AuthRequest } from '../middleware/auth';
import { query } from '../db';

const router = Router();

// GET /api/users/search?q=query
router.get(
  '/search',
  authMiddleware,
  async (req: AuthRequest, res: Response): Promise<void> => {
    const searchQuery = req.query.q as string;

    if (!searchQuery || searchQuery.trim().length === 0) {
      res.status(400).json({ error: 'Search query is required' });
      return;
    }

    try {
      const result = await query(
        `SELECT id, username, is_online, last_seen
         FROM users
         WHERE username ILIKE $1 AND id != $2
         ORDER BY username
         LIMIT 20`,
        [`%${searchQuery}%`, req.user!.id]
      );

      res.json({ users: result.rows });
    } catch (err) {
      console.error('[Users] Search error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// GET /api/users/:id
router.get(
  '/:id',
  authMiddleware,
  [param('id').isUUID().withMessage('Valid user ID required')],
  async (req: AuthRequest, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const { id } = req.params;

    try {
      const result = await query(
        `SELECT id, username, is_online, last_seen, created_at
         FROM users WHERE id = $1`,
        [id]
      );

      if (result.rows.length === 0) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      res.json({ user: result.rows[0] });
    } catch (err) {
      console.error('[Users] Get user error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

export default router;
