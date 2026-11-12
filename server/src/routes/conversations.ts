import { Router, Response } from 'express';
import { body, param, validationResult } from 'express-validator';
import { authMiddleware, AuthRequest } from '../middleware/auth';
import { query } from '../db';

const router = Router();

// GET /api/conversations - list user's conversations
router.get(
  '/',
  authMiddleware,
  async (req: AuthRequest, res: Response): Promise<void> => {
    const userId = req.user!.id;

    try {
      const result = await query(
        `SELECT
           c.id,
           c.created_at,
           c.updated_at,
           CASE WHEN c.participant_a = $1 THEN c.participant_b ELSE c.participant_a END AS other_user_id,
           u.username AS other_username,
           u.is_online AS other_is_online,
           u.last_seen AS other_last_seen,
           (SELECT COUNT(*) FROM messages m
            WHERE m.conversation_id = c.id
              AND m.sender_id != $1
              AND m.status = 'sent') AS unread_count,
           (SELECT row_to_json(sub)
            FROM (SELECT m2.id, m2.ciphertext, m2.created_at, m2.sender_id, m2.status
                  FROM messages m2
                  WHERE m2.conversation_id = c.id
                  ORDER BY m2.created_at DESC LIMIT 1) sub
           ) AS last_message
         FROM conversations c
         JOIN users u ON u.id = CASE WHEN c.participant_a = $1 THEN c.participant_b ELSE c.participant_a END
         WHERE c.participant_a = $1 OR c.participant_b = $1
         ORDER BY c.updated_at DESC`,
        [userId]
      );

      res.json({ conversations: result.rows });
    } catch (err) {
      console.error('[Conversations] List error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// POST /api/conversations - create or get conversation
router.post(
  '/',
  authMiddleware,
  [body('participantId').isUUID().withMessage('Valid participant ID required')],
  async (req: AuthRequest, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const userId = req.user!.id;
    const { participantId } = req.body;

    if (userId === participantId) {
      res.status(400).json({ error: 'Cannot create conversation with yourself' });
      return;
    }

    try {
      // Check if participant exists
      const userExists = await query('SELECT id FROM users WHERE id = $1', [
        participantId,
      ]);
      if (userExists.rows.length === 0) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      // Order participant IDs consistently to enforce uniqueness
      const [pA, pB] =
        userId < participantId
          ? [userId, participantId]
          : [participantId, userId];

      // Try to find existing conversation
      const existing = await query(
        `SELECT id, participant_a, participant_b, created_at, updated_at
         FROM conversations
         WHERE participant_a = $1 AND participant_b = $2`,
        [pA, pB]
      );

      if (existing.rows.length > 0) {
        res.json({ conversation: existing.rows[0], created: false });
        return;
      }

      // Create new conversation
      const result = await query(
        `INSERT INTO conversations (participant_a, participant_b)
         VALUES ($1, $2)
         RETURNING id, participant_a, participant_b, created_at, updated_at`,
        [pA, pB]
      );

      res.status(201).json({ conversation: result.rows[0], created: true });
    } catch (err) {
      console.error('[Conversations] Create error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// GET /api/conversations/:id/messages - paginated messages
router.get(
  '/:id/messages',
  authMiddleware,
  [param('id').isUUID().withMessage('Valid conversation ID required')],
  async (req: AuthRequest, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const userId = req.user!.id;
    const conversationId = req.params.id;
    const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);
    const before = req.query.before as string; // cursor: message created_at

    try {
      // Verify user is participant
      const conv = await query(
        `SELECT id FROM conversations
         WHERE id = $1 AND (participant_a = $2 OR participant_b = $2)`,
        [conversationId, userId]
      );

      if (conv.rows.length === 0) {
        res.status(403).json({ error: 'Not a participant of this conversation' });
        return;
      }

      let messagesQuery: string;
      let params: any[];

      if (before) {
        messagesQuery = `
          SELECT id, conversation_id, sender_id, ciphertext, nonce, iv, tag,
                 sequence_number, metadata, created_at, delivered_at, read_at, status
          FROM messages
          WHERE conversation_id = $1 AND created_at < $2
          ORDER BY created_at DESC
          LIMIT $3`;
        params = [conversationId, before, limit];
      } else {
        messagesQuery = `
          SELECT id, conversation_id, sender_id, ciphertext, nonce, iv, tag,
                 sequence_number, metadata, created_at, delivered_at, read_at, status
          FROM messages
          WHERE conversation_id = $1
          ORDER BY created_at DESC
          LIMIT $2`;
        params = [conversationId, limit];
      }

      const result = await query(messagesQuery, params);
      const seqRes = await query<{ max_seq: string }>(
        `SELECT COALESCE(MAX(sequence_number), 0)::bigint AS max_seq
         FROM messages
         WHERE conversation_id = $1 AND sender_id = $2`,
        [conversationId, userId]
      );

      res.json({
        messages: result.rows.reverse(), // Return in chronological order
        hasMore: result.rows.length === limit,
        myLastSequenceNumber: Number(seqRes.rows[0].max_seq),
      });
    } catch (err) {
      console.error('[Conversations] Messages error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

export default router;
