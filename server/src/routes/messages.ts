import { Router, Response } from 'express';
import { body, param, validationResult } from 'express-validator';
import { authMiddleware, AuthRequest } from '../middleware/auth';
import { query } from '../db';
import { storeEncryptedMessage } from '../services/messageService';

const router = Router();

// POST /api/messages - store encrypted message with replay protection
router.post(
  '/',
  authMiddleware,
  [
    body('conversationId').isUUID().withMessage('Valid conversationId required'),
    body('ciphertext').isString().notEmpty().withMessage('Ciphertext required'),
    body('messageId').optional().isUUID().withMessage('Valid messageId required'),
    body('nonce').optional().isString(),
    body('iv').optional().isString(),
    body('tag').optional().isString(),
    body('sequenceNumber').optional().isInt({ min: 0 }),
    body('metadata').optional().isObject(),
  ],
  async (req: AuthRequest, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    if (req.body.plaintext !== undefined) {
      res.status(400).json({ error: 'Plaintext messages are not permitted; send ciphertext only' });
      return;
    }

    const userId = req.user!.id;
    const {
      conversationId,
      ciphertext,
      nonce,
      iv,
      tag,
      sequenceNumber,
      metadata,
      messageId,
    } = req.body;

    try {
      const outcome = await storeEncryptedMessage({
        conversationId,
        senderId: userId,
        ciphertext,
        nonce,
        iv,
        tag,
        sequenceNumber,
        metadata,
        messageId,
      });

      if (!outcome.ok) {
        res.status(outcome.status).json({ error: outcome.error });
        return;
      }

      res.status(201).json({ message: outcome.message });
    } catch (err) {
      console.error('[Messages] Store error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// PUT /api/messages/:id/status - update message delivery/read status
router.put(
  '/:id/status',
  authMiddleware,
  [
    param('id').isUUID().withMessage('Valid message ID required'),
    body('status')
      .isIn(['delivered', 'read'])
      .withMessage('Status must be delivered or read'),
  ],
  async (req: AuthRequest, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const userId = req.user!.id;
    const messageId = req.params.id;
    const { status } = req.body;

    try {
      const msgCheck = await query(
        `SELECT m.id, m.sender_id, m.status
         FROM messages m
         JOIN conversations c ON c.id = m.conversation_id
         WHERE m.id = $1 AND (c.participant_a = $2 OR c.participant_b = $2)`,
        [messageId, userId]
      );

      if (msgCheck.rows.length === 0) {
        res.status(404).json({ error: 'Message not found or access denied' });
        return;
      }

      const timestampCol = status === 'delivered' ? 'delivered_at' : 'read_at';
      const result = await query(
        `UPDATE messages
         SET status = $1, ${timestampCol} = COALESCE(${timestampCol}, NOW())
         WHERE id = $2
         RETURNING id, conversation_id, sender_id, status, delivered_at, read_at`,
        [status, messageId]
      );

      res.json({ message: result.rows[0] });
    } catch (err) {
      console.error('[Messages] Status update error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

export default router;
