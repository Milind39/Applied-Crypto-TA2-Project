import { validate as isUuid } from 'uuid';
import { query } from '../db';

export interface StoreMessageInput {
  conversationId: string;
  senderId: string;
  ciphertext: string;
  nonce?: string | null;
  iv?: string | null;
  tag?: string | null;
  sequenceNumber?: number | null;
  metadata?: Record<string, any> | null;
  messageId?: string | null;
}

export interface StoreMessageResult {
  ok: true;
  message: any;
  participantA: string;
  participantB: string;
}

export interface StoreMessageError {
  ok: false;
  status: number;
  error: string;
}

/**
 * Verifies conversation participation, enforces replay protection (unique messageId
 * and strictly monotonic sequenceNumber per sender & conversation), and stores ciphertext.
 */
export async function storeEncryptedMessage(
  input: StoreMessageInput
): Promise<StoreMessageResult | StoreMessageError> {
  const {
    conversationId,
    senderId,
    ciphertext,
    nonce,
    iv,
    tag,
    sequenceNumber,
    metadata,
    messageId,
  } = input;

  if (!isUuid(conversationId)) {
    return { ok: false, status: 400, error: 'Valid conversationId required' };
  }

  if (messageId !== undefined && messageId !== null && !isUuid(messageId)) {
    return { ok: false, status: 400, error: 'Invalid messageId format' };
  }

  if (
    sequenceNumber !== undefined &&
    sequenceNumber !== null &&
    (!Number.isInteger(sequenceNumber) || sequenceNumber < 0)
  ) {
    return {
      ok: false,
      status: 400,
      error: 'sequenceNumber must be a non-negative integer',
    };
  }

  // Verify user is participant in conversation
  const conv = await query<{ participant_a: string; participant_b: string }>(
    `SELECT participant_a, participant_b FROM conversations
     WHERE id = $1 AND (participant_a = $2 OR participant_b = $2)`,
    [conversationId, senderId]
  );

  if (conv.rows.length === 0) {
    return {
      ok: false,
      status: 403,
      error: 'Not a participant of this conversation',
    };
  }

  // Replay protection 1: reject duplicate messageId
  if (messageId) {
    const dup = await query('SELECT id FROM messages WHERE id = $1', [messageId]);
    if (dup.rows.length > 0) {
      return {
        ok: false,
        status: 409,
        error: 'Replay detected: duplicate messageId',
      };
    }
  }

  // Replay protection 2: enforce strictly monotonic sequence_number per (conversation, sender)
  if (sequenceNumber !== undefined && sequenceNumber !== null) {
    const seqRes = await query<{ max_seq: string }>(
      `SELECT COALESCE(MAX(sequence_number), -1)::text AS max_seq
       FROM messages
       WHERE conversation_id = $1 AND sender_id = $2 AND sequence_number IS NOT NULL`,
      [conversationId, senderId]
    );
    const maxSeq = BigInt(seqRes.rows[0].max_seq);
    if (BigInt(sequenceNumber) <= maxSeq) {
      return {
        ok: false,
        status: 409,
        error: 'Replay detected: sequenceNumber must be strictly greater than previous messages',
      };
    }
  }

  try {
    const insertSql = messageId
      ? `INSERT INTO messages (id, conversation_id, sender_id, ciphertext, nonce, iv, tag, sequence_number, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING id, conversation_id, sender_id, ciphertext, nonce, iv, tag,
                   sequence_number, metadata, created_at, delivered_at, read_at, status`
      : `INSERT INTO messages (conversation_id, sender_id, ciphertext, nonce, iv, tag, sequence_number, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id, conversation_id, sender_id, ciphertext, nonce, iv, tag,
                   sequence_number, metadata, created_at, delivered_at, read_at, status`;

    const params = messageId
      ? [
          messageId,
          conversationId,
          senderId,
          ciphertext,
          nonce || null,
          iv || null,
          tag || null,
          sequenceNumber ?? null,
          metadata ? JSON.stringify(metadata) : null,
        ]
      : [
          conversationId,
          senderId,
          ciphertext,
          nonce || null,
          iv || null,
          tag || null,
          sequenceNumber ?? null,
          metadata ? JSON.stringify(metadata) : null,
        ];

    const result = await query(insertSql, params);

    await query('UPDATE conversations SET updated_at = NOW() WHERE id = $1', [
      conversationId,
    ]);

    return {
      ok: true,
      message: result.rows[0],
      participantA: conv.rows[0].participant_a,
      participantB: conv.rows[0].participant_b,
    };
  } catch (err: any) {
    if (err?.code === '23505') {
      return {
        ok: false,
        status: 409,
        error: 'Replay detected: duplicate messageId or sequenceNumber',
      };
    }
    throw err;
  }
}
