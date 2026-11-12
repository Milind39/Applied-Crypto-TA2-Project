import { Server as HttpServer } from 'http';
import { Server, Socket } from 'socket.io';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { config } from './config';
import { query } from './db';
import { storeEncryptedMessage } from './services/messageService';

interface AuthenticatedSocket extends Socket {
  userId?: string;
  username?: string;
}

// Map userId -> Set<socketId> for multiple tabs/devices
const userSockets = new Map<string, Set<string>>();

function parseCookies(cookieHeader?: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!cookieHeader) return cookies;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx > -1) {
      const key = part.slice(0, idx).trim();
      const val = decodeURIComponent(part.slice(idx + 1).trim());
      cookies[key] = val;
    }
  }
  return cookies;
}

function emitToUser(io: Server, userId: string, event: string, payload: any): void {
  const sockets = userSockets.get(userId);
  if (!sockets) return;
  for (const socketId of sockets) {
    io.to(socketId).emit(event, payload);
  }
}

export function initSocketIO(httpServer: HttpServer): Server {
  const io = new Server(httpServer, {
    cors: {
      origin: config.corsOrigin,
      credentials: true,
      methods: ['GET', 'POST'],
    },
  });

  // Auth middleware: verify JWT from handshake auth or cookies
  io.use(async (socket: AuthenticatedSocket, next) => {
    let token = socket.handshake.auth?.token as string | undefined;

    if (!token && socket.handshake.headers.authorization) {
      const authHeader = socket.handshake.headers.authorization;
      if (authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
      }
    }

    if (!token && socket.handshake.headers.cookie) {
      const cookies = parseCookies(socket.handshake.headers.cookie);
      token = cookies.token;
    }

    if (!token) {
      return next(new Error('Authentication required'));
    }

    try {
      const decoded = jwt.verify(token, config.jwtSecret) as {
        id: string;
        username: string;
        email: string;
      };

      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      const sessionRes = await query<{ is_active: boolean; expires_at: Date }>(
        'SELECT is_active, expires_at FROM sessions WHERE token_hash = $1 LIMIT 1',
        [tokenHash]
      );

      if (
        sessionRes.rows.length > 0 &&
        (!sessionRes.rows[0].is_active ||
          new Date(sessionRes.rows[0].expires_at) < new Date())
      ) {
        return next(new Error('Session expired or revoked'));
      }

      socket.userId = decoded.id;
      socket.username = decoded.username;
      next();
    } catch {
      next(new Error('Invalid or expired token'));
    }
  });

  io.on('connection', async (socket: AuthenticatedSocket) => {
    const userId = socket.userId!;
    const username = socket.username!;

    // Track socket
    if (!userSockets.has(userId)) {
      userSockets.set(userId, new Set());
    }
    const sockets = userSockets.get(userId)!;
    const isFirstConnection = sockets.size === 0;
    sockets.add(socket.id);

    if (isFirstConnection) {
      try {
        await query(
          'UPDATE users SET is_online = TRUE, updated_at = NOW() WHERE id = $1',
          [userId]
        );
        socket.broadcast.emit('user:online', { userId, username });
      } catch (err) {
        console.error('[Socket] Error setting user online:', (err as Error).message);
      }
    }

    // message:send - store encrypted message in DB and emit to recipient
    socket.on(
      'message:send',
      async (
        data: {
          conversationId: string;
          recipientId: string;
          ciphertext: string;
          nonce?: string;
          iv?: string;
          tag?: string;
          sequenceNumber?: number;
          metadata?: Record<string, any>;
          messageId?: string;
        },
        callback?: (ack: any) => void
      ) => {
        try {
          if (!data || !data.conversationId || !data.ciphertext) {
            if (callback) callback({ error: 'Invalid message payload' });
            return;
          }

          if ((data as any).plaintext !== undefined) {
            if (callback) callback({ error: 'Plaintext messages are not permitted' });
            return;
          }

          const outcome = await storeEncryptedMessage({
            conversationId: data.conversationId,
            senderId: userId,
            ciphertext: data.ciphertext,
            nonce: data.nonce,
            iv: data.iv,
            tag: data.tag,
            sequenceNumber: data.sequenceNumber,
            metadata: data.metadata,
            messageId: data.messageId,
          });

          if (!outcome.ok) {
            if (callback) callback({ error: outcome.error });
            return;
          }

          const storedMessage = outcome.message;
          const recipientId =
            data.recipientId ||
            (outcome.participantA === userId
              ? outcome.participantB
              : outcome.participantA);

          // Deliver to recipient sockets
          emitToUser(io, recipientId, 'message:receive', {
            ...storedMessage,
            clientMessageId: data.messageId,
          });

          // Sync to sender's other open tabs/devices
          const senderSockets = userSockets.get(userId);
          if (senderSockets) {
            for (const sId of senderSockets) {
              if (sId !== socket.id) {
                io.to(sId).emit('message:receive', {
                  ...storedMessage,
                  clientMessageId: data.messageId,
                });
              }
            }
          }

          if (callback) {
            callback({ ok: true, message: storedMessage });
          }
        } catch (err) {
          console.error('[Socket] message:send error:', (err as Error).message);
          if (callback) callback({ error: 'Failed to send message' });
        }
      }
    );

    // message:delivered - update status and notify sender
    socket.on(
      'message:delivered',
      async (data: { messageId: string; conversationId?: string }) => {
        try {
          if (!data?.messageId) return;

          const result = await query(
            `UPDATE messages m
             SET status = CASE WHEN m.status = 'read' THEN 'read' ELSE 'delivered' END,
                 delivered_at = COALESCE(m.delivered_at, NOW())
             FROM conversations c
             WHERE m.id = $1
               AND c.id = m.conversation_id
               AND (c.participant_a = $2 OR c.participant_b = $2)
               AND m.sender_id != $2
             RETURNING m.id, m.conversation_id, m.sender_id, m.status, m.delivered_at`,
            [data.messageId, userId]
          );

          if (result.rows.length > 0) {
            const msg = result.rows[0];
            emitToUser(io, msg.sender_id, 'message:delivered', {
              messageId: msg.id,
              conversationId: msg.conversation_id,
              deliveredAt: msg.delivered_at,
              status: msg.status,
            });
          }
        } catch (err) {
          console.error('[Socket] message:delivered error:', (err as Error).message);
        }
      }
    );

    // message:read - update status and notify sender
    socket.on(
      'message:read',
      async (data: { messageId: string; conversationId?: string }) => {
        try {
          if (!data?.messageId) return;

          const result = await query(
            `UPDATE messages m
             SET status = 'read',
                 delivered_at = COALESCE(m.delivered_at, NOW()),
                 read_at = COALESCE(m.read_at, NOW())
             FROM conversations c
             WHERE m.id = $1
               AND c.id = m.conversation_id
               AND (c.participant_a = $2 OR c.participant_b = $2)
               AND m.sender_id != $2
             RETURNING m.id, m.conversation_id, m.sender_id, m.status, m.read_at`,
            [data.messageId, userId]
          );

          if (result.rows.length > 0) {
            const msg = result.rows[0];
            emitToUser(io, msg.sender_id, 'message:read', {
              messageId: msg.id,
              conversationId: msg.conversation_id,
              readAt: msg.read_at,
              status: msg.status,
            });
          }
        } catch (err) {
          console.error('[Socket] message:read error:', (err as Error).message);
        }
      }
    );

    // handshake:initiate - relay PQ KEM public key to target user
    socket.on(
      'handshake:initiate',
      (data: {
        targetUserId: string;
        kemPublicKey: string;
        signedKemPublicKey?: string;
        signature?: string;
        certificate?: any;
        caSignature?: string;
        conversationId?: string;
        senderSigningPublicKey?: string;
      }) => {
        if (
          !data?.targetUserId ||
          !data?.kemPublicKey ||
          (!data?.signedKemPublicKey && !data?.signature)
        ) {
          return;
        }
        emitToUser(io, data.targetUserId, 'handshake:initiate', {
          ...data,
          fromUserId: userId,
          fromUsername: username,
        });
      }
    );

    // handshake:respond - relay encapsulated key to initiator
    socket.on(
      'handshake:respond',
      (data: {
        targetUserId: string;
        encapsulatedKey?: string;
        encapsulatedCiphertext?: string;
        signedEncapsulatedKey?: string;
        signature?: string;
        certificate?: any;
        caSignature?: string;
        conversationId?: string;
        senderSigningPublicKey?: string;
      }) => {
        if (
          !data?.targetUserId ||
          (!data?.encapsulatedKey && !data?.encapsulatedCiphertext) ||
          (!data?.signedEncapsulatedKey && !data?.signature)
        ) {
          return;
        }
        emitToUser(io, data.targetUserId, 'handshake:respond', {
          ...data,
          fromUserId: userId,
          fromUsername: username,
        });
      }
    );

    // typing:start / typing:stop
    socket.on(
      'typing:start',
      (data: { targetUserId: string; conversationId?: string }) => {
        if (!data?.targetUserId) return;
        emitToUser(io, data.targetUserId, 'typing:start', {
          userId,
          username,
          conversationId: data.conversationId,
        });
      }
    );

    socket.on(
      'typing:stop',
      (data: { targetUserId: string; conversationId?: string }) => {
        if (!data?.targetUserId) return;
        emitToUser(io, data.targetUserId, 'typing:stop', {
          userId,
          username,
          conversationId: data.conversationId,
        });
      }
    );

    // Disconnect handling
    socket.on('disconnect', async () => {
      const currentSockets = userSockets.get(userId);
      if (currentSockets) {
        currentSockets.delete(socket.id);
        if (currentSockets.size === 0) {
          userSockets.delete(userId);
          try {
            const res = await query(
              'UPDATE users SET is_online = FALSE, last_seen = NOW(), updated_at = NOW() WHERE id = $1 RETURNING last_seen',
              [userId]
            );
            const lastSeen = res.rows[0]?.last_seen || new Date().toISOString();
            socket.broadcast.emit('user:offline', {
              userId,
              username,
              lastSeen,
            });
          } catch (err) {
            console.error('[Socket] Error setting user offline:', (err as Error).message);
          }
        }
      }
    });
  });

  return io;
}
