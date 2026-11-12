import { io, Socket } from 'socket.io-client';
import { Message } from '../types';
import { normalizeMessage } from './api';

export interface IncomingHandshakeInitiate {
  fromUserId: string;
  fromUsername: string;
  kemPublicKey: string;
  signedKemPublicKey: string;
  conversationId?: string;
  senderSigningPublicKey?: string;
}

export interface IncomingHandshakeRespond {
  fromUserId: string;
  fromUsername: string;
  encapsulatedKey: string;
  signedEncapsulatedKey: string;
  conversationId?: string;
  senderSigningPublicKey?: string;
}

class SocketService {
  private socket: Socket | null = null;

  connect(token?: string): Socket {
    if (this.socket && this.socket.connected) {
      return this.socket;
    }

    if (this.socket) {
      this.socket.disconnect();
    }

    this.socket = io('/', {
      auth: token ? { token } : undefined,
      withCredentials: true,
      autoConnect: true,
      reconnection: true,
      reconnectionAttempts: Infinity,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
    });

    return this.socket;
  }

  disconnect(): void {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
  }

  getSocket(): Socket | null {
    return this.socket;
  }

  isConnected(): boolean {
    return Boolean(this.socket?.connected);
  }

  // ── Outbound Events ───────────────────────────────────────────────────────

  sendEncryptedMessage(
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
    callback?: (ack: { ok?: boolean; message?: any; error?: string }) => void
  ): void {
    if (!this.socket) {
      callback?.({ error: 'Socket not connected' });
      return;
    }
    this.socket.emit('message:send', data, callback);
  }

  markDelivered(messageId: string, conversationId?: string): void {
    this.socket?.emit('message:delivered', { messageId, conversationId });
  }

  markRead(messageId: string, conversationId?: string): void {
    this.socket?.emit('message:read', { messageId, conversationId });
  }

  initiateHandshake(data: {
    targetUserId: string;
    kemPublicKey: string;
    signedKemPublicKey: string;
    conversationId?: string;
    senderSigningPublicKey?: string;
  }): void {
    this.socket?.emit('handshake:initiate', data);
  }

  respondHandshake(data: {
    targetUserId: string;
    encapsulatedKey: string;
    signedEncapsulatedKey: string;
    conversationId?: string;
    senderSigningPublicKey?: string;
  }): void {
    this.socket?.emit('handshake:respond', data);
  }

  sendTyping(targetUserId: string, conversationId: string, isTyping: boolean): void {
    this.socket?.emit(isTyping ? 'typing:start' : 'typing:stop', {
      targetUserId,
      conversationId,
    });
  }

  // ── Event Listeners (return unsubscribe function) ─────────────────────────

  onMessage(handler: (msg: Message & { clientMessageId?: string }) => void): () => void {
    const wrapped = (raw: any) => {
      handler({
        ...normalizeMessage(raw),
        clientMessageId: raw.clientMessageId,
      });
    };
    this.socket?.on('message:receive', wrapped);
    return () => {
      this.socket?.off('message:receive', wrapped);
    };
  }

  onDelivered(
    handler: (data: {
      messageId: string;
      conversationId: string;
      deliveredAt: string;
      status: string;
    }) => void
  ): () => void {
    this.socket?.on('message:delivered', handler);
    return () => {
      this.socket?.off('message:delivered', handler);
    };
  }

  onRead(
    handler: (data: {
      messageId: string;
      conversationId: string;
      readAt: string;
      status: string;
    }) => void
  ): () => void {
    this.socket?.on('message:read', handler);
    return () => {
      this.socket?.off('message:read', handler);
    };
  }

  onHandshakeInitiate(
    handler: (data: IncomingHandshakeInitiate) => void
  ): () => void {
    this.socket?.on('handshake:initiate', handler);
    return () => {
      this.socket?.off('handshake:initiate', handler);
    };
  }

  onHandshakeRespond(
    handler: (data: IncomingHandshakeRespond) => void
  ): () => void {
    this.socket?.on('handshake:respond', handler);
    return () => {
      this.socket?.off('handshake:respond', handler);
    };
  }

  onUserOnline(
    handler: (data: { userId: string; username: string }) => void
  ): () => void {
    this.socket?.on('user:online', handler);
    return () => {
      this.socket?.off('user:online', handler);
    };
  }

  onUserOffline(
    handler: (data: { userId: string; username: string; lastSeen: string }) => void
  ): () => void {
    this.socket?.on('user:offline', handler);
    return () => {
      this.socket?.off('user:offline', handler);
    };
  }

  onTyping(
    handler: (data: {
      userId: string;
      username: string;
      conversationId?: string;
      isTyping: boolean;
    }) => void
  ): () => void {
    const onStart = (d: { userId: string; username: string; conversationId?: string }) =>
      handler({ ...d, isTyping: true });
    const onStop = (d: { userId: string; username: string; conversationId?: string }) =>
      handler({ ...d, isTyping: false });
    this.socket?.on('typing:start', onStart);
    this.socket?.on('typing:stop', onStop);
    return () => {
      this.socket?.off('typing:start', onStart);
      this.socket?.off('typing:stop', onStop);
    };
  }
}

export const socketService = new SocketService();
