export interface User {
  id: string;
  username: string;
  email: string;
  isEmailVerified?: boolean;
  is_online: boolean;
  last_seen: string;
  created_at?: string;
}

export interface Certificate {
  id: string;
  userId: string;
  username: string;
  publicSigningKey: string;
  issuedAt: string;
  expiresAt: string;
  fingerprint: string;
  caSignature: string;
  isRevoked: boolean;
  rawCertificate?: string; // exact JSON string signed by CA
}

export interface Message {
  id: string;
  conversationId: string;
  senderId: string;
  ciphertext: string;
  nonce: string;
  iv: string;
  tag: string;
  sequenceNumber: number;
  metadata: Record<string, any> | null;
  createdAt: string;
  deliveredAt?: string | null;
  readAt?: string | null;
  status: 'sending' | 'sent' | 'delivered' | 'read' | 'failed';
  plaintext?: string; // local only, after client-side decryption
  decryptionError?: string;
}

export interface Conversation {
  id: string;
  participantA?: string;
  participantB?: string;
  otherUser: User;
  lastMessage?: Partial<Message> & {
    id: string;
    ciphertext: string;
    createdAt: string;
    senderId: string;
    status: string;
  };
  unreadCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface CryptoIdentity {
  signingKeyPair: {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
  };
  certificate: Certificate;
}

export interface SessionKeys {
  conversationId: string;
  peerId: string;
  sendKey: CryptoKey;
  receiveKey: CryptoKey;
  sequenceNumber: number;
  establishedAt: string;
  peerFingerprint?: string;
  peerVerified?: boolean;
}

export interface KeyBackupRecord {
  id: string;
  user_id: string;
  encrypted_private_key: string;
  salt: string;
  iv: string;
  created_at: string;
}

export interface HandshakeStatus {
  state: 'idle' | 'initiating' | 'responding' | 'established' | 'failed';
  error?: string;
  establishedAt?: string;
  peerFingerprint?: string;
}
