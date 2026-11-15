import { Certificate, Conversation, KeyBackupRecord, Message, User } from '../types';

const BASE_URL = '';

function getCookie(name: string): string | null {
  const match = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return match ? decodeURIComponent(match[1]) : null;
}

async function ensureCsrfToken(): Promise<string> {
  let token = getCookie('csrf-token');
  if (token) return token;

  const res = await fetch(`${BASE_URL}/api/csrf-token`, {
    method: 'GET',
    credentials: 'include',
  });
  if (res.ok) {
    const data = await res.json();
    return data.csrfToken || getCookie('csrf-token') || '';
  }
  return '';
}

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const method = (options.method || 'GET').toUpperCase();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> | undefined),
  };

  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const csrfToken = await ensureCsrfToken();
    if (csrfToken) {
      headers['X-CSRF-Token'] = csrfToken;
    }
  }

  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    method,
    headers,
    credentials: 'include',
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const message =
      data.error ||
      (Array.isArray(data.errors) && data.errors[0]?.msg) ||
      `Request failed (${res.status})`;
    throw new Error(message);
  }

  return data as T;
}

// ── Normalizers for backend snake_case payloads ─────────────────────────────

function normalizeCertificate(row: any): Certificate {
  let parsed: any = {};
  if (typeof row.certificate === 'string') {
    try {
      parsed = JSON.parse(row.certificate);
    } catch {
      parsed = {};
    }
  }

  return {
    id: row.id || row.fingerprint || '',
    userId: row.user_id || parsed.userId || '',
    username: parsed.username || row.username || '',
    publicSigningKey: row.public_signing_key || parsed.publicSigningKey || '',
    issuedAt: row.issued_at || parsed.issuedAt || '',
    expiresAt: row.expires_at || parsed.expiresAt || '',
    fingerprint: row.fingerprint || parsed.fingerprint || '',
    caSignature: row.ca_signature || row.caSignature || '',
    isRevoked: Boolean(row.is_revoked ?? row.isRevoked ?? false),
    rawCertificate: typeof row.certificate === 'string' ? row.certificate : undefined,
  };
}

export function normalizeMessage(row: any): Message {
  let metadata = row.metadata ?? null;
  if (typeof metadata === 'string') {
    try {
      metadata = JSON.parse(metadata);
    } catch {
      metadata = null;
    }
  }

  return {
    id: row.id,
    conversationId: row.conversation_id ?? row.conversationId,
    senderId: row.sender_id ?? row.senderId,
    ciphertext: row.ciphertext,
    nonce: row.nonce || row.iv || '',
    iv: row.iv || row.nonce || '',
    tag: row.tag || '',
    sequenceNumber: Number(row.sequence_number ?? row.sequenceNumber ?? 0),
    metadata,
    createdAt: row.created_at ?? row.createdAt,
    deliveredAt: row.delivered_at ?? row.deliveredAt ?? null,
    readAt: row.read_at ?? row.readAt ?? null,
    status: row.status || 'sent',
  };
}

function normalizeConversation(row: any): Conversation {
  return {
    id: row.id,
    participantA: row.participant_a,
    participantB: row.participant_b,
    otherUser: row.otherUser || {
      id: row.other_user_id,
      username: row.other_username,
      email: '',
      is_online: Boolean(row.other_is_online),
      last_seen: row.other_last_seen || '',
    },
    lastMessage: row.last_message
      ? {
          id: row.last_message.id,
          ciphertext: row.last_message.ciphertext,
          createdAt: row.last_message.created_at,
          senderId: row.last_message.sender_id,
          status: row.last_message.status,
        }
      : undefined,
    unreadCount: Number(row.unread_count ?? 0),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// ── Auth API ────────────────────────────────────────────────────────────────

export async function register(
  username: string,
  email: string,
  password: string,
  confirmPassword: string
): Promise<{ user: User; token?: string; needsVerification?: boolean; message?: string }> {
  return request('/api/auth/register', {
    method: 'POST',
    body: JSON.stringify({ username, email, password, confirmPassword }),
  });
}

export async function verifyEmail(
  token: string
): Promise<{ message: string; email?: string }> {
  return request('/api/auth/verify-email', {
    method: 'POST',
    body: JSON.stringify({ token }),
  });
}

export async function resendVerification(
  email: string
): Promise<{ message: string }> {
  return request('/api/auth/resend-verification', {
    method: 'POST',
    body: JSON.stringify({ email }),
  });
}

export async function login(
  email: string,
  password: string
): Promise<{ user: User; token: string }> {
  return request('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
}

export async function logout(): Promise<{ message: string }> {
  return request('/api/auth/logout', { method: 'POST' });
}

export async function getMe(): Promise<{ user: User }> {
  return request('/api/auth/me');
}

export async function requestPasswordReset(
  email: string
): Promise<{ message: string; resetToken?: string }> {
  return request('/api/auth/password-reset/request', {
    method: 'POST',
    body: JSON.stringify({ email }),
  });
}

export async function confirmPasswordReset(
  token: string,
  newPassword: string,
  confirmPassword: string
): Promise<{ message: string }> {
  return request('/api/auth/password-reset/confirm', {
    method: 'POST',
    body: JSON.stringify({ token, newPassword, confirmPassword }),
  });
}

// ── Users API ───────────────────────────────────────────────────────────────

export async function searchUsers(q: string): Promise<{ users: User[] }> {
  return request(`/api/users/search?q=${encodeURIComponent(q)}`);
}

export async function getUserById(id: string): Promise<{ user: User }> {
  return request(`/api/users/${encodeURIComponent(id)}`);
}

// ── Certificates & CA API ───────────────────────────────────────────────────

export async function issueCertificate(
  publicSigningKey: string
): Promise<Certificate> {
  const res = await request<{
    certificate: string;
    caSignature: string;
    fingerprint: string;
  }>('/api/certificates/issue', {
    method: 'POST',
    body: JSON.stringify({ publicSigningKey }),
  });

  return normalizeCertificate({
    certificate: res.certificate,
    ca_signature: res.caSignature,
    fingerprint: res.fingerprint,
    public_signing_key: publicSigningKey,
    is_revoked: false,
  });
}

export async function getUserCertificate(userId: string): Promise<Certificate> {
  const res = await request<{ certificate: any }>(
    `/api/certificates/user/${encodeURIComponent(userId)}`
  );
  return normalizeCertificate(res.certificate);
}

export async function verifyCertificate(
  certificate: string,
  caSignature: string
): Promise<{
  valid: boolean;
  signatureValid?: boolean;
  revoked?: boolean;
  expired?: boolean;
  reason?: string;
}> {
  return request('/api/certificates/verify', {
    method: 'POST',
    body: JSON.stringify({ certificate, caSignature }),
  });
}

export async function revokeCertificate(): Promise<{ message: string }> {
  return request('/api/certificates/revoke', { method: 'POST' });
}

export async function getCRL(): Promise<{ crl: string[] }> {
  return request('/api/certificates/crl');
}

export async function getCAPublicKey(): Promise<{ publicKey: string }> {
  return request('/api/ca/public-key');
}

// ── Conversations & Messages API ────────────────────────────────────────────

export async function getConversations(): Promise<{
  conversations: Conversation[];
}> {
  const res = await request<{ conversations: any[] }>('/api/conversations');
  return {
    conversations: res.conversations.map(normalizeConversation),
  };
}

export async function createConversation(
  participantId: string
): Promise<{ conversation: { id: string; participant_a: string; participant_b: string }; created: boolean }> {
  return request('/api/conversations', {
    method: 'POST',
    body: JSON.stringify({ participantId }),
  });
}

export async function getMessages(
  conversationId: string,
  before?: string,
  limit = 50
): Promise<{
  messages: Message[];
  hasMore: boolean;
  myLastSequenceNumber?: number;
}> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (before) params.set('before', before);

  const res = await request<{
    messages: any[];
    hasMore: boolean;
    myLastSequenceNumber?: number | string;
  }>(
    `/api/conversations/${encodeURIComponent(conversationId)}/messages?${params.toString()}`
  );
  return {
    messages: res.messages.map(normalizeMessage),
    hasMore: res.hasMore,
    myLastSequenceNumber:
      res.myLastSequenceNumber !== undefined
        ? Number(res.myLastSequenceNumber)
        : undefined,
  };
}

export async function sendMessage(data: {
  conversationId: string;
  ciphertext: string;
  nonce?: string;
  iv?: string;
  tag?: string;
  sequenceNumber?: number;
  metadata?: Record<string, any>;
}): Promise<{ message: Message }> {
  const res = await request<{ message: any }>('/api/messages', {
    method: 'POST',
    body: JSON.stringify(data),
  });
  return { message: normalizeMessage(res.message) };
}

export async function updateMessageStatus(
  messageId: string,
  status: 'delivered' | 'read'
): Promise<{ message: Partial<Message> }> {
  return request(`/api/messages/${encodeURIComponent(messageId)}/status`, {
    method: 'PUT',
    body: JSON.stringify({ status }),
  });
}

// ── Key Backup API ──────────────────────────────────────────────────────────

export async function backupKeys(
  encryptedPrivateKey: string,
  salt: string,
  iv: string
): Promise<{ message: string; backup: any }> {
  return request('/api/keys/backup', {
    method: 'POST',
    body: JSON.stringify({ encryptedPrivateKey, salt, iv }),
  });
}

export async function getKeyBackup(): Promise<{ backup: KeyBackupRecord }> {
  return request('/api/keys/backup');
}
