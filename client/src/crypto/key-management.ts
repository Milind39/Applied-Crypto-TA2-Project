import { Certificate, CryptoIdentity, SessionKeys } from '../types';
import { base64ToUint8Array, uint8ArrayToBase64 } from './pq-crypto';

const DB_NAME = 'pq-messenger-keystore';
const DB_VERSION = 2;
const IDENTITIES_STORE = 'identities';
const SESSIONS_STORE = 'session_keys';

interface StoredIdentityRecord {
  userId: string;
  publicKeyB64: string;
  secretKeyB64: string;
  certificate: Certificate;
  updatedAt: string;
}

export interface StoredSessionRecord {
  id: string; // `${userId}:${conversationId}`
  userId: string;
  conversationId: string;
  peerId: string;
  sendKeyB64: string;
  receiveKeyB64: string;
  sequenceNumber: number;
  establishedAt: string;
  peerFingerprint?: string;
  peerVerified?: boolean;
}

function openKeyDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(IDENTITIES_STORE)) {
        db.createObjectStore(IDENTITIES_STORE, { keyPath: 'userId' });
      }
      if (!db.objectStoreNames.contains(SESSIONS_STORE)) {
        const store = db.createObjectStore(SESSIONS_STORE, { keyPath: 'id' });
        store.createIndex('userId', 'userId', { unique: false });
        store.createIndex('conversationId', 'conversationId', { unique: false });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('Failed to open IndexedDB'));
  });
}

/**
 * Store signing keypair and certificate in IndexedDB (never localStorage).
 */
export async function saveIdentityToIndexedDB(
  userId: string,
  identity: CryptoIdentity
): Promise<void> {
  const db = await openKeyDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(IDENTITIES_STORE, 'readwrite');
    const store = tx.objectStore(IDENTITIES_STORE);
    const record: StoredIdentityRecord = {
      userId,
      publicKeyB64: uint8ArrayToBase64(identity.signingKeyPair.publicKey),
      secretKeyB64: uint8ArrayToBase64(identity.signingKeyPair.secretKey),
      certificate: identity.certificate,
      updatedAt: new Date().toISOString(),
    };
    store.put(record);
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error || new Error('Failed to save keys to IndexedDB'));
    };
  });
}

/**
 * Load signing keypair and certificate for a user from IndexedDB.
 */
export async function loadIdentityFromIndexedDB(
  userId: string
): Promise<CryptoIdentity | null> {
  const db = await openKeyDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(IDENTITIES_STORE, 'readonly');
    const store = tx.objectStore(IDENTITIES_STORE);
    const req = store.get(userId);
    req.onsuccess = () => {
      db.close();
      const record = req.result as StoredIdentityRecord | undefined;
      if (!record) {
        resolve(null);
        return;
      }
      resolve({
        signingKeyPair: {
          publicKey: base64ToUint8Array(record.publicKeyB64),
          secretKey: base64ToUint8Array(record.secretKeyB64),
        },
        certificate: record.certificate,
      });
    };
    req.onerror = () => {
      db.close();
      reject(req.error || new Error('Failed to load keys from IndexedDB'));
    };
  });
}

/**
 * Persist an established post-quantum session key pair across page refreshes.
 */
export async function saveSessionKeysToIndexedDB(
  userId: string,
  session: SessionKeys
): Promise<void> {
  const db = await openKeyDB();
  const sendRaw = await crypto.subtle.exportKey('raw', session.sendKey);
  const receiveRaw = await crypto.subtle.exportKey('raw', session.receiveKey);

  const record: StoredSessionRecord = {
    id: `${userId}:${session.conversationId}`,
    userId,
    conversationId: session.conversationId,
    peerId: session.peerId,
    sendKeyB64: uint8ArrayToBase64(new Uint8Array(sendRaw)),
    receiveKeyB64: uint8ArrayToBase64(new Uint8Array(receiveRaw)),
    sequenceNumber: session.sequenceNumber,
    establishedAt: session.establishedAt,
    peerFingerprint: session.peerFingerprint,
    peerVerified: session.peerVerified,
  };

  return new Promise((resolve, reject) => {
    const tx = db.transaction(SESSIONS_STORE, 'readwrite');
    const store = tx.objectStore(SESSIONS_STORE);
    store.put(record);
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error || new Error('Failed to save session keys to IndexedDB'));
    };
  });
}

/**
 * Update the stored sequence number for a session in IndexedDB.
 */
export async function updateSessionSequenceInIndexedDB(
  userId: string,
  conversationId: string,
  sequenceNumber: number
): Promise<void> {
  const db = await openKeyDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(SESSIONS_STORE, 'readwrite');
    const store = tx.objectStore(SESSIONS_STORE);
    const key = `${userId}:${conversationId}`;
    const req = store.get(key);
    req.onsuccess = () => {
      const record = req.result as StoredSessionRecord | undefined;
      if (record) {
        if (sequenceNumber > record.sequenceNumber) {
          record.sequenceNumber = sequenceNumber;
          store.put(record);
        }
      }
    };
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error || new Error('Failed to update session sequence in IndexedDB'));
    };
  });
}

/**
 * Load all stored post-quantum session keys for the user across all conversations.
 */
export async function loadAllSessionKeysFromIndexedDB(
  userId: string
): Promise<Map<string, SessionKeys>> {
  const db = await openKeyDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(SESSIONS_STORE, 'readonly');
    const store = tx.objectStore(SESSIONS_STORE);
    const req = store.getAll();
    req.onsuccess = async () => {
      db.close();
      const records = (req.result || []) as StoredSessionRecord[];
      const map = new Map<string, SessionKeys>();

      for (const rec of records) {
        if (rec.userId !== userId) continue;
        try {
          const sendKey = await crypto.subtle.importKey(
            'raw',
            new Uint8Array(base64ToUint8Array(rec.sendKeyB64)),
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
          );
          const receiveKey = await crypto.subtle.importKey(
            'raw',
            new Uint8Array(base64ToUint8Array(rec.receiveKeyB64)),
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
          );

          map.set(rec.conversationId, {
            conversationId: rec.conversationId,
            peerId: rec.peerId,
            sendKey,
            receiveKey,
            sequenceNumber: rec.sequenceNumber,
            establishedAt: rec.establishedAt,
            peerFingerprint: rec.peerFingerprint,
            peerVerified: rec.peerVerified,
          });
        } catch (err) {
          console.warn('[KeyStore] Failed to restore session key for conversation:', rec.conversationId, err);
        }
      }
      resolve(map);
    };
    req.onerror = () => {
      db.close();
      reject(req.error || new Error('Failed to load session keys from IndexedDB'));
    };
  });
}

/**
 * Delete a specific conversation's session keys from IndexedDB (e.g. on explicit reset).
 */
export async function deleteSessionKeyFromIndexedDB(
  userId: string,
  conversationId: string
): Promise<void> {
  const db = await openKeyDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(SESSIONS_STORE, 'readwrite');
    const store = tx.objectStore(SESSIONS_STORE);
    store.delete(`${userId}:${conversationId}`);
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error || new Error('Failed to delete session key from IndexedDB'));
    };
  });
}

/**
 * Clear stored keys and session keys from IndexedDB on logout.
 */
export async function clearKeysFromIndexedDB(userId?: string): Promise<void> {
  const db = await openKeyDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction([IDENTITIES_STORE, SESSIONS_STORE], 'readwrite');
    const idStore = tx.objectStore(IDENTITIES_STORE);
    const sessStore = tx.objectStore(SESSIONS_STORE);

    if (userId) {
      idStore.delete(userId);
      const req = sessStore.getAll();
      req.onsuccess = () => {
        const records = (req.result || []) as StoredSessionRecord[];
        for (const r of records) {
          if (r.userId === userId) {
            sessStore.delete(r.id);
          }
        }
      };
    } else {
      idStore.clear();
      sessStore.clear();
    }

    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error || new Error('Failed to clear keys from IndexedDB'));
    };
  });
}

/**
 * Derive an AES-256-GCM wrapping key from the user's password using PBKDF2-SHA-256.
 */
async function deriveBackupKey(
  password: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  const passwordBytes = new TextEncoder().encode(password);
  const baseKey = await crypto.subtle.importKey(
    'raw',
    passwordBytes,
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: new Uint8Array(salt),
      iterations: 150000,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt private signing key client-side before uploading backup to server.
 */
export async function encryptPrivateKeyForBackup(
  secretKey: Uint8Array,
  password: string
): Promise<{ encryptedPrivateKey: string; salt: string; iv: string }> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrappingKey = await deriveBackupKey(password, salt);

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    wrappingKey,
    new Uint8Array(secretKey)
  );

  return {
    encryptedPrivateKey: uint8ArrayToBase64(new Uint8Array(encrypted)),
    salt: uint8ArrayToBase64(salt),
    iv: uint8ArrayToBase64(iv),
  };
}

/**
 * Decrypt private signing key from server backup using the user's password.
 */
export async function decryptPrivateKeyFromBackup(
  encryptedPrivateKeyB64: string,
  saltB64: string,
  ivB64: string,
  password: string
): Promise<Uint8Array> {
  const salt = base64ToUint8Array(saltB64);
  const iv = base64ToUint8Array(ivB64);
  const encrypted = base64ToUint8Array(encryptedPrivateKeyB64);
  const wrappingKey = await deriveBackupKey(password, salt);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(iv) },
    wrappingKey,
    new Uint8Array(encrypted)
  );

  return new Uint8Array(decrypted);
}
