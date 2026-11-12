import { Certificate, CryptoIdentity } from '../types';
import { base64ToUint8Array, uint8ArrayToBase64 } from './pq-crypto';

const DB_NAME = 'pq-messenger-keystore';
const DB_VERSION = 1;
const STORE_NAME = 'identities';

interface StoredIdentityRecord {
  userId: string;
  publicKeyB64: string;
  secretKeyB64: string;
  certificate: Certificate;
  updatedAt: string;
}

function openKeyDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'userId' });
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
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
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
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
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
 * Clear stored keys from IndexedDB on logout.
 */
export async function clearKeysFromIndexedDB(userId?: string): Promise<void> {
  const db = await openKeyDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    if (userId) {
      store.delete(userId);
    } else {
      store.clear();
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
