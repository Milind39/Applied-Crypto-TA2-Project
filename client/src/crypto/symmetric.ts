import { base64ToUint8Array, uint8ArrayToBase64 } from './pq-crypto';

/**
 * Derive directional AES-256-GCM session keys from an ML-KEM-768 shared secret
 * using HKDF-SHA-256 bound to the sessionId and handshake transcript.
 */
export async function deriveKeys(
  sharedSecret: Uint8Array,
  sessionId: string,
  transcript: Uint8Array,
  isInitiator: boolean
): Promise<{ sendKey: CryptoKey; receiveKey: CryptoKey; isInitiator: boolean }> {
  const secretCopy = new Uint8Array(sharedSecret);
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    secretCopy,
    'HKDF',
    false,
    ['deriveKey']
  );

  // Bind salt to sessionId + transcript hash
  const sessionBytes = new TextEncoder().encode(sessionId);
  const saltInput = new Uint8Array(sessionBytes.length + transcript.length);
  saltInput.set(sessionBytes, 0);
  saltInput.set(transcript, sessionBytes.length);
  const saltDigest = new Uint8Array(
    await crypto.subtle.digest('SHA-256', saltInput)
  );

  const aliceToBobKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: saltDigest,
      info: new TextEncoder().encode('pq-messenger:alice-to-bob:v1'),
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  const bobToAliceKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: saltDigest,
      info: new TextEncoder().encode('pq-messenger:bob-to-alice:v1'),
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  return {
    sendKey: isInitiator ? aliceToBobKey : bobToAliceKey,
    receiveKey: isInitiator ? bobToAliceKey : aliceToBobKey,
    isInitiator,
  };
}

function canonicalizeValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalizeValue);
  }
  if (value !== null && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
      if (obj[key] !== undefined) {
        sorted[key] = canonicalizeValue(obj[key]);
      }
    }
    return sorted;
  }
  return value;
}

function buildCanonicalAAD(
  sequenceNumber: number,
  metadata?: Record<string, any>
): Uint8Array<ArrayBuffer> {
  const raw = metadata ? { seq: sequenceNumber, ...metadata } : { seq: sequenceNumber };
  const canonical = canonicalizeValue(raw);
  return new Uint8Array(new TextEncoder().encode(JSON.stringify(canonical)));
}

/**
 * Encrypt plaintext using AES-256-GCM with a fresh 96-bit CSPRNG nonce
 * and authenticated associated data (sequence number + metadata).
 */
export async function encrypt(
  plaintext: string,
  key: CryptoKey,
  sequenceNumber: number,
  metadata?: Record<string, any>
): Promise<{ ciphertext: string; nonce: string; iv: string; tag: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit unique nonce
  const encodedText = new TextEncoder().encode(plaintext);
  const aad = buildCanonicalAAD(sequenceNumber, metadata);

  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: aad,
      tagLength: 128,
    },
    key,
    encodedText
  );

  // Web Crypto appends the 16-byte authentication tag to the ciphertext
  const encryptedArray = new Uint8Array(encrypted);
  const ct = encryptedArray.slice(0, encryptedArray.length - 16);
  const tag = encryptedArray.slice(encryptedArray.length - 16);

  const ivB64 = uint8ArrayToBase64(iv);
  return {
    ciphertext: uint8ArrayToBase64(ct),
    nonce: ivB64,
    iv: ivB64,
    tag: uint8ArrayToBase64(tag),
  };
}

/**
 * Decrypt AES-256-GCM ciphertext and verify the 128-bit authentication tag and AAD.
 */
export async function decrypt(
  ciphertext: string,
  nonce: string,
  tag: string,
  key: CryptoKey,
  sequenceNumber: number,
  metadata?: Record<string, any>
): Promise<string> {
  const iv = base64ToUint8Array(nonce);
  const ct = base64ToUint8Array(ciphertext);
  const tagBytes = base64ToUint8Array(tag);
  const aad = buildCanonicalAAD(sequenceNumber, metadata);

  // Recombine ciphertext + tag for Web Crypto AES-GCM
  const combined = new Uint8Array(ct.length + tagBytes.length);
  combined.set(ct, 0);
  combined.set(tagBytes, ct.length);

  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: new Uint8Array(iv),
      additionalData: aad,
      tagLength: 128,
    },
    key,
    combined
  );

  return new TextDecoder().decode(decrypted);
}
