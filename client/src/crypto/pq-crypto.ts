import {
  createMLDSA65,
  createMLKEM768,
  type MLDSA65,
  type MLKEM768,
} from '@oqs/liboqs-js';

let sigInstance: MLDSA65 | null = null;
let kemInstance: MLKEM768 | null = null;
let initPromise: Promise<void> | null = null;

/**
 * Initialize liboqs WASM modules for ML-DSA-65 and ML-KEM-768.
 * Safe to call multiple times; initialization runs once.
 */
export async function initCrypto(): Promise<void> {
  if (sigInstance && kemInstance) return;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    const [sig, kem] = await Promise.all([createMLDSA65(), createMLKEM768()]);
    sigInstance = sig;
    kemInstance = kem;
  })();

  try {
    await initPromise;
  } catch (err) {
    initPromise = null;
    throw err;
  }
}

export function isCryptoReady(): boolean {
  return sigInstance !== null && kemInstance !== null;
}

async function ensureSig(): Promise<MLDSA65> {
  if (!sigInstance) await initCrypto();
  if (!sigInstance) throw new Error('ML-DSA-65 WASM module not initialized');
  return sigInstance;
}

async function ensureKem(): Promise<MLKEM768> {
  if (!kemInstance) await initCrypto();
  if (!kemInstance) throw new Error('ML-KEM-768 WASM module not initialized');
  return kemInstance;
}

// ── Base64 Helpers (safe for large PQ keys/signatures) ──────────────────────

export function uint8ArrayToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

export function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const bytes =
    typeof data === 'string'
      ? new TextEncoder().encode(data)
      : new Uint8Array(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
  const hashArray = new Uint8Array(hashBuffer);
  return Array.from(hashArray)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function sha256Bytes(data: Uint8Array): Promise<Uint8Array> {
  const copy = new Uint8Array(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', copy);
  return new Uint8Array(hashBuffer);
}

// ── ML-DSA-65 Digital Signatures (NIST FIPS 204) ──────────────────────────

export async function generateSigningKeyPair(): Promise<{
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}> {
  const sig = await ensureSig();
  return sig.generateKeyPair();
}

export async function sign(
  message: Uint8Array,
  secretKey: Uint8Array
): Promise<Uint8Array> {
  const sig = await ensureSig();
  return sig.sign(message, secretKey);
}

export async function verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  const sig = await ensureSig();
  try {
    return sig.verify(message, signature, publicKey);
  } catch {
    return false;
  }
}

// ── ML-KEM-768 Key Encapsulation (NIST FIPS 203) ──────────────────────────

export async function generateKEMKeyPair(): Promise<{
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}> {
  const kem = await ensureKem();
  return kem.generateKeyPair();
}

export async function encapsulate(publicKey: Uint8Array): Promise<{
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}> {
  const kem = await ensureKem();
  return kem.encapsulate(publicKey);
}

export async function decapsulate(
  ciphertext: Uint8Array,
  secretKey: Uint8Array
): Promise<Uint8Array> {
  const kem = await ensureKem();
  return kem.decapsulate(ciphertext, secretKey);
}
