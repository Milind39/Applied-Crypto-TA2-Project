import { createHash } from 'crypto';
import { config } from '../config';

// We need dynamic import since @oqs/liboqs-js is ESM-only
let sigInstance: any = null;
let caPublicKey: Uint8Array;
let caSecretKey: Uint8Array;
const revokedFingerprints: Set<string> = new Set();

// Dynamic import helper that prevents TypeScript CommonJS compilation from rewriting import() to require()
const importEsm = new Function('specifier', 'return import(specifier)') as (
  specifier: string
) => Promise<typeof import('@oqs/liboqs-js')>;

async function loadLiboqs() {
  const { createMLDSA65 } = await importEsm('@oqs/liboqs-js');
  return createMLDSA65();
}

export async function initCA(): Promise<void> {
  sigInstance = await loadLiboqs();
  const keyPair = await sigInstance.generateKeyPair();
  caPublicKey = keyPair.publicKey;
  caSecretKey = keyPair.secretKey;
  console.log('[CA] Certificate Authority initialized with ML-DSA-65');
  console.log(`[CA] Public key length: ${caPublicKey.length} bytes`);
}

function computeFingerprint(publicSigningKey: string): string {
  return createHash('sha256').update(publicSigningKey).digest('hex');
}

export async function issueCertificate(
  userId: string,
  username: string,
  publicSigningKey: string
): Promise<{ certificate: string; caSignature: string; fingerprint: string }> {
  if (!sigInstance) throw new Error('CA not initialized');

  const fingerprint = computeFingerprint(publicSigningKey);
  const now = new Date();
  const expiresAt = new Date(now);
  expiresAt.setDate(expiresAt.getDate() + config.certValidityDays);

  const certData = {
    version: 1,
    userId,
    username,
    publicSigningKey,
    issuedAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    fingerprint,
  };

  const certificate = JSON.stringify(certData);
  const messageBytes = new TextEncoder().encode(certificate);
  const signatureBytes = await sigInstance.sign(messageBytes, caSecretKey);
  const caSignature = Buffer.from(signatureBytes).toString('base64');

  return { certificate, caSignature, fingerprint };
}

export async function verifyCertificate(
  certificate: string,
  caSignature: string
): Promise<boolean> {
  if (!sigInstance) throw new Error('CA not initialized');

  try {
    const messageBytes = new TextEncoder().encode(certificate);
    const signatureBytes = new Uint8Array(Buffer.from(caSignature, 'base64'));
    return await sigInstance.verify(messageBytes, signatureBytes, caPublicKey);
  } catch {
    return false;
  }
}

export function revokeCertificate(fingerprint: string): void {
  revokedFingerprints.add(fingerprint);
  console.log(`[CA] Certificate revoked: ${fingerprint.substring(0, 16)}...`);
}

export function getCRL(): string[] {
  return Array.from(revokedFingerprints);
}

export function getCAPublicKey(): string {
  if (!caPublicKey) throw new Error('CA not initialized');
  return Buffer.from(caPublicKey).toString('base64');
}

export function loadRevokedFingerprints(fingerprints: string[]): void {
  for (const fp of fingerprints) {
    revokedFingerprints.add(fp);
  }
}

export function isRevoked(fingerprint: string): boolean {
  return revokedFingerprints.has(fingerprint);
}
