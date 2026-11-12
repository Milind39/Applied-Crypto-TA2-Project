import { Certificate, CryptoIdentity, SessionKeys } from '../types';
import {
  base64ToUint8Array,
  decapsulate,
  encapsulate,
  generateKEMKeyPair,
  sha256Bytes,
  sign,
  uint8ArrayToBase64,
  verify,
} from './pq-crypto';
import { deriveKeys } from './symmetric';

export interface PendingInitiatorHandshake {
  conversationId: string;
  peerId: string;
  kemKeyPair: { publicKey: Uint8Array; secretKey: Uint8Array };
  kemPublicKeyB64: string;
  createdAt: number;
}

export interface HandshakeInitPayload {
  targetUserId: string;
  conversationId: string;
  kemPublicKey: string;
  signedKemPublicKey: string;
  senderSigningPublicKey?: string;
}

export interface HandshakeRespondPayload {
  targetUserId: string;
  conversationId: string;
  encapsulatedKey: string;
  signedEncapsulatedKey: string;
  senderSigningPublicKey?: string;
}

/**
 * Per-conversation replay protection state tracking seen message IDs
 * and the highest incoming sequence number from the peer.
 */
export class ReplayProtector {
  private seenIds = new Set<string>();
  private maxIncomingSeq = new Map<string, number>();

  /**
   * Record historical messages already persisted on the server so they are
   * not treated as live replay attacks, while preventing future duplicates.
   */
  recordHistorical(conversationId: string, messageId: string, sequenceNumber: number): void {
    this.seenIds.add(messageId);
    const current = this.maxIncomingSeq.get(conversationId) ?? 0;
    if (sequenceNumber > current) {
      this.maxIncomingSeq.set(conversationId, sequenceNumber);
    }
  }

  /**
   * Validate a live incoming message against replay attacks.
   * Throws an error if messageId was already seen or sequenceNumber regressed.
   */
  verifyAndTrackIncoming(
    conversationId: string,
    messageId: string,
    sequenceNumber: number
  ): void {
    if (this.seenIds.has(messageId)) {
      throw new Error(`Replay detected: duplicate message ID ${messageId}`);
    }
    const lastSeq = this.maxIncomingSeq.get(conversationId) ?? 0;
    if (sequenceNumber > 0 && sequenceNumber <= lastSeq) {
      throw new Error(
        `Replay detected: stale sequence number ${sequenceNumber} <= ${lastSeq}`
      );
    }
    this.seenIds.add(messageId);
    if (sequenceNumber > lastSeq) {
      this.maxIncomingSeq.set(conversationId, sequenceNumber);
    }
  }

  resetConversation(conversationId: string): void {
    this.maxIncomingSeq.delete(conversationId);
  }
}

/**
 * Verify a user's certificate locally using the CA's ML-DSA-65 public key,
 * checking expiration, userId binding, and CRL revocation list.
 */
export async function verifyPeerCertificate(
  cert: Certificate,
  caPublicKeyB64: string,
  crl: string[],
  expectedUserId?: string
): Promise<{ valid: boolean; reason?: string }> {
  if (!cert.rawCertificate || !cert.caSignature) {
    return { valid: false, reason: 'Missing raw certificate or CA signature' };
  }

  if (cert.isRevoked || crl.includes(cert.fingerprint)) {
    return { valid: false, reason: 'Certificate has been revoked' };
  }

  if (new Date(cert.expiresAt) < new Date()) {
    return { valid: false, reason: 'Certificate has expired' };
  }

  if (expectedUserId && cert.userId !== expectedUserId) {
    return { valid: false, reason: 'Certificate userId mismatch' };
  }

  try {
    const parsed = JSON.parse(cert.rawCertificate);
    if (parsed.publicSigningKey !== cert.publicSigningKey) {
      return { valid: false, reason: 'Certificate signing key mismatch' };
    }
    if (expectedUserId && parsed.userId !== expectedUserId) {
      return { valid: false, reason: 'Certificate payload userId mismatch' };
    }
  } catch {
    return { valid: false, reason: 'Malformed certificate JSON' };
  }

  const caPublicKey = base64ToUint8Array(caPublicKeyB64);
  const caSignature = base64ToUint8Array(cert.caSignature);
  const messageBytes = new TextEncoder().encode(cert.rawCertificate);

  const signatureValid = await verify(messageBytes, caSignature, caPublicKey);
  if (!signatureValid) {
    return { valid: false, reason: 'Invalid CA ML-DSA-65 signature' };
  }

  return { valid: true };
}

/**
 * Build deterministic handshake transcript hash:
 * SHA-256(aliceKemPubKey || bobEncapsulatedCiphertext || aliceCertRaw || bobCertRaw)
 */
export async function computeHandshakeTranscript(
  aliceKemPubKey: Uint8Array,
  bobCiphertext: Uint8Array,
  aliceCertRaw: string,
  bobCertRaw: string
): Promise<Uint8Array> {
  const aliceCertBytes = new TextEncoder().encode(aliceCertRaw);
  const bobCertBytes = new TextEncoder().encode(bobCertRaw);

  const combined = new Uint8Array(
    aliceKemPubKey.length +
      bobCiphertext.length +
      aliceCertBytes.length +
      bobCertBytes.length
  );

  let offset = 0;
  combined.set(aliceKemPubKey, offset);
  offset += aliceKemPubKey.length;
  combined.set(bobCiphertext, offset);
  offset += bobCiphertext.length;
  combined.set(aliceCertBytes, offset);
  offset += aliceCertBytes.length;
  combined.set(bobCertBytes, offset);

  return sha256Bytes(combined);
}

/**
 * Initiator (Alice) Step 1:
 * Generate ephemeral ML-KEM-768 key pair and sign the KEM public key with ML-DSA-65.
 */
export async function createHandshakeInitiation(
  identity: CryptoIdentity,
  conversationId: string,
  peerId: string
): Promise<{
  pending: PendingInitiatorHandshake;
  payload: HandshakeInitPayload;
}> {
  const kemKeyPair = await generateKEMKeyPair();
  const signatureBytes = await sign(
    kemKeyPair.publicKey,
    identity.signingKeyPair.secretKey
  );

  const kemPublicKeyB64 = uint8ArrayToBase64(kemKeyPair.publicKey);
  const signedKemPublicKey = uint8ArrayToBase64(signatureBytes);

  return {
    pending: {
      conversationId,
      peerId,
      kemKeyPair,
      kemPublicKeyB64,
      createdAt: Date.now(),
    },
    payload: {
      targetUserId: peerId,
      conversationId,
      kemPublicKey: kemPublicKeyB64,
      signedKemPublicKey,
      senderSigningPublicKey: identity.certificate.publicSigningKey,
    },
  };
}

/**
 * Responder (Bob) Step 2:
 * Verify Alice's certificate and ML-DSA-65 signature on her KEM public key,
 * encapsulate a shared secret via ML-KEM-768, sign the ciphertext, and derive session keys.
 */
export async function respondToHandshake(
  identity: CryptoIdentity,
  conversationId: string,
  peerId: string,
  peerCertificate: Certificate,
  caPublicKeyB64: string,
  crl: string[],
  aliceKemPublicKeyB64: string,
  aliceSignedKemPublicKeyB64: string
): Promise<{
  sessionKeys: SessionKeys;
  payload: HandshakeRespondPayload;
}> {
  const certCheck = await verifyPeerCertificate(
    peerCertificate,
    caPublicKeyB64,
    crl,
    peerId
  );
  if (!certCheck.valid) {
    throw new Error(`Peer certificate verification failed: ${certCheck.reason}`);
  }

  const aliceKemPubKey = base64ToUint8Array(aliceKemPublicKeyB64);
  const aliceSignature = base64ToUint8Array(aliceSignedKemPublicKeyB64);
  const aliceSigningPubKey = base64ToUint8Array(peerCertificate.publicSigningKey);

  const sigValid = await verify(aliceKemPubKey, aliceSignature, aliceSigningPubKey);
  if (!sigValid) {
    throw new Error('Peer ML-DSA-65 signature verification failed on KEM public key');
  }

  const { ciphertext, sharedSecret } = await encapsulate(aliceKemPubKey);
  const responseSignature = await sign(ciphertext, identity.signingKeyPair.secretKey);

  const transcript = await computeHandshakeTranscript(
    aliceKemPubKey,
    ciphertext,
    peerCertificate.rawCertificate || JSON.stringify(peerCertificate),
    identity.certificate.rawCertificate || JSON.stringify(identity.certificate)
  );

  const { sendKey, receiveKey } = await deriveKeys(
    sharedSecret,
    conversationId,
    transcript,
    false // Bob is responder
  );

  return {
    sessionKeys: {
      conversationId,
      peerId,
      sendKey,
      receiveKey,
      sequenceNumber: 0,
      establishedAt: new Date().toISOString(),
      peerFingerprint: peerCertificate.fingerprint,
      peerVerified: true,
    },
    payload: {
      targetUserId: peerId,
      conversationId,
      encapsulatedKey: uint8ArrayToBase64(ciphertext),
      signedEncapsulatedKey: uint8ArrayToBase64(responseSignature),
      senderSigningPublicKey: identity.certificate.publicSigningKey,
    },
  };
}

/**
 * Initiator (Alice) Step 3:
 * Verify Bob's certificate and ML-DSA-65 signature on encapsulated ciphertext,
 * decapsulate shared secret, and derive directional session keys.
 */
export async function completeHandshakeInitiation(
  identity: CryptoIdentity,
  pending: PendingInitiatorHandshake,
  peerCertificate: Certificate,
  caPublicKeyB64: string,
  crl: string[],
  bobEncapsulatedKeyB64: string,
  bobSignedEncapsulatedKeyB64: string
): Promise<SessionKeys> {
  const certCheck = await verifyPeerCertificate(
    peerCertificate,
    caPublicKeyB64,
    crl,
    pending.peerId
  );
  if (!certCheck.valid) {
    throw new Error(`Peer certificate verification failed: ${certCheck.reason}`);
  }

  const ciphertext = base64ToUint8Array(bobEncapsulatedKeyB64);
  const bobSignature = base64ToUint8Array(bobSignedEncapsulatedKeyB64);
  const bobSigningPubKey = base64ToUint8Array(peerCertificate.publicSigningKey);

  const sigValid = await verify(ciphertext, bobSignature, bobSigningPubKey);
  if (!sigValid) {
    throw new Error('Peer ML-DSA-65 signature verification failed on encapsulated key');
  }

  const sharedSecret = await decapsulate(ciphertext, pending.kemKeyPair.secretKey);

  const transcript = await computeHandshakeTranscript(
    pending.kemKeyPair.publicKey,
    ciphertext,
    identity.certificate.rawCertificate || JSON.stringify(identity.certificate),
    peerCertificate.rawCertificate || JSON.stringify(peerCertificate)
  );

  const { sendKey, receiveKey } = await deriveKeys(
    sharedSecret,
    pending.conversationId,
    transcript,
    true // Alice is initiator
  );

  return {
    conversationId: pending.conversationId,
    peerId: pending.peerId,
    sendKey,
    receiveKey,
    sequenceNumber: 0,
    establishedAt: new Date().toISOString(),
    peerFingerprint: peerCertificate.fingerprint,
    peerVerified: true,
  };
}
