process.env.NODE_ENV = 'test';
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto, { webcrypto } from 'node:crypto';
import { io as ioClient, Socket } from 'socket.io-client';
import { v4 as uuidv4 } from 'uuid';
import { createServerApp } from '../src/index';
import { pool, query } from '../src/db';
import {
  issueCertificate,
  verifyCertificate,
} from '../src/ca/certificate-authority';

const subtle = webcrypto.subtle;

const importEsm = new Function('specifier', 'return import(specifier)') as (
  specifier: string
) => Promise<typeof import('@oqs/liboqs-js')>;

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function fromBase64(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

async function deriveDirectionalKeys(
  sharedSecret: Uint8Array,
  sessionId: string,
  transcript: Uint8Array
) {
  const keyMaterial = await subtle.importKey(
    'raw',
    Buffer.from(sharedSecret),
    'HKDF',
    false,
    ['deriveKey']
  );

  // Bind salt to sessionId + handshake transcript hash
  const transcriptHash = new Uint8Array(
    await subtle.digest('SHA-256', Buffer.from(transcript))
  );
  const sessionBytes = new TextEncoder().encode(sessionId);
  const salt = new Uint8Array(sessionBytes.length + transcriptHash.length);
  salt.set(sessionBytes, 0);
  salt.set(transcriptHash, sessionBytes.length);

  const aliceToBobKey = await subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: new TextEncoder().encode('alice-to-bob'),
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  const bobToAliceKey = await subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: new TextEncoder().encode('bob-to-alice'),
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  return { aliceToBobKey, bobToAliceKey };
}

async function encryptAesGcm(
  plaintext: string,
  key: webcrypto.CryptoKey,
  sequenceNumber: number,
  metadata: Record<string, any> = {}
) {
  const iv = crypto.randomBytes(12);
  const aad = new TextEncoder().encode(
    JSON.stringify({ seq: sequenceNumber, ...metadata })
  );
  const encoded = new TextEncoder().encode(plaintext);

  const encrypted = new Uint8Array(
    await subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
      key,
      encoded
    )
  );

  const ct = encrypted.slice(0, encrypted.length - 16);
  const tag = encrypted.slice(encrypted.length - 16);

  return {
    ciphertext: toBase64(ct),
    nonce: toBase64(iv),
    iv: toBase64(iv),
    tag: toBase64(tag),
  };
}

async function decryptAesGcm(
  ciphertextB64: string,
  nonceB64: string,
  tagB64: string,
  key: webcrypto.CryptoKey,
  sequenceNumber: number,
  metadata: Record<string, any> = {}
): Promise<string> {
  const iv = fromBase64(nonceB64);
  const ct = fromBase64(ciphertextB64);
  const tag = fromBase64(tagB64);
  const aad = new TextEncoder().encode(
    JSON.stringify({ seq: sequenceNumber, ...metadata })
  );

  const combined = new Uint8Array(ct.length + tag.length);
  combined.set(ct, 0);
  combined.set(tag, ct.length);

  const decrypted = await subtle.decrypt(
    { name: 'AES-GCM', iv: Buffer.from(iv), additionalData: aad, tagLength: 128 },
    key,
    combined
  );

  return new TextDecoder().decode(decrypted);
}

describe('Post-Quantum Secure Messenger Security & Integration Suite', () => {
  let server: http.Server;
  let baseUrl: string;
  let dsa: any;
  let kem: any;

  const runSuffix = crypto.randomBytes(4).toString('hex');
  const aliceCreds = {
    username: `alice_${runSuffix}`,
    email: `alice_${runSuffix}@example.com`,
    password: 'AliceSecurePass123!',
  };
  const bobCreds = {
    username: `bob_${runSuffix}`,
    email: `bob_${runSuffix}@example.com`,
    password: 'BobSecurePass123!',
  };
  const eveCreds = {
    username: `eve_${runSuffix}`,
    email: `eve_${runSuffix}@example.com`,
    password: 'EveSecurePass123!',
  };

  let aliceId: string;
  let aliceToken: string;
  let bobId: string;
  let bobToken: string;
  let eveToken: string;
  let conversationId: string;

  let aliceSignKeys: { publicKey: Uint8Array; secretKey: Uint8Array };
  let bobSignKeys: { publicKey: Uint8Array; secretKey: Uint8Array };
  let aliceCertPayload: {
    certificate: string;
    caSignature: string;
    fingerprint: string;
  };
  let bobCertPayload: {
    certificate: string;
    caSignature: string;
    fingerprint: string;
  };
  let caPublicKeyBytes: Uint8Array;

  let aliceToBobKey: webcrypto.CryptoKey;
  let bobToAliceKey: webcrypto.CryptoKey;
  let csrfToken: string;

  const createdUserIds: string[] = [];

  function csrfHeaders(extra: Record<string, string> = {}): Record<string, string> {
    return {
      Cookie: `csrf-token=${csrfToken}`,
      'X-CSRF-Token': csrfToken,
      ...extra,
    };
  }

  before(async () => {
    const liboqs = await importEsm('@oqs/liboqs-js');
    dsa = await liboqs.createMLDSA65();
    kem = await liboqs.createMLKEM768();

    const appBundle = await createServerApp();
    server = appBundle.server;

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve());
    });
    const addr = server.address() as { port: number };
    baseUrl = `http://127.0.0.1:${addr.port}`;

    const csrfRes = await fetch(`${baseUrl}/api/csrf-token`);
    assert.equal(csrfRes.status, 200);
    const csrfJson = (await csrfRes.json()) as any;
    csrfToken = csrfJson.csrfToken;
    assert.ok(csrfToken);
  });

  after(async () => {
    for (const uid of createdUserIds) {
      await query('DELETE FROM users WHERE id = $1', [uid]).catch(() => {});
    }
    if (dsa) dsa.destroy();
    if (kem) kem.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await pool.end();
  });

  it('1. Registers Alice, Bob, and Eve with Argon2id hashing and rejects weak passwords', async () => {
    // Rejects state-changing requests missing or mismatching CSRF double-submit tokens
    const noCsrfRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: `nocsrf_${runSuffix}`,
        email: `nocsrf_${runSuffix}@example.com`,
        password: 'ValidPassword123!',
        confirmPassword: 'ValidPassword123!',
      }),
    });
    assert.equal(noCsrfRes.status, 403);

    const mismatchCsrfRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: `csrf-token=${csrfToken}`,
        'X-CSRF-Token': 'wrong-token',
      },
      body: JSON.stringify({
        username: `nocsrf_${runSuffix}`,
        email: `nocsrf_${runSuffix}@example.com`,
        password: 'ValidPassword123!',
        confirmPassword: 'ValidPassword123!',
      }),
    });
    assert.equal(mismatchCsrfRes.status, 403);

    // Weak password rejected
    const weakRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        username: `weak_${runSuffix}`,
        email: `weak_${runSuffix}@example.com`,
        password: 'weak',
        confirmPassword: 'weak',
      }),
    });
    assert.equal(weakRes.status, 400);

    // Register Alice
    const aliceRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        ...aliceCreds,
        confirmPassword: aliceCreds.password,
      }),
    });
    assert.equal(aliceRes.status, 201);
    const aliceJson = (await aliceRes.json()) as any;
    aliceId = aliceJson.user.id;
    aliceToken = aliceJson.token;
    createdUserIds.push(aliceId);

    // Verify stored hash uses argon2id and is not plaintext password
    const dbUser = await query<{ password_hash: string }>(
      'SELECT password_hash FROM users WHERE id = $1',
      [aliceId]
    );
    assert.ok(dbUser.rows[0].password_hash.startsWith('$argon2id$'));
    assert.notEqual(dbUser.rows[0].password_hash, aliceCreds.password);

    // Register Bob
    const bobRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        ...bobCreds,
        confirmPassword: bobCreds.password,
      }),
    });
    assert.equal(bobRes.status, 201);
    const bobJson = (await bobRes.json()) as any;
    bobId = bobJson.user.id;
    bobToken = bobJson.token;
    createdUserIds.push(bobId);

    // Register Eve
    const eveRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        ...eveCreds,
        confirmPassword: eveCreds.password,
      }),
    });
    assert.equal(eveRes.status, 201);
    const eveJson = (await eveRes.json()) as any;
    eveToken = eveJson.token;
    createdUserIds.push(eveJson.user.id);
  });

  it('2. Rejects unauthenticated requests to protected REST and Socket.IO endpoints', async () => {
    const protectedGets = [
      '/api/auth/me',
      '/api/users/search?q=alice',
      '/api/conversations',
      '/api/keys/backup',
    ];
    for (const path of protectedGets) {
      const res = await fetch(`${baseUrl}${path}`);
      assert.equal(res.status, 401, `Expected 401 on GET ${path}`);
    }

    const msgRes = await fetch(`${baseUrl}/api/messages`, {
      method: 'POST',
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ conversationId: uuidv4(), ciphertext: 'abc' }),
    });
    assert.equal(msgRes.status, 401);

    // Socket.IO unauthenticated connection rejected
    await assert.rejects(
      () =>
        new Promise<void>((resolve, reject) => {
          const s = ioClient(baseUrl, {
            transports: ['websocket'],
            reconnection: false,
          });
          s.on('connect', () => {
            s.close();
            resolve();
          });
          s.on('connect_error', (err) => {
            s.close();
            reject(err);
          });
        }),
      /Authentication required/
    );

    // Verify unverified user is blocked from logging in
    const oldEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    try {
      const eveId = createdUserIds[createdUserIds.length - 1];
      await query('UPDATE users SET is_email_verified = FALSE WHERE id = $1', [eveId]);
      const unverifiedLoginRes = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: csrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({
          email: eveCreds.email,
          password: eveCreds.password,
        }),
      });
      assert.equal(unverifiedLoginRes.status, 403);
      const unverifiedJson = (await unverifiedLoginRes.json()) as any;
      assert.equal(unverifiedJson.needsVerification, true);

      // Verify email and verify login now succeeds
      await query('UPDATE users SET is_email_verified = TRUE WHERE id = $1', [eveId]);
      const verifiedLoginRes = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: csrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({
          email: eveCreds.email,
          password: eveCreds.password,
        }),
      });
      assert.equal(verifiedLoginRes.status, 200);
    } finally {
      process.env.NODE_ENV = oldEnv;
    }
  });

  it('3. Alice & Bob generate distinct ML-DSA-65 identities and receive valid CA-signed certs', async () => {
    const caRes = await fetch(`${baseUrl}/api/ca/public-key`);
    assert.equal(caRes.status, 200);
    const caJson = (await caRes.json()) as any;
    caPublicKeyBytes = fromBase64(caJson.publicKey);
    assert.equal(caPublicKeyBytes.length, 1952); // ML-DSA-65 public key size

    aliceSignKeys = await dsa.generateKeyPair();
    bobSignKeys = await dsa.generateKeyPair();
    assert.notDeepEqual(aliceSignKeys.publicKey, bobSignKeys.publicKey);

    // Issue Alice cert
    const aCertRes = await fetch(`${baseUrl}/api/certificates/issue`, {
      method: 'POST',
      headers: csrfHeaders({
        'Content-Type': 'application/json',
        Authorization: `Bearer ${aliceToken}`,
      }),
      body: JSON.stringify({
        publicSigningKey: toBase64(aliceSignKeys.publicKey),
      }),
    });
    assert.equal(aCertRes.status, 201);
    aliceCertPayload = (await aCertRes.json()) as any;

    // Issue Bob cert
    const bCertRes = await fetch(`${baseUrl}/api/certificates/issue`, {
      method: 'POST',
      headers: csrfHeaders({
        'Content-Type': 'application/json',
        Authorization: `Bearer ${bobToken}`,
      }),
      body: JSON.stringify({
        publicSigningKey: toBase64(bobSignKeys.publicKey),
      }),
    });
    assert.equal(bCertRes.status, 201);
    bobCertPayload = (await bCertRes.json()) as any;

    assert.notEqual(
      aliceCertPayload.fingerprint,
      bobCertPayload.fingerprint
    );

    // Verify Alice cert via CA public key locally AND via API
    const localValid = await dsa.verify(
      new TextEncoder().encode(aliceCertPayload.certificate),
      fromBase64(aliceCertPayload.caSignature),
      caPublicKeyBytes
    );
    assert.equal(localValid, true);

    const apiVerifyRes = await fetch(`${baseUrl}/api/certificates/verify`, {
      method: 'POST',
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        certificate: aliceCertPayload.certificate,
        caSignature: aliceCertPayload.caSignature,
      }),
    });
    assert.equal(apiVerifyRes.status, 200);
    const apiVerifyJson = (await apiVerifyRes.json()) as any;
    assert.equal(apiVerifyJson.valid, true);
    assert.equal(apiVerifyJson.signatureValid, true);
    assert.equal(apiVerifyJson.revoked, false);
    assert.equal(apiVerifyJson.expired, false);
  });

  it('4. Rejects invalid, expired, and revoked certificates and invalid ML-DSA-65 signatures', async () => {
    // Tampered certificate payload
    const parsed = JSON.parse(aliceCertPayload.certificate);
    parsed.username = 'mallory';
    const tamperedCert = JSON.stringify(parsed);

    const tamperedRes = await fetch(`${baseUrl}/api/certificates/verify`, {
      method: 'POST',
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        certificate: tamperedCert,
        caSignature: aliceCertPayload.caSignature,
      }),
    });
    const tamperedJson = (await tamperedRes.json()) as any;
    assert.equal(tamperedJson.valid, false);
    assert.equal(tamperedJson.signatureValid, false);

    // Expired certificate (even if CA-signed or forged expiry)
    const expiredObj = {
      ...JSON.parse(aliceCertPayload.certificate),
      expiresAt: new Date(Date.now() - 60_000).toISOString(),
    };
    const expiredRes = await fetch(`${baseUrl}/api/certificates/verify`, {
      method: 'POST',
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        certificate: JSON.stringify(expiredObj),
        caSignature: aliceCertPayload.caSignature,
      }),
    });
    const expiredJson = (await expiredRes.json()) as any;
    assert.equal(expiredJson.valid, false);
    assert.equal(expiredJson.expired, true);

    // Invalid ML-DSA-65 signature directly
    const msg = new TextEncoder().encode('authentic-handshake-payload');
    const validSig = await dsa.sign(msg, aliceSignKeys.secretKey);
    assert.equal(await dsa.verify(msg, validSig, aliceSignKeys.publicKey), true);
    assert.equal(
      await dsa.verify(
        new TextEncoder().encode('tampered-handshake-payload'),
        validSig,
        aliceSignKeys.publicKey
      ),
      false
    );
    assert.equal(
      await dsa.verify(msg, validSig, bobSignKeys.publicKey),
      false
    );

    // Revoke Eve's certificate and verify CRL rejection
    const eveSignKeys = await dsa.generateKeyPair();
    const eveIssueRes = await fetch(`${baseUrl}/api/certificates/issue`, {
      method: 'POST',
      headers: csrfHeaders({
        'Content-Type': 'application/json',
        Authorization: `Bearer ${eveToken}`,
      }),
      body: JSON.stringify({
        publicSigningKey: toBase64(eveSignKeys.publicKey),
      }),
    });
    assert.equal(eveIssueRes.status, 201);
    const eveCert = (await eveIssueRes.json()) as any;

    const revokeRes = await fetch(`${baseUrl}/api/certificates/revoke`, {
      method: 'POST',
      headers: csrfHeaders({ Authorization: `Bearer ${eveToken}` }),
    });
    assert.equal(revokeRes.status, 200);

    const crlRes = await fetch(`${baseUrl}/api/certificates/crl`);
    const crlJson = (await crlRes.json()) as any;
    assert.ok(crlJson.crl.includes(eveCert.fingerprint));

    const verifyRevokedRes = await fetch(`${baseUrl}/api/certificates/verify`, {
      method: 'POST',
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        certificate: eveCert.certificate,
        caSignature: eveCert.caSignature,
      }),
    });
    const verifyRevokedJson = (await verifyRevokedRes.json()) as any;
    assert.equal(verifyRevokedJson.valid, false);
    assert.equal(verifyRevokedJson.revoked, true);
  });

  it('5. Alice & Bob derive matching ML-KEM-768 shared secrets and distinct directional HKDF-SHA-256 keys', async () => {
    // Alice generates ephemeral ML-KEM-768 keypair & signs public key with ML-DSA-65
    const aliceKem = await kem.generateKeyPair();
    const aliceKemSig = await dsa.sign(
      aliceKem.publicKey,
      aliceSignKeys.secretKey
    );

    // Bob verifies Alice's certificate and signature on KEM public key
    assert.equal(
      await verifyCertificate(
        aliceCertPayload.certificate,
        aliceCertPayload.caSignature
      ),
      true
    );
    assert.equal(
      await dsa.verify(aliceKem.publicKey, aliceKemSig, aliceSignKeys.publicKey),
      true
    );

    // Bob encapsulates & signs ciphertext with his ML-DSA-65 key
    const { ciphertext: kemCt, sharedSecret: bobSharedSecret } =
      await kem.encapsulate(aliceKem.publicKey);
    const bobCtSig = await dsa.sign(kemCt, bobSignKeys.secretKey);

    // Alice verifies Bob's certificate & signature, then decapsulates
    assert.equal(
      await verifyCertificate(
        bobCertPayload.certificate,
        bobCertPayload.caSignature
      ),
      true
    );
    assert.equal(
      await dsa.verify(kemCt, bobCtSig, bobSignKeys.publicKey),
      true
    );
    const aliceSharedSecret = await kem.decapsulate(kemCt, aliceKem.secretKey);

    assert.deepEqual(aliceSharedSecret, bobSharedSecret);

    // Build handshake transcript & derive directional keys
    const transcript = new TextEncoder().encode(
      `${toBase64(aliceKem.publicKey)}|${toBase64(kemCt)}|${aliceCertPayload.fingerprint}|${bobCertPayload.fingerprint}`
    );
    const sessionId = `session-${runSuffix}`;

    const aliceDerived = await deriveDirectionalKeys(
      aliceSharedSecret,
      sessionId,
      transcript
    );
    const bobDerived = await deriveDirectionalKeys(
      bobSharedSecret,
      sessionId,
      transcript
    );

    const a2bRawA = new Uint8Array(
      await subtle.exportKey('raw', aliceDerived.aliceToBobKey)
    );
    const a2bRawB = new Uint8Array(
      await subtle.exportKey('raw', bobDerived.aliceToBobKey)
    );
    const b2aRawA = new Uint8Array(
      await subtle.exportKey('raw', aliceDerived.bobToAliceKey)
    );
    const b2aRawB = new Uint8Array(
      await subtle.exportKey('raw', bobDerived.bobToAliceKey)
    );

    assert.deepEqual(a2bRawA, a2bRawB);
    assert.deepEqual(b2aRawA, b2aRawB);
    assert.notDeepEqual(a2bRawA, b2aRawA); // Directional separation

    aliceToBobKey = aliceDerived.aliceToBobKey;
    bobToAliceKey = bobDerived.bobToAliceKey;
  });

  it('6. AES-256-GCM encrypts/decrypts valid messages and rejects tampered ciphertext, tag, or AAD', async () => {
    const plaintext = 'Top-secret post-quantum message from Alice to Bob';
    const meta = { senderId: aliceId, algo: 'AES-256-GCM' };
    const enc = await encryptAesGcm(plaintext, aliceToBobKey, 1, meta);

    // Valid decrypt
    const dec = await decryptAesGcm(
      enc.ciphertext,
      enc.nonce,
      enc.tag,
      aliceToBobKey,
      1,
      meta
    );
    assert.equal(dec, plaintext);

    // Wrong directional key rejected
    await assert.rejects(() =>
      decryptAesGcm(enc.ciphertext, enc.nonce, enc.tag, bobToAliceKey, 1, meta)
    );

    // Tampered ciphertext rejected
    const ctBytes = fromBase64(enc.ciphertext);
    ctBytes[0] ^= 0xff;
    await assert.rejects(() =>
      decryptAesGcm(
        toBase64(ctBytes),
        enc.nonce,
        enc.tag,
        aliceToBobKey,
        1,
        meta
      )
    );

    // Tampered auth tag rejected
    const tagBytes = fromBase64(enc.tag);
    tagBytes[0] ^= 0xff;
    await assert.rejects(() =>
      decryptAesGcm(
        enc.ciphertext,
        enc.nonce,
        toBase64(tagBytes),
        aliceToBobKey,
        1,
        meta
      )
    );

    // Tampered AAD (wrong sequenceNumber) rejected
    await assert.rejects(() =>
      decryptAesGcm(enc.ciphertext, enc.nonce, enc.tag, aliceToBobKey, 2, meta)
    );
  });

  it('7. Creates conversation, rejects non-participants, enforces replay protection & zero-knowledge DB storage', async () => {
    const convRes = await fetch(`${baseUrl}/api/conversations`, {
      method: 'POST',
      headers: csrfHeaders({
        'Content-Type': 'application/json',
        Authorization: `Bearer ${aliceToken}`,
      }),
      body: JSON.stringify({ participantId: bobId }),
    });
    assert.equal(convRes.status, 201);
    const convJson = (await convRes.json()) as any;
    conversationId = convJson.conversation.id;

    // Eve cannot access Alice-Bob conversation
    const eveGetMsgs = await fetch(
      `${baseUrl}/api/conversations/${conversationId}/messages`,
      { headers: { Authorization: `Bearer ${eveToken}` } }
    );
    assert.equal(eveGetMsgs.status, 403);

    const secretText = 'Sensitive plaintext that must NEVER touch the backend DB';
    const meta = { senderId: aliceId };
    const enc1 = await encryptAesGcm(secretText, aliceToBobKey, 1, meta);
    const msgId1 = uuidv4();

    // Plaintext field rejected
    const plaintextAttempt = await fetch(`${baseUrl}/api/messages`, {
      method: 'POST',
      headers: csrfHeaders({
        'Content-Type': 'application/json',
        Authorization: `Bearer ${aliceToken}`,
      }),
      body: JSON.stringify({
        conversationId,
        ciphertext: enc1.ciphertext,
        plaintext: secretText,
      }),
    });
    assert.equal(plaintextAttempt.status, 400);

    // Store encrypted message seq=1
    const postRes1 = await fetch(`${baseUrl}/api/messages`, {
      method: 'POST',
      headers: csrfHeaders({
        'Content-Type': 'application/json',
        Authorization: `Bearer ${aliceToken}`,
      }),
      body: JSON.stringify({
        messageId: msgId1,
        conversationId,
        ciphertext: enc1.ciphertext,
        nonce: enc1.nonce,
        iv: enc1.iv,
        tag: enc1.tag,
        sequenceNumber: 1,
        metadata: meta,
      }),
    });
    assert.equal(postRes1.status, 201);

    // Replay same sequenceNumber=1 -> 409 Conflict
    const replaySeqRes = await fetch(`${baseUrl}/api/messages`, {
      method: 'POST',
      headers: csrfHeaders({
        'Content-Type': 'application/json',
        Authorization: `Bearer ${aliceToken}`,
      }),
      body: JSON.stringify({
        messageId: uuidv4(),
        conversationId,
        ciphertext: enc1.ciphertext,
        nonce: enc1.nonce,
        iv: enc1.iv,
        tag: enc1.tag,
        sequenceNumber: 1,
        metadata: meta,
      }),
    });
    assert.equal(replaySeqRes.status, 409);

    // Replay same messageId with higher seq=2 -> 409 Conflict
    const replayIdRes = await fetch(`${baseUrl}/api/messages`, {
      method: 'POST',
      headers: csrfHeaders({
        'Content-Type': 'application/json',
        Authorization: `Bearer ${aliceToken}`,
      }),
      body: JSON.stringify({
        messageId: msgId1,
        conversationId,
        ciphertext: enc1.ciphertext,
        nonce: enc1.nonce,
        iv: enc1.iv,
        tag: enc1.tag,
        sequenceNumber: 2,
        metadata: meta,
      }),
    });
    assert.equal(replayIdRes.status, 409);

    // Verify DB stores ciphertext only, never plaintext
    const dbMsg = await query<{ ciphertext: string; metadata: any }>(
      'SELECT ciphertext, metadata FROM messages WHERE id = $1',
      [msgId1]
    );
    assert.equal(dbMsg.rows[0].ciphertext, enc1.ciphertext);
    assert.equal(
      JSON.stringify(dbMsg.rows[0]).includes(secretText),
      false
    );

    // Bob fetches messages and decrypts locally
    const bobMsgsRes = await fetch(
      `${baseUrl}/api/conversations/${conversationId}/messages`,
      { headers: { Authorization: `Bearer ${bobToken}` } }
    );
    assert.equal(bobMsgsRes.status, 200);
    const bobMsgsJson = (await bobMsgsRes.json()) as any;
    assert.equal(bobMsgsJson.messages.length, 1);
    assert.equal(bobMsgsJson.myLastSequenceNumber, 0);

    // Alice's view reports myLastSequenceNumber = 1
    const aliceMsgsRes = await fetch(
      `${baseUrl}/api/conversations/${conversationId}/messages`,
      { headers: { Authorization: `Bearer ${aliceToken}` } }
    );
    assert.equal(aliceMsgsRes.status, 200);
    const aliceMsgsJson = (await aliceMsgsRes.json()) as any;
    assert.equal(aliceMsgsJson.myLastSequenceNumber, 1);
    const m = bobMsgsJson.messages[0];
    const decrypted = await decryptAesGcm(
      m.ciphertext,
      m.nonce,
      m.tag,
      aliceToBobKey,
      Number(m.sequence_number),
      m.metadata
    );
    assert.equal(decrypted, secretText);
  });

  it('8. Socket.IO real-time ciphertext relay, handshake relay, receipts, and socket replay rejection', async () => {
    const connectSocket = (token: string) =>
      new Promise<Socket>((resolve, reject) => {
        const s = ioClient(baseUrl, {
          auth: { token },
          transports: ['websocket'],
          reconnection: false,
        });
        s.on('connect', () => resolve(s));
        s.on('connect_error', reject);
      });

    const aliceSocket = await connectSocket(aliceToken);
    const bobSocket = await connectSocket(bobToken);

    try {
      // Handshake relay test
      const handshakeReceived = new Promise<any>((resolve) => {
        bobSocket.once('handshake:initiate', resolve);
      });
      aliceSocket.emit('handshake:initiate', {
        targetUserId: bobId,
        kemPublicKey: 'mock-kem-pub-b64',
        signedKemPublicKey: 'mock-sig-b64',
        conversationId,
      });
      const relayedHandshake = await handshakeReceived;
      assert.equal(relayedHandshake.fromUserId, aliceId);
      assert.equal(relayedHandshake.kemPublicKey, 'mock-kem-pub-b64');

      // Real-time encrypted message send (seq=2)
      const realtimePlaintext = 'Live Socket.IO encrypted payload';
      const enc2 = await encryptAesGcm(realtimePlaintext, aliceToBobKey, 2, {
        senderId: aliceId,
      });

      const bobRecvPromise = new Promise<any>((resolve) => {
        bobSocket.once('message:receive', resolve);
      });

      const ack: any = await new Promise((resolve) => {
        aliceSocket.emit(
          'message:send',
          {
            conversationId,
            recipientId: bobId,
            ciphertext: enc2.ciphertext,
            nonce: enc2.nonce,
            iv: enc2.iv,
            tag: enc2.tag,
            sequenceNumber: 2,
            metadata: { senderId: aliceId },
          },
          resolve
        );
      });
      assert.equal(ack.ok, true);

      const received = await bobRecvPromise;
      const decryptedLive = await decryptAesGcm(
        received.ciphertext,
        received.nonce,
        received.tag,
        aliceToBobKey,
        Number(received.sequence_number),
        received.metadata
      );
      assert.equal(decryptedLive, realtimePlaintext);

      // Delivery & Read receipts
      const readReceiptPromise = new Promise<any>((resolve) => {
        aliceSocket.once('message:read', resolve);
      });
      bobSocket.emit('message:read', {
        messageId: received.id,
        conversationId,
      });
      const readReceipt = await readReceiptPromise;
      assert.equal(readReceipt.messageId, received.id);
      assert.equal(readReceipt.status, 'read');

      // Socket replay attack (seq=2 again) rejected
      const replayAck: any = await new Promise((resolve) => {
        aliceSocket.emit(
          'message:send',
          {
            conversationId,
            recipientId: bobId,
            ciphertext: enc2.ciphertext,
            nonce: enc2.nonce,
            iv: enc2.iv,
            tag: enc2.tag,
            sequenceNumber: 2,
          },
          resolve
        );
      });
      assert.ok(replayAck.error);
      assert.match(replayAck.error, /Replay detected/);
    } finally {
      aliceSocket.close();
      bobSocket.close();
    }
  });

  it('9. Encrypted key backup & password reset flow invalidate old password and old sessions', async () => {
    // Store encrypted private key backup (never plaintext private key)
    const backupRes = await fetch(`${baseUrl}/api/keys/backup`, {
      method: 'POST',
      headers: csrfHeaders({
        'Content-Type': 'application/json',
        Authorization: `Bearer ${aliceToken}`,
      }),
      body: JSON.stringify({
        encryptedPrivateKey: 'encrypted-blob-base64',
        salt: 'salt-base64',
        iv: 'iv-base64',
      }),
    });
    assert.equal(backupRes.status, 201);

    const getBackupRes = await fetch(`${baseUrl}/api/keys/backup`, {
      headers: { Authorization: `Bearer ${aliceToken}` },
    });
    assert.equal(getBackupRes.status, 200);
    const backupJson = (await getBackupRes.json()) as any;
    assert.equal(backupJson.backup.encrypted_private_key, 'encrypted-blob-base64');

    // Request password reset
    const reqResetRes = await fetch(
      `${baseUrl}/api/auth/password-reset/request`,
      {
        method: 'POST',
        headers: csrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ email: aliceCreds.email }),
      }
    );
    assert.equal(reqResetRes.status, 200);
    const reqResetJson = (await reqResetRes.json()) as any;
    assert.ok(reqResetJson.resetToken);

    const newPassword = 'AliceNewSecurePass456!';
    const confirmResetRes = await fetch(
      `${baseUrl}/api/auth/password-reset/confirm`,
      {
        method: 'POST',
        headers: csrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({
          token: reqResetJson.resetToken,
          newPassword,
          confirmPassword: newPassword,
        }),
      }
    );
    assert.equal(confirmResetRes.status, 200);

    // Old JWT session is now revoked
    const oldSessionMe = await fetch(`${baseUrl}/api/auth/me`, {
      headers: { Authorization: `Bearer ${aliceToken}` },
    });
    assert.equal(oldSessionMe.status, 401);

    // Old password login fails
    const oldLoginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        email: aliceCreds.email,
        password: aliceCreds.password,
      }),
    });
    assert.equal(oldLoginRes.status, 401);

    // New password login succeeds
    const newLoginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        email: aliceCreds.email,
        password: newPassword,
      }),
    });
    assert.equal(newLoginRes.status, 200);
  });
});
