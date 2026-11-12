# Threat Model, Security Mitigations & Hardening Roadmap

This document evaluates the security posture of PQ Messenger based on the implemented codebase, detailing protected assets, trust boundaries, adversary capabilities, implemented controls, and known architectural limitations.

---

## 1. Protected Assets

| Asset | Storage / Location | Sensitivity |
| :--- | :--- | :--- |
| **User ML-DSA-65 Private Signing Key** | Browser IndexedDB (`pq-messenger-keystore`) + in-memory React state | Critical — compromises user identity impersonation and MITM protection during handshakes |
| **Encrypted Private Key Backup** | PostgreSQL `key_backups` table (wrapped with PBKDF2-SHA-256 + AES-256-GCM) | High — offline brute-force target if database leaks and user password is weak |
| **Ephemeral ML-KEM-768 Secret Key & Shared Secret** | Browser memory only during active handshake | Critical — recovers session keys for that conversation |
| **Derived AES-256-GCM Session Keys (`sendKey`, `receiveKey`)** | Browser memory (`non-extractable` Web Crypto `CryptoKey`) | Critical — decrypts messages for that session |
| **Message Plaintext & AAD Metadata** | Browser memory/UI only (`messages.plaintext` is never transmitted) | Critical — core confidentiality asset |
| **CA ML-DSA-65 Private Signing Key** | Backend server memory (`server/src/ca/certificate-authority.ts`) | Critical — compromises trust anchor for all identity certificates |
| **JWT Session Tokens & Password Hashes** | HttpOnly `token` cookie + `sessionStorage` (`pq_socket_token`); `users.password_hash` (Argon2id) & `sessions.token_hash` (SHA-256) in PostgreSQL | High — protects account access and real-time socket identity |

---

## 2. Trust Boundaries

```text
[ Boundary 1: Browser Execution Context (Trusted by User) ]
  - Holds plaintext, ML-DSA-65 private keys, ML-KEM-768 secrets, AES-256-GCM CryptoKeys
  - Performs all encryption/decryption and CA/peer signature verification
        |
        |  HTTP/REST + WebSocket (Ciphertext, Public Keys, Signed Handshakes, Auth Cookies/Tokens)
        v
[ Boundary 2: Network & Transport ]
  - Untrusted public network (assumed observable and modifiable by active/passive attackers)
        |
        v
[ Boundary 3: Express + Socket.IO Relay & CA Server (Honest-but-Curious for Content; Trusted for Identity Issuance) ]
  - Untrusted for message plaintext (zero-knowledge relay)
  - Trusted for account authentication, replay enforcement, and CA certificate signing/CRL maintenance
        |
        v
[ Boundary 4: PostgreSQL Persistence ]
  - Stores Argon2id password hashes, certificates, ciphertext messages, encrypted key backups, session hashes
```

---

## 3. Adversary Capabilities Considered

1. **Harvest-Now, Decrypt-Later (Quantum Adversary):** Captures encrypted traffic and key exchange payloads today to break with a future fault-tolerant quantum computer running Shor's algorithm.
2. **Active Network Attacker / MITM:** Intercepts, alters, drops, or replays REST requests, Socket.IO handshake payloads (`handshake:initiate`, `handshake:respond`), or encrypted messages.
3. **Compromised / Honest-but-Curious Relay Server or DB Leak:** Inspects PostgreSQL tables (`messages`, `key_backups`, `users`, `sessions`) or server logs attempting to recover plaintext messages, private keys, or user passwords.
4. **Unauthorized / Cross-Conversation User:** Authenticated user (e.g., Eve) attempting to read, inject, or update messages in a conversation between Alice and Bob, or impersonate another user's identity.
5. **Web Application Attacker:** Attempts CSRF, brute-force login/registration, clickjacking/header attacks, or replay of previously captured ciphertext frames.

---

## 4. Mitigations Implemented in the Codebase

| Threat / Attack Vector | Implemented Mitigation | Verified Code Location |
| :--- | :--- | :--- |
| **Quantum Key Exchange Breaking** | Ephemeral **ML-KEM-768** (NIST FIPS 203, Level 3) key encapsulation | [`client/src/crypto/pq-crypto.ts`](../client/src/crypto/pq-crypto.ts), [`handshake.ts`](../client/src/crypto/handshake.ts) |
| **Quantum Signature Forgery / MITM** | **ML-DSA-65** (NIST FIPS 204, Level 3) identity keys, CA-signed certificates, signed KEM public keys & ciphertexts, and SHA-256 transcript binding in HKDF salt | [`server/src/ca/certificate-authority.ts`](../server/src/ca/certificate-authority.ts), [`client/src/crypto/handshake.ts`](../client/src/crypto/handshake.ts), [`symmetric.ts`](../client/src/crypto/symmetric.ts) |
| **Compromised Peer Key / Impersonation** | Local CA signature verification + expiry check + CRL check (`verifyPeerCertificate`) and key revocation (`POST /api/certificates/revoke`) | [`client/src/crypto/handshake.ts`](../client/src/crypto/handshake.ts), [`server/src/routes/certificates.ts`](../server/src/routes/certificates.ts) |
| **Server Plaintext Exposure** | Client-side AES-256-GCM encryption; server explicitly rejects any `plaintext` field on `POST /api/messages` and `message:send` | [`server/src/routes/messages.ts`](../server/src/routes/messages.ts), [`server/src/socket.ts`](../server/src/socket.ts) |
| **Ciphertext Tampering / Truncation** | AES-256-GCM 128-bit tag + AAD binding `{ seq, senderId, timestamp }`; fresh 96-bit CSPRNG nonce per message | [`client/src/crypto/symmetric.ts`](../client/src/crypto/symmetric.ts) |
| **Message Replay Attacks** | Server-side duplicate `messageId` check + strictly monotonic `sequence_number` check + DB unique index `idx_messages_replay_seq`; client-side `ReplayProtector` | [`server/src/services/messageService.ts`](../server/src/services/messageService.ts), [`server/src/db.ts`](../server/src/db.ts), [`client/src/crypto/handshake.ts`](../client/src/crypto/handshake.ts) |
| **Cross-Conversation Access** | SQL participant checks `(participant_a = $user OR participant_b = $user)` on conversation fetch, message send, and status updates | [`server/src/routes/conversations.ts`](../server/src/routes/conversations.ts), [`messageService.ts`](../server/src/services/messageService.ts), [`socket.ts`](../server/src/socket.ts) |
| **Credential & Session Theft** | **Argon2id** password hashing, SHA-256 hashed JWT session tracking in `sessions`, session invalidation on logout/refresh/password-reset | [`server/src/routes/auth.ts`](../server/src/routes/auth.ts), [`server/src/middleware/auth.ts`](../server/src/middleware/auth.ts) |
| **CSRF, Brute Force & HTTP Header Attacks** | Strict double-submit cookie CSRF (`csrfProtection` with `crypto.timingSafeEqual`, requiring `GET /api/csrf-token` bootstrap), Helmet headers, strict CORS (`CORS_ORIGIN`), `authRateLimit` (100/15m) & `generalRateLimit` (1000/15m) | [`server/src/middleware/security.ts`](../server/src/middleware/security.ts) |
| **Private Key Exposure in `localStorage`** | Private keys stored in **IndexedDB** (`pq-messenger-keystore`) and cleared on logout; server backups encrypted client-side with PBKDF2-SHA-256 (150k iters) + AES-256-GCM | [`client/src/crypto/key-management.ts`](../client/src/crypto/key-management.ts), [`client/src/contexts/AuthContext.tsx`](../client/src/contexts/AuthContext.tsx) |

---

## 5. Explicit Security Limitations & Future Hardening

The following limitations are directly observable in the current implementation and should be addressed before production deployment:

1. **Session-Only Forward Secrecy (No Double Ratchet / Key Persistence Across Reloads):**
   - `sessionKeys` are held solely in React memory (`CryptoContext.tsx`). Reloading the browser clears session keys, requiring both peers to be online to run a new ML-KEM-768 handshake, and historical messages encrypted under an earlier session key cannot be decrypted after a new handshake replaces `sessionKeys`.
   - Within a single session, all messages share the same directional key pair rather than ratcheting per message.
   - *Hardening:* Implement a post-quantum Double Ratchet (symmetric KDF chain ratcheting per message + periodic ML-KEM re-encapsulation) and/or encrypted local message caching in IndexedDB.

2. **Ephemeral In-Memory CA Key Pair on the Relay Server:**
   - [`server/src/ca/certificate-authority.ts`](../server/src/ca/certificate-authority.ts) generates a fresh ML-DSA-65 CA key pair in memory on every `initCA()` startup. Restarting the server invalidates all previously issued certificates persisted in PostgreSQL (`certificates`), because their `ca_signature` no longer verifies against the new CA public key.
   - Furthermore, co-locating the CA with the relay server means a compromised backend could theoretically issue rogue certificates for users unless out-of-band fingerprint verification is performed.
   - *Hardening:* Persist the CA signing key inside an HSM/KMS or encrypted vault, separate the CA from the message relay, and add a UI safety-number / QR fingerprint verification flow between peers.

3. **Unauthenticated Handshake Relay & Lack of Offline Prekey Bundles:**
   - `handshake:initiate` and `handshake:respond` require both Alice and Bob to have active Socket.IO connections simultaneously.
   - The server relays handshake events without verifying the embedded ML-DSA-65 signatures itself (delegating verification to the peers, which is secure for E2EE but permits handshake spam/DoS by an authenticated user).
   - *Hardening:* Support signed ephemeral ML-KEM-768 prekey bundles stored on the server for asynchronous offline session initiation.

4. **Plaintext Transport in Local Development (`http://` / `ws://`):**
   - The local dev setup runs over unencrypted `http://localhost:3000` and `ws://localhost:4000`, and `config.ts` provides a fallback `jwtSecret` (`pq-messenger-dev-secret-change-in-prod`).
   - *Hardening:* Terminate TLS 1.3 (HTTPS/WSS) at a reverse proxy in production, enforce `NODE_ENV=production` (`secure: true` cookies), and require a strong `JWT_SECRET` from environment/secrets management.

5. **IndexedDB & `sessionStorage` Exposure Under XSS:**
   - While IndexedDB isolates keys from `localStorage` string APIs and `AuthContext` clears IndexedDB on explicit logout, any Cross-Site Scripting (XSS) vulnerability in the origin can still read IndexedDB records and `sessionStorage.getItem('pq_socket_token')`.
   - *Hardening:* Enforce a strict Content-Security-Policy (CSP) via Helmet, rely exclusively on HttpOnly cookies for Socket.IO auth instead of mirroring the JWT in `sessionStorage`, and wrap IndexedDB secret keys with a user-supplied passphrase or WebAuthn PRF key.

6. **Metadata Visibility to the Relay Server:**
   - Although message payloads are E2EE, the server and database observe social graph and timing metadata: user identities, conversation pairs, `sequence_number`, `created_at`/`delivered_at`/`read_at`, `metadata.senderId`/`metadata.timestamp`, online presence (`is_online`, `last_seen`), and typing indicators.
   - *Hardening:* Strip client-side `timestamp` from unencrypted JSON metadata or pad/batch traffic if metadata privacy is required.

7. **Password Reset vs. Encrypted Key Backup Tradeoff:**
   - As noted in [`PasswordResetPage.tsx`](../client/src/pages/PasswordResetPage.tsx), resetting an account password via `/api/auth/password-reset/confirm` updates `users.password_hash` and revokes active sessions, but the server cannot re-encrypt `key_backups.encrypted_private_key` because it never knows the old password or plaintext key. While key rotation on `/security` (`SecurityPage.tsx`) supports entering a password to wrap and update `/api/keys/backup` for newly generated keys, a user who resets a forgotten password without an existing IndexedDB session must rotate/regenerate their ML-DSA-65 identity on `/security`.
   - *Hardening:* Provide an offline recovery phrase (e.g., BIP-39 mnemonic / separate recovery key) to wrap the backup independently of the login password.

8. **Development Password-Reset Token Disclosure:**
   - In [`server/src/routes/auth.ts`](../server/src/routes/auth.ts), `POST /api/auth/password-reset/request` returns `resetToken` in the JSON response whenever `NODE_ENV !== 'production'` so local testing works without an SMTP server.
   - *Hardening:* Always deploy with `NODE_ENV=production` and deliver password reset tokens exclusively via an out-of-band channel (e.g., verified email).
