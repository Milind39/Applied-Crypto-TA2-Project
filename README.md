# PQ Messenger — Post-Quantum End-to-End Encrypted Messaging Platform

![Post-Quantum](https://img.shields.io/badge/Post--Quantum-ML--KEM--768%20%7C%20ML--DSA--65-00ff41?style=flat-square)
![Symmetric](https://img.shields.io/badge/AEAD-AES--256--GCM%20%7C%20HKDF--SHA--256-06b6d4?style=flat-square)
![Stack](https://img.shields.io/badge/Stack-React%2019%20%7C%20Node.js%20%7C%20MariaDB-111827?style=flat-square)
![Tests](https://img.shields.io/badge/Security%20Suite-9%2F9%20Passing-10b981?style=flat-square)

**PQ Messenger** is a full-stack, zero-knowledge, **post-quantum end-to-end encrypted (E2EE)** real-time messaging web application. All long-term identity key generation, ephemeral post-quantum key encapsulation, directional session key derivation, and symmetric authenticated encryption happen **exclusively inside the user's browser** using WebAssembly (`@oqs/liboqs-js`) and the Web Crypto API.

The Node.js/Express/Socket.IO backend and MariaDB database act strictly as an authenticated **ciphertext relay**, **encrypted private-key backup vault**, and **post-quantum Certificate Authority (CA)** — never seeing plaintext messages, unencrypted private keys, or session secrets.

---

## Cryptographic Architecture

| Algorithm | Standard | Responsibility | Execution Location |
| :--- | :--- | :--- | :--- |
| **ML-DSA-65** | NIST FIPS 204 | Identity key pairs, CA certificate signing, and mutual handshake authentication | Browser (WASM) & Server CA |
| **ML-KEM-768** | NIST FIPS 203 | Ephemeral post-quantum shared-secret establishment (`encapsulate` / `decapsulate`) | Browser (WASM) |
| **HKDF-SHA-256** | RFC 5869 | Transcript-bound directional session key derivation (`alice-to-bob` & `bob-to-alice`) | Browser (Web Crypto) |
| **AES-256-GCM** | NIST SP 800-38D | Authenticated message encryption with unique 96-bit nonces and canonicalized AAD | Browser (Web Crypto) |
| **Argon2id** | RFC 9106 | Password hashing for account authentication | Server (`argon2`) |
| **PBKDF2-SHA-256** | RFC 8018 | Client-side password-based encryption (`150,000` iterations + AES-256-GCM) for key backups | Browser (Web Crypto) |

### System & Protocol Flow

```mermaid
flowchart LR
  subgraph BrowserA["Browser A (Alice) — :3000"]
    UI_A["React UI"]
    CRYPTO_A["WASM + Web Crypto\nML-DSA-65 / ML-KEM-768\nHKDF-SHA-256 / AES-256-GCM"]
    IDB_A[("IndexedDB\npq-messenger-keystore")]
    UI_A <--> CRYPTO_A
    CRYPTO_A <--> IDB_A
  end

  subgraph BrowserB["Browser B (Bob) — :3000"]
    UI_B["React UI"]
    CRYPTO_B["WASM + Web Crypto\nML-DSA-65 / ML-KEM-768\nHKDF-SHA-256 / AES-256-GCM"]
    IDB_B[("IndexedDB\npq-messenger-keystore")]
    UI_B <--> CRYPTO_B
    CRYPTO_B <--> IDB_B
  end

  subgraph Backend["Node.js + Express + Socket.IO (:4000)"]
    API["REST API + Auth\nHelmet, CORS, Rate Limit, Double-Submit CSRF"]
    WS["Socket.IO Ciphertext & Handshake Relay"]
    CA["ML-DSA-65 Certificate Authority + CRL"]
    EMAIL["Nodemailer\nGmail SMTP Verification & Reset"]
  end

  subgraph DB["MariaDB (:3306 / pqmessenger)"]
    MDB[("users, verification_tokens, certificates,\nconversations, messages (ciphertext only),\nsessions, key_backups, password_resets")]
  end

  BrowserA -- "Ciphertext + Signed Handshakes" --> API
  BrowserA -- "Real-time Socket.IO" --> WS
  BrowserB -- "Ciphertext + Signed Handshakes" --> API
  BrowserB -- "Real-time Socket.IO" --> WS
  API --> CA
  API --> EMAIL
  API --> MDB
  WS --> MDB
```

### Mutually Authenticated Handshake

```mermaid
sequenceDiagram
  autonumber
  participant Alice as Alice (Browser A)
  participant Server as Backend Relay + CA
  participant Bob as Bob (Browser B)

  Alice->>Alice: Generate ephemeral ML-KEM-768 keypair (ek, dk)
  Alice->>Alice: Sign ek with Alice ML-DSA-65 secret key
  Alice->>Server: handshake:initiate (ek, sig_A, cert_A)
  Server->>Bob: Relay handshake:initiate

  Bob->>Bob: Verify cert_A against CA public key, expiry & CRL
  Bob->>Bob: Verify sig_A over ek using Alice public key
  Bob->>Bob: ML-KEM-768.encapsulate(ek) -> (ct, ss)
  Bob->>Bob: Sign ct with Bob ML-DSA-65 secret key
  Bob->>Server: handshake:respond (ct, sig_B, cert_B)
  Server->>Alice: Relay handshake:respond

  Alice->>Alice: Verify cert_B against CA public key, expiry & CRL
  Alice->>Alice: Verify sig_B over ct using Bob public key
  Alice->>Alice: ML-KEM-768.decapsulate(ct, dk) -> ss
  Note over Alice,Bob: Both compute transcript = SHA-256(ek || ct || cert_A || cert_B)<br/>and derive independent directional AES-256-GCM keys via HKDF-SHA-256
```

---

## Key Features

- **Real Post-Quantum Cryptography:** Uses `@oqs/liboqs-js` (liboqs compiled to WebAssembly) for `ML-DSA-65` and `ML-KEM-768` — no mocked encryption or classical substitution.
- **Trusted Certificate Authority & CRL:** Dedicated server-side ML-DSA-65 CA issues signed JSON certificates, tracks expiration, maintains a Certificate Revocation List (`GET /api/certificates/crl`), and rejects revoked/expired certificates.
- **Zero-Knowledge Relay & Storage:** Both `POST /api/messages` and Socket.IO `message:send` reject payloads containing `plaintext`. MariaDB stores only ciphertext, nonces, tags, and routing metadata.
- **Replay & Tamper Protection:** AES-256-GCM binds canonicalized `{ seq, senderId, timestamp }` AAD; both client (`ReplayProtector`) and server (monotonic `sequence_number` + unique `messageId` + MariaDB duplicate detection) reject replayed or modified messages.
- **Encrypted Key Backup & Session Persistence:** Private signing keys, directional AES-256-GCM session keys, and sequence numbers persist in IndexedDB (`pq-messenger-keystore`) across tab refreshes. Identity keys can also be backed up encrypted with PBKDF2-SHA-256 + AES-256-GCM.
- **Mandatory Email Verification:** Requires email verification before allowing user login or socket connection. Accounts must verify via a time-limited email link sent via Gmail SMTP before accessing chat features.
- **Secure Password Reset:** Time-limited 15-minute reset tokens delivered exclusively via email with direct 1-click links (`/reset-password?token=...&email=...`), terminating all active sessions on password change.
- **Immediate Real-time Synchronization:** Senders see their own messages render immediately in active chat and conversation sidebar, with real-time status transitions (`sending` -> `sent` -> `delivered` -> `read`).
- **Web Hardening:** Argon2id password hashing, HttpOnly `SameSite=Strict` JWT cookies + active session tracking, strict `crypto.timingSafeEqual` double-submit CSRF protection, Helmet headers, CORS, and rate limiting.

---

## Repository Structure

```text
Applied-Crypto-TA2-Project/
├── README.md
├── .gitignore
├── DB_Structure_Import/                # Pre-exported MariaDB schema dump
│   └── mariadb_struct.sql              # Database structure export for quick import
├── docs/
│   ├── architecture.md                 # System diagram, DB schema, REST & Socket.IO API reference
│   ├── cryptography.md                 # Sequence diagrams, key sizes, KDF, AEAD & CRL specs
│   └── threat-model.md                 # Assets, trust boundaries, mitigations & limitations
├── server/                             # Node.js + Express 5 + Socket.IO + TypeScript (:4000)
│   ├── .env.example                    # Template for environment variables and secrets
│   ├── package.json
│   ├── tsconfig.json
│   ├── src/
│   │   ├── index.ts                    # Express + Socket.IO bootstrap
│   │   ├── config.ts                   # Port, JWT, CORS, MariaDB & Nodemailer configuration
│   │   ├── db.ts                       # MariaDB pool & schema initialization
│   │   ├── socket.ts                   # Authenticated Socket.IO relay
│   │   ├── ca/
│   │   │   └── certificate-authority.ts # ML-DSA-65 CA issuance, verification & CRL
│   │   ├── middleware/
│   │   │   ├── auth.ts                 # JWT + active-session authentication
│   │   │   └── security.ts             # Helmet, CORS, rate limiters & strict CSRF
│   │   ├── services/
│   │   │   ├── emailService.ts         # Nodemailer Gmail SMTP for verification & reset
│   │   │   └── messageService.ts       # Participant checks, replay guard & ciphertext storage
│   │   └── routes/
│   │       ├── auth.ts                 # Register, email verification, login, logout, password reset
│   │       ├── users.ts                # User search & profile lookup
│   │       ├── certificates.ts         # CA public key, cert issue/verify/revoke & CRL
│   │       ├── conversations.ts        # Conversations & paginated encrypted history
│   │       ├── messages.ts             # Encrypted message submission & read/delivery receipts
│   │       └── keys.ts                 # Encrypted private-key backup endpoints
│   └── tests/
│       └── security-integration.test.ts # 9-test security & integration suite
└── client/                             # React 19 + TypeScript + Vite 8 + Tailwind CSS v4 (:3000)
    ├── package.json
    ├── vite.config.ts                  # /api & /socket.io proxy to :4000
    └── src/
        ├── App.tsx                     # Protected routes: /, /register, /login, /verify-email, /reset-password, /dashboard, /security
        ├── crypto/
        │   ├── pq-crypto.ts            # @oqs/liboqs-js ML-DSA-65 & ML-KEM-768 WASM wrappers
        │   ├── symmetric.ts            # HKDF-SHA-256 & AES-256-GCM with canonicalized AAD
        │   ├── handshake.ts            # Authenticated ML-KEM-768 handshake & ReplayProtector
        │   └── key-management.ts       # IndexedDB keystore & session key persistence
        ├── contexts/                   # AuthContext, CryptoContext, SocketContext
        ├── services/                   # REST API client (with CSRF handling) & Socket.IO client
        ├── components/                 # Chat UI, CertificateViewer, EncryptionBadge, UserSearch
        └── pages/                      # Landing, Register, Login, VerifyEmail, PasswordReset, Dashboard, Security
```

---

## Getting Started

### Prerequisites

- **Node.js** v20+ (tested on Node v24) & `npm`
- **MariaDB** 10.7+ / 11+ (running locally on port `3306`)

### 1. Database Setup (MariaDB)

Start your local MariaDB service manually:

```bash
# On Linux / WSL:
sudo systemctl start mariadb
# Or on Windows:
net start MariaDB
```

Create the database and database user (if not already existing):

```sql
CREATE DATABASE IF NOT EXISTS pqmessenger;
CREATE USER IF NOT EXISTS 'toji'@'127.0.0.1' IDENTIFIED BY 'toji123';
GRANT ALL PRIVILEGES ON pqmessenger.* TO 'toji'@'127.0.0.1';
FLUSH PRIVILEGES;
```

On server startup, `initDatabase()` in [`server/src/db.ts`](server/src/db.ts) automatically creates all 8 tables (`users`, `verification_tokens`, `certificates`, `conversations`, `messages`, `sessions`, `key_backups`, `password_resets`) and indexes.

#### Importing a Database
A pre-exported database schema is available in [`DB_Structure_Import/mariadb_struct.sql`](DB_Structure_Import/mariadb_struct.sql).

First, create a new empty database for the import. Then, run the import command:

```bash
mariadb -u username -p new_database_name < dump_filename.sql
```

- Replace `username` with your database user (e.g., `toji`).
- Replace `new_database_name` with the target database (which must exist, e.g., `pqmessenger`).
- Replace `dump_filename.sql` with the path to the exported SQL file (e.g., `DB_Structure_Import/mariadb_struct.sql`).

#### Exporting a Database
Run the following command in your terminal to export the database structure and data:

```bash
mariadb-dump -u username -p database_name > dump_filename.sql
```

- Replace `username` with your database user.
- Replace `database_name` with the name of the database to export (e.g., `pqmessenger`).
- Replace `dump_filename.sql` with your desired output file name.

### 2. Configure Environment (`server/.env`)

Copy the sample environment file in `server/`:

```bash
cp server/.env.example server/.env
```

Ensure the configuration matches your local setup:

```env
PORT=4000
JWT_SECRET=your-secure-jwt-secret-at-least-32-characters
CORS_ORIGIN=http://localhost:3000

# MariaDB Configuration
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=toji
DB_PASSWORD=toji123
DB_NAME=pqmessenger

# Nodemailer / Gmail SMTP Configuration
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_gmail_app_password
EMAIL_FROM=your_email@gmail.com

# Frontend URL
FRONTEND_URL=http://localhost:3000

# Feature Flags
REQUIRE_EMAIL_VERIFICATION=true
```

### 3. Install & Run Backend (`server/`)

```bash
cd server
npm install
npm run dev        # Starts Express + Socket.IO + ML-DSA-65 CA on http://localhost:4000 with nodemon
```

Production build:

```bash
npm run build && npm start
```

### 4. Install & Run Frontend (`client/`)

In a second terminal:

```bash
cd client
npm install
npm run dev        # Starts Vite dev server on http://localhost:3000
```

Production build:

```bash
npm run build
```

---

## Automated Security & Integration Tests

Run the backend security test suite (`server/tests/security-integration.test.ts`):

```bash
cd server
npm test
```

The suite verifies **9 end-to-end security & cryptographic scenarios**:
1. Argon2id registration & weak-password rejection
2. Rejection of unauthenticated REST and Socket.IO connections (plus strict CSRF `403` enforcement)
3. Distinct ML-DSA-65 identity generation & valid CA-signed certificates for Alice and Bob
4. Rejection of invalid, expired, and revoked certificates and forged ML-DSA-65 signatures
5. Matching ML-KEM-768 shared secrets and distinct directional HKDF-SHA-256 keys
6. AES-256-GCM encryption/decryption and rejection of tampered ciphertext, tag, or AAD
7. Non-participant access denial, replay protection, and zero-knowledge ciphertext-only DB storage
8. Socket.IO real-time handshake/ciphertext relay, receipts, and socket replay rejection
9. Encrypted key backup recovery and password reset invalidating prior credentials and sessions

---

## Two-User Demo Walkthrough (Alice & Bob)

Because IndexedDB and cookies are isolated per browser profile, use **two separate browser profiles** (e.g., normal browser window + Incognito/Private window or two different browsers):

1. **Window A (Alice):**
   - Open `http://localhost:3000/register` and register `alice`.
   - Check your inbox for the email verification link (or use the displayed link) to activate the account.
   - Sign in at `http://localhost:3000/login`. Client-side WASM generates an ML-DSA-65 keypair, obtains a CA certificate, and stores the keys in IndexedDB.
2. **Window B (Bob):**
   - Open `http://localhost:3000/register` in an isolated browser session and register `bob`.
   - Complete email verification and sign in.
3. **Inspect Security Details:** Visit `/security` in either window to view the public key fingerprint, CA signature verification, certificate validity, and CRL status.
4. **Discover & Handshake:** From Alice's Dashboard, search for `bob` and open the conversation. Click **Establish PQ Session** (or **Start ML-KEM Handshake**) while both users are online until the badge reads **PQ E2EE Active**.
5. **Exchange Encrypted Messages:** Send messages in both directions between Alice and Bob and verify real-time decryption, sequence numbers, and delivery/read receipts. Keys persist across tab refreshes.
6. **Verify Zero-Knowledge Database Storage:**
   ```bash
   mariadb -u toji -ptoji123 pqmessenger -e "SELECT id, sequence_number, LEFT(ciphertext, 32) AS ct_prefix, LEFT(nonce, 16) AS iv, LEFT(tag, 16) AS tag FROM messages;"
   ```

---

## Additional Documentation

- [**System Architecture, Schema & API Reference**](docs/architecture.md)
- [**Cryptographic Protocols, Parameters & Workflows**](docs/cryptography.md)
- [**Threat Model, Mitigations & Security Limitations**](docs/threat-model.md)
