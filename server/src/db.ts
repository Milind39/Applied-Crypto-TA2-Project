import mysql from 'mysql2/promise';
import { config } from './config';

export const pool = mysql.createPool({
  host: config.db.host,
  port: config.db.port,
  user: config.db.user,
  password: config.db.password,
  database: config.db.database,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  typeCast: function (field: any, next: any) {
    if (field.type === 'TINY' && field.length === 1) {
      const val = field.string();
      return val === null ? null : val === '1';
    }
    return next();
  },
});

export interface QueryResult<T = any> {
  rows: T[];
  rowCount: number;
}

export async function query<T = any>(
  text: string,
  params?: any[]
): Promise<QueryResult<T>> {
  let sql = text;
  let values: any[] = [];

  if (params && params.length > 0) {
    const processedParams = params.map((p) => {
      if (typeof p === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(p)) {
        return new Date(p);
      }
      return p;
    });

    if (/\$\d+/.test(sql)) {
      sql = sql.replace(/\$(\d+)/g, (_, numStr) => {
        const idx = parseInt(numStr, 10) - 1;
        values.push(processedParams[idx]);
        return '?';
      });
    } else {
      values = processedParams;
    }
  }

  // Replace ILIKE with LIKE for MariaDB
  sql = sql.replace(/\bILIKE\b/gi, 'LIKE');

  const [results] = await pool.query(sql, values);

  if (Array.isArray(results)) {
    return {
      rows: results as T[],
      rowCount: results.length,
    };
  } else {
    const header = results as mysql.ResultSetHeader;
    return {
      rows: [],
      rowCount: header.affectedRows || 0,
    };
  }
}

export async function initDatabase(): Promise<void> {
  // Test connection to MariaDB
  const conn = await pool.getConnection();
  conn.release();

  // Users table
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      is_email_verified BOOLEAN DEFAULT FALSE,
      created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
      updated_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
      is_online BOOLEAN DEFAULT FALSE,
      last_seen DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3)
    );
  `);

  // Ensure is_email_verified column exists if table was already created
  try {
    await query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_email_verified BOOLEAN DEFAULT FALSE;`);
  } catch {}

  // Verification Tokens table (for email verification)
  await query(`
    CREATE TABLE IF NOT EXISTS verification_tokens (
      id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
      email VARCHAR(255) NOT NULL,
      token VARCHAR(128) NOT NULL,
      expiry DATETIME(3) NOT NULL,
      created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
      INDEX idx_verification_token (token),
      INDEX idx_verification_email (email)
    );
  `);

  // Certificates table
  await query(`
    CREATE TABLE IF NOT EXISTS certificates (
      id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
      user_id CHAR(36) NOT NULL,
      public_signing_key TEXT NOT NULL,
      certificate LONGTEXT NOT NULL,
      ca_signature TEXT NOT NULL,
      issued_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
      expires_at DATETIME(3) NOT NULL,
      is_revoked BOOLEAN DEFAULT FALSE,
      revoked_at DATETIME(3),
      fingerprint VARCHAR(128) UNIQUE NOT NULL,
      CONSTRAINT fk_certificates_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  // Conversations table
  await query(`
    CREATE TABLE IF NOT EXISTS conversations (
      id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
      participant_a CHAR(36) NOT NULL,
      participant_b CHAR(36) NOT NULL,
      created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
      updated_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
      UNIQUE KEY uk_participants (participant_a, participant_b),
      CONSTRAINT fk_conv_a FOREIGN KEY (participant_a) REFERENCES users(id) ON DELETE CASCADE,
      CONSTRAINT fk_conv_b FOREIGN KEY (participant_b) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  // Messages table
  await query(`
    CREATE TABLE IF NOT EXISTS messages (
      id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
      conversation_id CHAR(36) NOT NULL,
      sender_id CHAR(36) NOT NULL,
      ciphertext LONGTEXT NOT NULL,
      nonce VARCHAR(64),
      iv VARCHAR(64),
      tag VARCHAR(128),
      sequence_number BIGINT,
      metadata JSON,
      created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
      delivered_at DATETIME(3),
      read_at DATETIME(3),
      status VARCHAR(20) DEFAULT 'sent',
      CONSTRAINT fk_messages_conv FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
      CONSTRAINT fk_messages_sender FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  // Sessions table
  await query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
      user_id CHAR(36) NOT NULL,
      token_hash VARCHAR(128) NOT NULL,
      created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
      expires_at DATETIME(3) NOT NULL,
      is_active BOOLEAN DEFAULT TRUE,
      CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  // Key backups table
  await query(`
    CREATE TABLE IF NOT EXISTS key_backups (
      id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
      user_id CHAR(36) NOT NULL,
      encrypted_private_key LONGTEXT NOT NULL,
      salt TEXT NOT NULL,
      iv TEXT NOT NULL,
      created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
      CONSTRAINT fk_key_backups_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  // Password resets table
  await query(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
      user_id CHAR(36) NOT NULL,
      token_hash VARCHAR(128) UNIQUE NOT NULL,
      expires_at DATETIME(3) NOT NULL,
      used BOOLEAN DEFAULT FALSE,
      created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
      CONSTRAINT fk_password_resets_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  // Indexes
  await query(`
    CREATE INDEX IF NOT EXISTS idx_messages_conversation_created
      ON messages(conversation_id, created_at);
  `);
  await query(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_replay_seq
      ON messages(conversation_id, sender_id, sequence_number);
  `);
  await query(`
    CREATE INDEX IF NOT EXISTS idx_certificates_user_id
      ON certificates(user_id);
  `);
  await query(`
    CREATE INDEX IF NOT EXISTS idx_sessions_user_id
      ON sessions(user_id);
  `);
  await query(`
    CREATE INDEX IF NOT EXISTS idx_password_resets_user_id
      ON password_resets(user_id);
  `);

  console.log('[DB] All tables and indexes created successfully in MariaDB');
}
