import { Pool, QueryResult, QueryResultRow } from 'pg';
import { config } from './config';

export const pool = new Pool({
  host: config.db.host,
  port: config.db.port,
  user: config.db.user,
  database: config.db.database,
});

export async function query<T extends QueryResultRow = any>(
  text: string,
  params?: any[]
): Promise<QueryResult<T>> {
  return pool.query<T>(text, params);
}

export async function initDatabase(): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        is_online BOOLEAN DEFAULT FALSE,
        last_seen TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // Certificates table
    await client.query(`
      CREATE TABLE IF NOT EXISTS certificates (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        public_signing_key TEXT NOT NULL,
        certificate TEXT NOT NULL,
        ca_signature TEXT NOT NULL,
        issued_at TIMESTAMPTZ DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL,
        is_revoked BOOLEAN DEFAULT FALSE,
        revoked_at TIMESTAMPTZ,
        fingerprint VARCHAR(128) UNIQUE NOT NULL
      );
    `);

    // Conversations table
    await client.query(`
      CREATE TABLE IF NOT EXISTS conversations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        participant_a UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        participant_b UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(participant_a, participant_b)
      );
    `);

    // Messages table
    await client.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
        sender_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        ciphertext TEXT NOT NULL,
        nonce VARCHAR(64),
        iv VARCHAR(64),
        tag VARCHAR(128),
        sequence_number BIGINT,
        metadata JSONB,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        delivered_at TIMESTAMPTZ,
        read_at TIMESTAMPTZ,
        status VARCHAR(20) DEFAULT 'sent'
      );
    `);

    // Sessions table
    await client.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash VARCHAR(128) NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL,
        is_active BOOLEAN DEFAULT TRUE
      );
    `);

    // Key backups table
    await client.query(`
      CREATE TABLE IF NOT EXISTS key_backups (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        encrypted_private_key TEXT NOT NULL,
        salt TEXT NOT NULL,
        iv TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // Password resets table
    await client.query(`
      CREATE TABLE IF NOT EXISTS password_resets (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash VARCHAR(128) UNIQUE NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        used BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // Indexes
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_messages_conversation_created
        ON messages(conversation_id, created_at);
    `);
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_replay_seq
        ON messages(conversation_id, sender_id, sequence_number)
        WHERE sequence_number IS NOT NULL;
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_certificates_user_id
        ON certificates(user_id);
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_sessions_user_id
        ON sessions(user_id);
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_password_resets_user_id
        ON password_resets(user_id);
    `);

    await client.query('COMMIT');
    console.log('[DB] All tables and indexes created successfully');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[DB] Error initializing database:', err);
    throw err;
  } finally {
    client.release();
  }
}
