import dotenv from 'dotenv';
import path from 'path';

// Load environment variables from .env file
dotenv.config({ path: path.resolve(__dirname, '../.env') });

export const config = {
  port: parseInt(process.env.PORT || '4000', 10),
  jwtSecret: process.env.JWT_SECRET || 'fallback-dev-secret-do-not-use-in-production',
  jwtExpiresIn: '24h',
  db: {
    host: process.env.DB_HOST || '127.0.0.1',
    port: parseInt(process.env.DB_PORT || '3306', 10),
    user: process.env.DB_USER || 'toji',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'pqmessenger',
  },
  corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  certValidityDays: 365,
  email: {
    user: process.env.EMAIL_USER || '',
    pass: process.env.EMAIL_PASS || '',
    from: process.env.EMAIL_FROM || process.env.EMAIL_USER || '',
  },
  frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000',
  requireEmailVerification: process.env.REQUIRE_EMAIL_VERIFICATION !== 'false',
};
