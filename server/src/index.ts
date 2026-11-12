import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import http from 'http';
import cookieParser from 'cookie-parser';
import { config } from './config';
import { initDatabase, query } from './db';
import { initCA, loadRevokedFingerprints } from './ca/certificate-authority';
import {
  helmetMiddleware,
  corsMiddleware,
  generalRateLimit,
  csrfProtection,
  generateCsrfToken,
} from './middleware/security';
import { initSocketIO } from './socket';

import authRoutes from './routes/auth';
import userRoutes from './routes/users';
import certificateRoutes, { caRouter } from './routes/certificates';
import conversationRoutes from './routes/conversations';
import messageRoutes from './routes/messages';
import keyRoutes from './routes/keys';

export async function createServerApp(): Promise<{
  app: express.Express;
  server: http.Server;
}> {
  const app = express();

  // Security and parsing middleware
  app.use(helmetMiddleware);
  app.use(corsMiddleware);
  app.use(generalRateLimit);
  app.use(express.json({ limit: '2mb' }));
  app.use(cookieParser());
  app.use(csrfProtection);

  // Health & CSRF endpoints
  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({ status: 'ok', service: 'pq-messenger-server' });
  });
  app.get('/api/csrf-token', generateCsrfToken);

  // Mount API routes
  app.use('/api/auth', authRoutes);
  app.use('/api/users', userRoutes);
  app.use('/api/certificates', certificateRoutes);
  app.use('/api/ca', caRouter);
  app.use('/api/conversations', conversationRoutes);
  app.use('/api/messages', messageRoutes);
  app.use('/api/keys', keyRoutes);

  // Error handler (never leak sensitive data or stack traces in prod)
  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    console.error('[Server] Unhandled error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  });

  // Create HTTP server and initialize Socket.IO
  const server = http.createServer(app);
  initSocketIO(server);

  // Initialize PostgreSQL schema & Post-Quantum CA
  await initDatabase();
  await initCA();

  // Sync revoked certificate fingerprints from DB into CA CRL
  const revokedRows = await query<{ fingerprint: string }>(
    'SELECT fingerprint FROM certificates WHERE is_revoked = TRUE'
  );
  if (revokedRows.rows.length > 0) {
    loadRevokedFingerprints(revokedRows.rows.map((r) => r.fingerprint));
  }

  return { app, server };
}

async function bootstrap(): Promise<void> {
  const { server } = await createServerApp();

  server.listen(config.port, () => {
    console.log(`[Server] Listening on port ${config.port}`);
    console.log(`[Server] CORS origin: ${config.corsOrigin}`);
    console.log(`[Server] Database: ${config.db.database}@${config.db.host}:${config.db.port}`);
  });
}

if (require.main === module) {
  bootstrap().catch((err) => {
    console.error('[Server] Failed to start:', err.message);
    process.exit(1);
  });
}
