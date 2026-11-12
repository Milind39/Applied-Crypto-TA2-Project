export const config = {
  port: parseInt(process.env.PORT || '4000'),
  jwtSecret: process.env.JWT_SECRET || 'pq-messenger-dev-secret-change-in-prod',
  jwtExpiresIn: '24h',
  db: {
    host: '/home/toji/.local/pgdata',
    port: 5433,
    user: 'toji',
    database: 'pqmessenger',
  },
  corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  certValidityDays: 365,
};
