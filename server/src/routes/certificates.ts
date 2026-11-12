import { Router, Response } from 'express';
import { body, param, validationResult } from 'express-validator';
import { authMiddleware, AuthRequest } from '../middleware/auth';
import { query } from '../db';
import {
  issueCertificate,
  verifyCertificate,
  revokeCertificate,
  getCRL,
  getCAPublicKey,
} from '../ca/certificate-authority';

const router = Router();

// POST /api/certificates/issue
router.post(
  '/issue',
  authMiddleware,
  [body('publicSigningKey').isString().notEmpty()],
  async (req: AuthRequest, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const { publicSigningKey } = req.body;
    const user = req.user!;

    try {
      const { certificate, caSignature, fingerprint } = await issueCertificate(
        user.id,
        user.username,
        publicSigningKey
      );

      // Revoke any other existing active certificates for this user
      const revoked = await query(
        `UPDATE certificates SET is_revoked = TRUE, revoked_at = NOW()
         WHERE user_id = $1 AND is_revoked = FALSE AND fingerprint != $2
         RETURNING fingerprint`,
        [user.id, fingerprint]
      );
      for (const row of revoked.rows) {
        revokeCertificate(row.fingerprint);
      }

      const certData = JSON.parse(certificate);

      await query(
        `INSERT INTO certificates (user_id, public_signing_key, certificate, ca_signature, issued_at, expires_at, fingerprint)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (fingerprint) DO UPDATE SET
           certificate = EXCLUDED.certificate,
           ca_signature = EXCLUDED.ca_signature,
           issued_at = EXCLUDED.issued_at,
           expires_at = EXCLUDED.expires_at,
           is_revoked = FALSE,
           revoked_at = NULL
         WHERE certificates.user_id = EXCLUDED.user_id`,
        [
          user.id,
          publicSigningKey,
          certificate,
          caSignature,
          certData.issuedAt,
          certData.expiresAt,
          fingerprint,
        ]
      );

      res.status(201).json({ certificate, caSignature, fingerprint });
    } catch (err) {
      console.error('[Certs] Issue error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// GET /api/certificates/user/:userId
router.get(
  '/user/:userId',
  authMiddleware,
  [param('userId').isUUID().withMessage('Valid user ID required')],
  async (req: AuthRequest, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const { userId } = req.params;

    try {
      const result = await query(
        `SELECT id, user_id, public_signing_key, certificate, ca_signature,
                issued_at, expires_at, fingerprint
         FROM certificates
         WHERE user_id = $1
           AND is_revoked = FALSE
           AND expires_at > NOW()
         ORDER BY issued_at DESC
         LIMIT 1`,
        [userId]
      );

      if (result.rows.length === 0) {
        res.status(404).json({ error: 'No active certificate found' });
        return;
      }

      res.json({ certificate: result.rows[0] });
    } catch (err) {
      console.error('[Certs] Get cert error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// POST /api/certificates/verify
router.post(
  '/verify',
  [
    body('certificate').isString().notEmpty(),
    body('caSignature').isString().notEmpty(),
  ],
  async (req: AuthRequest, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const { certificate, caSignature } = req.body;

    try {
      const isValid = await verifyCertificate(certificate, caSignature);

      // Also check if revoked
      let certData;
      try {
        certData = JSON.parse(certificate);
      } catch {
        res.json({ valid: false, reason: 'Invalid certificate format' });
        return;
      }

      const crl = getCRL();
      const isRevokedCert = crl.includes(certData.fingerprint);

      // Check expiry
      const isExpired = new Date(certData.expiresAt) < new Date();

      res.json({
        valid: isValid && !isRevokedCert && !isExpired,
        signatureValid: isValid,
        revoked: isRevokedCert,
        expired: isExpired,
      });
    } catch (err) {
      console.error('[Certs] Verify error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// POST /api/certificates/revoke
router.post(
  '/revoke',
  authMiddleware,
  async (req: AuthRequest, res: Response): Promise<void> => {
    const user = req.user!;

    try {
      const result = await query(
        `SELECT fingerprint FROM certificates
         WHERE user_id = $1 AND is_revoked = FALSE`,
        [user.id]
      );

      if (result.rows.length === 0) {
        res.status(404).json({ error: 'No active certificate found' });
        return;
      }

      for (const row of result.rows) {
        revokeCertificate(row.fingerprint);
      }

      await query(
        `UPDATE certificates SET is_revoked = TRUE, revoked_at = NOW()
         WHERE user_id = $1 AND is_revoked = FALSE`,
        [user.id]
      );

      res.json({ message: 'Certificate(s) revoked' });
    } catch (err) {
      console.error('[Certs] Revoke error:', (err as Error).message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// GET /api/certificates/crl
router.get('/crl', (_req: AuthRequest, res: Response): void => {
  res.json({ crl: getCRL() });
});

export default router;

// Separate router for CA public key
export const caRouter = Router();

// GET /api/ca/public-key
caRouter.get('/public-key', (_req: AuthRequest, res: Response): void => {
  try {
    const publicKey = getCAPublicKey();
    res.json({ publicKey });
  } catch (err) {
    console.error('[CA] Get public key error:', (err as Error).message);
    res.status(500).json({ error: 'CA not initialized' });
  }
});
